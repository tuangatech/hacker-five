package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/uniformwall"
)

// commonPaths are probed directly (via r.client, not katana) to map the
// shape of the app — distinct from misconfig's exposed-path checks, which
// look for bad *exposure* (docs/91-research-recon-phase.md §3, Wave 3).
// /robots.txt and /sitemap.xml are deliberately absent: Wave 0 already
// fetches both once (see passive.go — robots.txt for the policy signal,
// sitemap.xml parsed for <loc> hints in LT-39) and a second GET here only
// produced a duplicate EndpointFact (docs/follow-up.md R-c, LT-39).
var commonPaths = []string{
	"/api", "/graphql", "/swagger.json", "/.well-known/openapi.json",
}

// reconCanaryPath is a path guaranteed not to be a real resource on any
// target — probeCommonPaths GETs it once per host so it can tell a genuine
// distinct resource from the single generic page a SPA catch-all / soft-404
// / WAF layer returns for *every* path (docs/follow-up.md LT-30: against
// www.valmo.in, /swagger.json, /api, /graphql and a random path all
// returned the identical 1526-byte React shell at HTTP 200, so the
// unguarded ">= 200 && < 400" check fabricated a ConfidenceHigh openapi
// APISpecFact and a fistful of endpoints). Alphanumeric only, matching
// pkg/detectors/misconfig.baselineCanaryPath's own reasoning: a WAF/CDN
// block page that echoes the requested path back HTML-entity-encodes
// punctuation but leaves alphanumeric runs literal.
const reconCanaryPath = "/hackerfivereconcanary8b2e14d0"

// maxCanaryBodyRead bounds how much of a common-path / canary response body
// probeCommonPaths measures for the length comparison — a real SPA shell is
// a couple of KiB, and both sides are capped identically so an equal pair
// still compares equal.
const maxCanaryBodyRead = 1 << 20

// blockPageSampleBytes is how much of the canary/root body is kept in
// memory for pkg/uniformwall's block-page marker match — a WAF block page's
// signature is in the first few hundred bytes; the rest is only counted for
// bodyLen and discarded.
const blockPageSampleBytes = 8192

// canaryResponse is what reconCanaryPath returned for one host — the
// yardstick sameAsCanary compares each real common-path probe against, and
// (Phase 7 Step 4 D6) the input to pkg/uniformwall.Classify.
type canaryResponse struct {
	fetched     bool
	status      int
	bodyLen     int
	contentType string // normalized: media type only, lower-cased
	server      string // raw Server header
	bodySample  []byte // first blockPageSampleBytes of the body
}

// sameAsCanary reports whether a probe's (status, bodyLen, contentType)
// is indistinguishable from the host's canary response — i.e. the probe
// almost certainly hit the same catch-all page, not a real resource. Body
// length is compared with a small relative tolerance (a shell can embed the
// requested path or a per-request nonce); status and normalized content
// type must match exactly.
func (c canaryResponse) sameAsCanary(status, bodyLen int, contentType string) bool {
	if !c.fetched || status != c.status || contentType != c.contentType {
		return false
	}
	tol := c.bodyLen / 10
	if tol < 64 {
		tol = 64
	}
	diff := bodyLen - c.bodyLen
	if diff < 0 {
		diff = -diff
	}
	return diff <= tol
}

// normalizeContentType lower-cases a Content-Type header and drops its
// parameters (";charset=utf-8", ";boundary=..."), leaving just the media
// type for comparison.
func normalizeContentType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// isStructuredSpecContentType reports whether a normalized Content-Type
// plausibly belongs to a real machine-readable API spec (JSON or YAML) —
// the gate LT-30 adds before probeCommonPaths records an APISpecFact, so an
// HTML shell served at /swagger.json no longer counts as "a spec is
// publicly reachable."
func isStructuredSpecContentType(ct string) bool {
	switch ct {
	case "application/json", "text/json",
		"application/yaml", "text/yaml", "application/x-yaml", "text/x-yaml",
		"application/openapi+json", "application/vnd.oai.openapi+json",
		"application/openapi+yaml", "application/vnd.oai.openapi":
		return true
	}
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+yaml")
}

// specPaths is the subset of commonPaths whose presence is itself a
// higher-value finding than a generic discovered endpoint — a publicly
// reachable OpenAPI/Swagger doc can reveal the whole route/parameter
// surface. Recorded as an APISpecFact (presence-only, never parsed — see
// APISpecFact's own doc comment) in addition to the usual EndpointFact.
var specPaths = map[string]string{
	"/swagger.json":             "openapi",
	"/.well-known/openapi.json": "openapi",
}

// authBoundaryKeywords are lowercase substrings whose presence in a page
// body suggests a login/auth boundary — cheap heuristic; doesn't attempt to
// break anything, just answers "are the IDOR/authbypass detectors even
// applicable here" (docs/91-research-recon-phase.md §3, Wave 3).
var authBoundaryKeywords = []string{`type="password"`, "oauth", "sign in", "log in", "login"}

// runWave3 is the bounded application-layer mapping wave: a katana crawl
// (which also parses JS bundles for embedded API paths via its own -jc
// flag — no separate JS parser this pass) plus direct common-path probing
// and a lightweight auth-boundary tag. liveURLs comes from Wave 2's httpx
// results; if empty (e.g. httpx unavailable), falls back to target itself
// so Wave 3 can still run something.
func (r *Recon) runWave3(ctx context.Context, agg *aggregator, target string, liveURLs []string) {
	seeds := liveURLs
	if len(seeds) == 0 {
		seeds = []string{target}
	}

	r.runKatana(ctx, agg, seeds)

	for _, seed := range seeds {
		r.probeCommonPaths(ctx, agg, seed)
		r.tagAuthBoundary(ctx, agg, seed)
	}
}

// runKatana crawls seeds. katana's own default scope ("-fs rdn", confirmed
// via its real -h output — not assumed) already keeps it from *fetching*
// links outside the seed's root domain; what still reaches this output is
// an out-of-scope link katana noticed but refused to follow, tagged with a
// non-empty "error" field (e.g. "max depth reached") instead of a real
// response. Those aren't confirmed endpoints — if the link's host also
// differs from every seed's own host, docs/91-research-recon-phase.md §3's
// "a genuinely new external domain found mid-crawl... set aside into
// OutOfScope, not silently followed" applies, so it's recorded there
// instead of silently dropped.
func (r *Recon) runKatana(ctx context.Context, agg *aggregator, seeds []string) {
	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	katanaArgs := []string{
		"-silent", "-jsonl", "-jc", "-depth", "2", "-rate-limit", itoa(r.rateLimit), "-concurrency", itoa(r.concurrency),
	}
	katanaArgs = append(katanaArgs, r.headerArgs()...) // LT-36: program-mandated identifying header on every crawl request
	out, err := r.run(waveCtx, strings.Join(seeds, "\n"), "katana", katanaArgs...)
	if err != nil && !isWaveTimeout(err) {
		if isBinaryMissing(err) {
			agg.addWarning("wave3: %v — crawl skipped", err)
		} else {
			agg.addWarning("wave3: katana: %v", err)
		}
		return
	}
	if isWaveTimeout(err) {
		// katana has no depth/rate visibility and a silent internal cap; a
		// wave-timeout kill means the crawl was still in progress. Whatever it
		// streamed is parsed below, but it's a partial map (LT-38).
		agg.addWarning("wave3: katana: %v (crawl did not run to completion)", err)
	}

	seedHosts := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedHosts[hostOnly(s)] = true
	}

	var authCandidates []EndpointFact
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			Request struct {
				Endpoint string `json:"endpoint"`
				Method   string `json:"method"`
			} `json:"request"`
			Response struct {
				StatusCode int `json:"status_code"`
			} `json:"response"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.Request.Endpoint == "" {
			continue
		}
		host := hostOnly(rec.Request.Endpoint)
		if rec.Error != "" {
			if !seedHosts[host] {
				agg.addOutOfScope(host)
			}
			continue // not a confirmed endpoint — katana didn't actually fetch it
		}
		// LT-52 (docs/follow-up.md): katana's default "-fs rdn" scope keeps it
		// on the seed's root domain, but a cross-host link it actually fetched
		// (a CDN/asset host referenced by the page — e.g. images.meesho.com off
		// superstoreapp.meesho.com) still lands here with no rec.Error. Keep it
		// only when its host is a seed or explicitly in --scope; otherwise it's
		// an out-of-scope host that happened to answer, recorded in OutOfScope
		// like the rec.Error case above, never in Endpoints.
		if !seedHosts[host] && r.scope != nil && !r.scope.Allowed("https://"+host) {
			agg.addOutOfScope(host)
			continue
		}
		if looksLikeEscapedJSArtifact(rec.Request.Endpoint) {
			continue // see looksLikeEscapedJSArtifact's own doc comment
		}
		method := rec.Request.Method
		if method == "" {
			method = http.MethodGet
		}
		// StatusCode was found live (docs/14-implementation-plan-ph5.md Step
		// 7's second live-testing pass, 2026-09-01) to always be 0 here —
		// katana's own "response" object was present in its JSONL output all
		// along, this struct just never decoded it, silently discarding a
		// real signal authbypass's recon-derived protected-path suggestion
		// depends on.
		ef := EndpointFact{URL: rec.Request.Endpoint, Method: method, StatusCode: rec.Response.StatusCode, Source: "katana-crawl", Confidence: ConfidenceMedium}
		if ef.StatusCode == http.StatusUnauthorized || ef.StatusCode == http.StatusForbidden {
			// Held back for verifyAuthCandidates rather than added directly
			// — see its own doc comment for why a single crawl-time 401/403
			// isn't trusted on its own.
			authCandidates = append(authCandidates, ef)
			continue
		}
		agg.addEndpoint(ef)
	}

	r.verifyAuthCandidates(waveCtx, agg, authCandidates)
}

// looksLikeEscapedJSArtifact reports whether endpoint carries a literal
// backslash or its percent-encoded form ("%5C"/"%5c") — never valid in a
// real URL path, so this is always a JS-parsing artifact, not a genuine
// endpoint. Found live against a real target, 2026-09-04: katana's -jc
// extractor, run against a Next.js app whose pages embed a JSON-serialized
// route tree inside an inline <script> tag (escaped as "\/en\/..." in the
// raw HTML source), mis-parsed those escapes into endpoints like
// "/en%5C", "/favicon.png%5C%5C", "/r-wordmark.svg%5C%5C%5C%5C" — 14 of
// this one target's 128 raw katana observations (~11%), all correctly
// 404s (nothing real was ever at those addresses), each one always
// carrying source attribute "text" (inline script content, not a real
// href/src) rather than the "href"/"src"/"link" attributes a genuine
// discovered link has. Dropped here, at ingestion, rather than filtered
// only from display — this is wrong data outright, not just low-value
// noise (contrast IsStaticAssetPath in suggest.go), so no downstream
// consumer (the Endpoints table, JSON export, authbypass/idor/ssrf
// suggesters) should ever see it.
func looksLikeEscapedJSArtifact(endpoint string) bool {
	return strings.ContainsRune(endpoint, '\\') || strings.Contains(strings.ToUpper(endpoint), "%5C")
}

// verifyAuthCandidates re-issues one direct GET per katana-observed
// 401/403 candidate before trusting it as evidence of real access control
// — a single crawl-time observation can come from bot-protection/a WAF
// blocking the crawler rather than the target's own auth logic. Found
// live, 2026-09-04: a real target's "/giftcard/" (a public redirect to a
// third-party gift-card storefront, no auth wall at all) got a 401 during
// the katana crawl, was trusted as "protected," and produced a false
// authbypass "missing auth" finding once the deterministic detector
// reasonably found it reachable unauthenticated. Only kept — at
// ConfidenceHigh, up from katana-crawl's own ConfidenceMedium, since this
// is now an independently reproduced signal rather than a single
// observation — when the same status code reproduces; dropped otherwise.
// Cost is bounded to the (typically small) subset of a crawl that actually
// hit 401/403, not the whole crawl.
func (r *Recon) verifyAuthCandidates(ctx context.Context, agg *aggregator, candidates []EndpointFact) {
	for _, ef := range candidates {
		host := hostOnly(ef.URL)
		if r.hostErrors.ShouldSkip(host) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ef.URL, nil)
		if err != nil {
			continue
		}
		r.applyHeaders(req)
		resp, err := r.client.Do(req)
		if err != nil {
			r.hostErrors.RecordError(host)
			continue
		}
		r.hostErrors.RecordSuccess(host)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == ef.StatusCode {
			ef.Confidence = ConfidenceHigh
			agg.addEndpoint(ef)
		}
	}
}

// probeCommonPaths GETs commonPaths against seed via the same rate-limited,
// circuit-broken httpclient.Client every detector uses — this is our own
// direct HTTP traffic, unlike the binary-shelled waves above.
//
// LT-30 (docs/follow-up.md): before recording anything, it GETs one
// guaranteed-nonexistent canary path so a 2xx/3xx that's byte-shaped
// identical to that canary (a SPA catch-all, a soft-404, a WAF page served
// for everything) is dropped as noise rather than fabricating an endpoint —
// and an APISpecFact is recorded only when the spec path's Content-Type is
// actually JSON/YAML, not just when it returned 200.
func (r *Recon) probeCommonPaths(ctx context.Context, agg *aggregator, seed string) {
	base := strings.TrimRight(seed, "/")
	host := hostOnly(base)
	if r.hostErrors.ShouldSkip(host) {
		return
	}

	canary := r.fetchReconCanary(ctx, agg, base, host)

	suppressed := 0
	blocked, answered := 0, 0
	for _, path := range commonPaths {
		reqURL := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			continue
		}
		r.applyHeaders(req)
		resp, err := r.client.Do(req)
		if err != nil {
			// LT-4 (docs/follow-up.md): before this, a host that failed every
			// wave3 request did so 100% silently — hostErrors.ShouldSkip
			// tripping was never logged anywhere, so a real recon run could
			// lose Wave 3 entirely for a broken host with no visible trace.
			// Detect the trip transition (not-yet-skipped -> skipped) here so
			// exactly one warning fires per host, not one per remaining path.
			wasOK := !r.hostErrors.ShouldSkip(host)
			r.hostErrors.RecordError(host)
			if wasOK && r.hostErrors.ShouldSkip(host) {
				agg.addWarning("wave3: %s: repeated request errors (last: %v) — no further common-path/auth-boundary probes will run against this host", host, err)
			}
			continue
		}
		r.hostErrors.RecordSuccess(host)
		n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxCanaryBodyRead))
		_ = resp.Body.Close()
		answered++
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
			blocked++ // D6 / LT-62: an intercept status, not the app routing
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 400 {
			continue
		}
		bodyLen := int(n)
		ctype := normalizeContentType(resp.Header.Get("Content-Type"))
		if canary.sameAsCanary(resp.StatusCode, bodyLen, ctype) {
			suppressed++
			blocked++ // every path is the same catch-all page — recon is blind here too
			continue  // indistinguishable from the catch-all — not a real resource
		}
		agg.addEndpoint(EndpointFact{
			URL: reqURL, Method: http.MethodGet, StatusCode: resp.StatusCode,
			BodyLen: bodyLen, ContentType: resp.Header.Get("Content-Type"),
			Source: "wave3-common-path-probe", Confidence: ConfidenceHigh,
		})
		if kind, ok := specPaths[path]; ok && isStructuredSpecContentType(ctype) {
			agg.addAPISpec(APISpecFact{Kind: kind, URL: reqURL})
		}
	}
	if suppressed > 0 {
		agg.addWarning("wave3: %s: %d common-path probe(s) returned a response indistinguishable from a random-path canary (uniform SPA/catch-all) — not recorded as endpoints (LT-30)", host, suppressed)
	}

	r.recordUniformResponse(ctx, agg, base, host, canary, blocked, answered)
}

// recordUniformResponse classifies whether host is a uniform wall — a
// WAF/bot/auth block layer or a SPA/bucket catch-all — from the canary
// probe plus a single root GET, and records the verdict on the aggregator
// (Phase 7 Step 4 D6). The blocked/answered counts from probeCommonPaths'
// own loop become UniformResponseFact.BlockedRatio (LT-62).
//
// Three refinements over the original canary-only path:
//   - LT-72 / LT-86a: when this wave's own canary probe errored (a reset,
//     a Cloudflare challenge, or the LT-4 circuit breaker having tripped
//     mid-wave-3), fall back to the wave-2 httpx GET of the root — a 401/403
//     root, or a known block-page marker in its title, is decisive on its
//     own, and a clean 2xx root there means there is no wall to record.
//   - LT-82: never set a `catchall`/`waf-block` verdict when recon's own
//     crawl already mapped several distinct endpoints spanning more than one
//     routed status code (a real 404 among 200s) — that combination is
//     proof the "one page for every path" conclusion is wrong, and the
//     scanner would otherwise short-circuit the whole corpus on it.
func (r *Recon) recordUniformResponse(ctx context.Context, agg *aggregator, base, host string, canary canaryResponse, blocked, answered int) {
	distinct, statuses, httpxRoot := hostEndpointEvidence(agg, host)

	var canaryObs uniformwall.Observation
	switch {
	case canary.fetched:
		canaryObs = uniformwall.Observation{
			Status: canary.status, BodyLen: canary.bodyLen, ContentType: canary.contentType,
			ServerHeader: canary.server, Body: canary.bodySample,
		}
	case httpxRoot != nil:
		// LT-72 / LT-86a: no usable canary this wave, but wave 2 already has
		// a readable root. Treat that as the yardstick instead of bailing.
		canaryObs = uniformwall.Observation{
			Status: httpxRoot.StatusCode, BodyLen: httpxRoot.BodyLen,
			ContentType: httpxRoot.ContentType, Body: []byte(httpxRoot.Title),
		}
	default:
		return
	}

	var rootObs *uniformwall.Observation
	if o, ok := r.fetchRootObservation(ctx, base, host); ok {
		rootObs = &o
	} else if httpxRoot != nil && canary.fetched {
		rootObs = &uniformwall.Observation{
			Status: httpxRoot.StatusCode, BodyLen: httpxRoot.BodyLen,
			ContentType: httpxRoot.ContentType, Body: []byte(httpxRoot.Title),
		}
	}
	verdict := uniformwall.Classify(canaryObs, rootObs)
	if verdict == uniformwall.VerdictNone {
		return
	}
	if crawlEvidenceRefutesWall(distinct, statuses) {
		agg.addWarning("wave3: %s: a uniform-wall signal (%s) was suppressed — recon already mapped %d distinct endpoints across %d routed status codes on this host, which contradicts it (LT-82)", host, verdict, distinct, countRoutedStatuses(statuses))
		return
	}
	effCanaryStatus := canary.status
	if !canary.fetched && httpxRoot != nil {
		effCanaryStatus = httpxRoot.StatusCode
	}
	ratio := 0.0
	if answered > 0 {
		ratio = float64(blocked) / float64(answered)
	}
	agg.setUniformResponse(UniformResponseFact{
		Host: host, Kind: string(verdict), CanaryStatus: effCanaryStatus, BlockedRatio: ratio,
	})
	switch verdict {
	case uniformwall.VerdictWAFBlock:
		agg.addWarning("wave3: %s: every probe hit a WAF/bot/auth block wall (canary status %d, %.0f%% of probes intercepted) — recon is blind here; a scan from this vantage will not reach the application (D6/LT-59; consider an in-region/residential egress)", host, effCanaryStatus, ratio*100)
	case uniformwall.VerdictCatchall:
		agg.addWarning("wave3: %s: host returns one generic catch-all page for every path (canary status %d) — no real routing to map from this vantage (D6/LT-43)", host, effCanaryStatus)
	}
}

// hostEndpointEvidence summarises what recon's other passes already recorded
// for host: the number of distinct endpoint URLs, the set of distinct HTTP
// status codes seen across them, and the wave-2 httpx GET of the root
// (Source "httpx", root path) if one exists. recordUniformResponse uses the
// root as a canary fallback (LT-72 / LT-86a) and the distinct/status counts
// to veto a uniform-wall verdict the crawl itself refutes (LT-82).
func hostEndpointEvidence(agg *aggregator, host string) (distinct int, statuses map[int]bool, httpxRoot *EndpointFact) {
	statuses = map[int]bool{}
	seenURL := map[string]bool{}
	host = NormalizeHost(host)
	for i := range agg.endpoints {
		ep := &agg.endpoints[i]
		if NormalizeHost(hostOnly(ep.URL)) != host {
			continue
		}
		if !seenURL[ep.URL] {
			seenURL[ep.URL] = true
			distinct++
		}
		if ep.StatusCode != 0 {
			statuses[ep.StatusCode] = true
		}
		if httpxRoot == nil && ep.Source == "httpx" && ep.StatusCode != 0 && isRootURL(ep.URL) {
			httpxRoot = ep
		}
	}
	return distinct, statuses, httpxRoot
}

// isRootURL reports whether rawURL's path is empty or "/".
func isRootURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Path == "" || u.Path == "/"
}

// countRoutedStatuses counts distinct status codes that represent the
// application actually routing a request — anything but a throttle (429) or
// a gateway/server error (5xx). Used only for the suppression warning's
// wording; the decision itself is crawlEvidenceRefutesWall's stricter test.
func countRoutedStatuses(statuses map[int]bool) int {
	n := 0
	for s := range statuses {
		if s == http.StatusTooManyRequests || s >= 500 {
			continue
		}
		n++
	}
	return n
}

// crawlEvidenceRefutesWall reports whether recon's own crawl already mapped
// enough of a host to contradict a "one generic page for every path"
// verdict (LT-82). The dispositive signal is a genuine 404 sitting among
// real 2xx responses across several distinct endpoints: a WAF/bot/auth wall
// answers a nonexistent path 401/403/429 (never 404), and a storage
// catch-all answers it 2xx — neither produces a real 404 alongside real
// content. Deliberately strict so a selective challenge that lets a couple
// of paths through (the model D6 case on accounts.shopify.com) is NOT
// mistaken for a mapped surface.
func crawlEvidenceRefutesWall(distinct int, statuses map[int]bool) bool {
	const minDistinctEndpoints = 5
	if distinct < minDistinctEndpoints {
		return false
	}
	has2xx, has404 := false, false
	for s := range statuses {
		switch {
		case s >= 200 && s < 300:
			has2xx = true
		case s == http.StatusNotFound:
			has404 = true
		}
	}
	return has2xx && has404
}

// fetchRootObservation GETs base+"/" once for recordUniformResponse's
// Classify — the root's shape is what tells a real SPA (shell on unknown
// paths, real content at "/") from a total catch-all. ok is false on a
// request error; the circuit breaker is already handled by the caller's
// loop, so this only reads.
func (r *Recon) fetchRootObservation(ctx context.Context, base, host string) (uniformwall.Observation, bool) {
	if r.hostErrors.ShouldSkip(host) {
		return uniformwall.Observation{}, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return uniformwall.Observation{}, false
	}
	r.applyHeaders(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return uniformwall.Observation{}, false
	}
	sample, n := readBodySampleAndLen(resp.Body)
	_ = resp.Body.Close()
	return uniformwall.Observation{
		Status: resp.StatusCode, BodyLen: n,
		ContentType:  normalizeContentType(resp.Header.Get("Content-Type")),
		ServerHeader: resp.Header.Get("Server"), Body: sample,
	}, true
}

// fetchReconCanary GETs reconCanaryPath against base once, giving
// probeCommonPaths' sameAsCanary a yardstick. A request error just leaves
// canaryResponse.fetched false — every real probe below then records
// unsuppressed, exactly as before LT-30 existed — and is fed through the
// same hostErrors circuit breaker as the real probes so a wholly-broken
// host still trips it here.
func (r *Recon) fetchReconCanary(ctx context.Context, agg *aggregator, base, host string) canaryResponse {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+reconCanaryPath, nil)
	if err != nil {
		return canaryResponse{}
	}
	r.applyHeaders(req)
	resp, err := r.client.Do(req)
	if err != nil {
		wasOK := !r.hostErrors.ShouldSkip(host)
		r.hostErrors.RecordError(host)
		if wasOK && r.hostErrors.ShouldSkip(host) {
			agg.addWarning("wave3: %s: repeated request errors (last: %v) — no further common-path/auth-boundary probes will run against this host", host, err)
		}
		return canaryResponse{}
	}
	r.hostErrors.RecordSuccess(host)
	sample, n := readBodySampleAndLen(resp.Body)
	_ = resp.Body.Close()
	return canaryResponse{
		fetched:     true,
		status:      resp.StatusCode,
		bodyLen:     n,
		contentType: normalizeContentType(resp.Header.Get("Content-Type")),
		server:      resp.Header.Get("Server"),
		bodySample:  sample,
	}
}

// readBodySampleAndLen reads up to blockPageSampleBytes of body into a
// returned slice (for pkg/uniformwall marker matching) while still counting
// the full body length up to maxCanaryBodyRead (for the sameAsCanary shape
// comparison) — the rest is discarded.
func readBodySampleAndLen(body io.Reader) (sample []byte, total int) {
	sample = make([]byte, 0, blockPageSampleBytes)
	buf := make([]byte, 4096)
	for total < maxCanaryBodyRead {
		nr, err := body.Read(buf)
		if nr > 0 {
			total += nr
			if len(sample) < blockPageSampleBytes {
				take := blockPageSampleBytes - len(sample)
				if take > nr {
					take = nr
				}
				sample = append(sample, buf[:take]...)
			}
		}
		if err != nil {
			break
		}
	}
	return sample, total
}

// tagAuthBoundary fetches seed's homepage once and tags an EndpointFact if
// it looks like a login/auth boundary — doesn't attempt to break anything.
func (r *Recon) tagAuthBoundary(ctx context.Context, agg *aggregator, seed string) {
	// A host probeCommonPaths already gave up on (LT-4) is exceedingly
	// unlikely to answer this single request either — skip it rather than
	// spend one more probe (and one more silent failure) on a host already
	// known to be broken.
	if r.hostErrors.ShouldSkip(hostOnly(seed)) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, seed, nil)
	if err != nil {
		return
	}
	r.applyHeaders(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if looksLikeAuthBoundary(body) {
		agg.addEndpoint(EndpointFact{URL: seed, Method: http.MethodGet, Source: "wave3-auth-boundary-heuristic", Confidence: ConfidenceLow})
	}
}

func looksLikeAuthBoundary(body []byte) bool {
	lower := strings.ToLower(string(body))
	for _, kw := range authBoundaryKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
