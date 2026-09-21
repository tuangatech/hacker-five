package recon

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// jsAsset is one served JavaScript body Wave 3 already fetched (via katana's
// own -jc crawl) that runJSStaticAnalysis inspects — captured once at
// ingestion (runKatana), analyzed here with zero new requests (Phase 8 Step
// 3, docs/17-implementation-plan-ph8.md: "pure functions over data recon
// already has in hand").
type jsAsset struct {
	URL  string
	Body string
}

const (
	// maxJSStaticAssets bounds how many distinct .js bodies one recon run
	// analyzes — the crawl can surface far more than this on a large SPA;
	// analyzing the first N keeps the regex/entropy work bounded.
	maxJSStaticAssets = 25
	// maxJSStaticBodyBytes truncates a single JS body before it's even kept
	// (set at capture time in runKatana). Raised from 512 KiB to 4 MiB
	// (LT-164, docs/follow-up.md): the original 512 KiB assumption — "a
	// multi-MB bundle's tail is usually vendored/minified library code, not
	// application routes" — is live-disproven by crAPI's own single-file CRA
	// build (no code-splitting): its route-prefix/API-path constants sit at
	// byte ~1.6M of a 1.65 MB bundle, entirely past the old cap, so the
	// original extractJSEndpoints pass (and LT-164's join pass) silently saw
	// nothing past the truncation point. 4 MiB covers this real bundle with
	// headroom, in line with maxSpecBodyBytes' own "generous headroom, still
	// bounded" reasoning.
	maxJSStaticBodyBytes = 4 << 20
	// maxJSQuotedStringsPerAsset bounds how many quoted-string candidates one
	// asset's regex pass considers, so a single pathological bundle (huge
	// data URI, embedded JSON blob) can't blow up the CPU cost of one file.
	// Raised from 5000 to 60000 alongside maxJSStaticBodyBytes (LT-164,
	// docs/follow-up.md): live-verified crAPI's own bundle carries 20,650
	// quoted-string matches before even reaching its route constants — a
	// dense but entirely ordinary minified single-file build, not a
	// pathological one. 60000 keeps real bundles like this one from being
	// silently cut off a second time by this cap right after
	// maxJSStaticBodyBytes was raised to stop truncating the byte count.
	maxJSQuotedStringsPerAsset = 60000
	// maxJSStaticEndpoints / maxJSStaticSecrets bound the total facts one run
	// emits from this pass, each with a truncation warning past the cap —
	// same "bounded, not silently truncated" convention as maxSpecEndpoints.
	maxJSStaticEndpoints = 150
	maxJSStaticSecrets   = 50

	// maxJSPathPrefixes / maxJSPathBases / maxJSQuerySuffixes bound how many
	// of each join-part class (LT-164, docs/follow-up.md) one asset
	// contributes. maxJSPathBases was 15 until LT-186: the candidates are
	// sorted, so on a real bundle (crAPI: 41 route literals) everything past the
	// 15th name alphabetically was never considered, including every route
	// under "api/v2/". Candidates beyond a cap are counted and reported in a
	// warning, never dropped silently.
	maxJSPathPrefixes  = 8
	maxJSPathBases     = 80
	maxJSQuerySuffixes = 10
	// maxJSJoinProbes caps how many prefix+base GETs runJSStaticAnalysis issues
	// in total, across every asset in one recon run — the one place this pass
	// stops being "pure, no new requests" (runJSStaticAnalysis's own doc
	// comment). It counts requests, not pairs: verifyJSJoinBases stops at the
	// first prefix that verifies a base and tries the prefix that verified its
	// nearest sibling first, so a bundle usually costs one to two probes per
	// route rather than one per prefix (LT-186). Templated routes cost none.
	maxJSJoinProbes = 300
)

// looksLikeJSAsset reports whether a katana-observed record is a JavaScript
// response worth capturing the body of — by URL extension (the common case)
// or by a captured Content-Type header (a .js-less route serving script,
// e.g. a bundler dev-server path).
func looksLikeJSAsset(rawURL string, headers map[string]string) bool {
	if u, err := url.Parse(rawURL); err == nil && strings.HasSuffix(strings.ToLower(u.Path), ".js") {
		return true
	}
	for k, v := range headers {
		if strings.EqualFold(k, "content-type") {
			ct := strings.ToLower(v)
			return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
		}
	}
	return false
}

// jsQuotedStringRe pulls every double- or single-quoted string literal out
// of a JS body — deliberately shape-agnostic (LinkFinder-style: grab
// everything quoted, then filter in Go) rather than trying to encode "looks
// like a URL" into the regex itself, which is far harder to review and tune.
var jsQuotedStringRe = regexp.MustCompile(`"([^"\n]{2,200})"|'([^'\n]{2,200})'`)

// isCandidateEndpointString reports whether a quoted string literal is
// shaped like a real request path or absolute URL — the coarse pre-filter
// before IsPlausibleURLPath/IsNonRouteAssetPath do the real work.
func isCandidateEndpointString(s string) bool {
	if strings.HasPrefix(s, "/") {
		return len(s) > 2 && s[1] != '/' && s[1] != '.'
	}
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// extractJSEndpoints returns every plausible relative-path or absolute-URL
// candidate found in body, resolved against assetURL's own host for a
// relative path. Filtering reuses the same IsPlausibleURLPath (LT-85,
// rejects a JS-syntax fragment) / IsNonRouteAssetPath (static/build-artifact
// noise) helpers the recon-derived candidate suggesters already rely on, so
// this pass holds itself to the identical bar rather than inventing a
// second one.
func extractJSEndpoints(assetURL, body string) []string {
	assetHost := ""
	if u, err := url.Parse(assetURL); err == nil {
		assetHost = u.Scheme + "://" + u.Host
	}

	matches := jsQuotedStringRe.FindAllStringSubmatch(body, maxJSQuotedStringsPerAsset)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		if !isCandidateEndpointString(s) {
			continue
		}
		if strings.HasPrefix(s, "/") {
			if !IsPlausibleURLPath(s) || IsNonRouteAssetPath(s) {
				continue
			}
			if assetHost == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, assetHost+s)
			continue
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.Path == "" || u.Path == "/" {
			continue
		}
		if !IsPlausibleURLPath(u.Path) || IsNonRouteAssetPath(u.Path) {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// isJSPathPrefixCandidate reports whether a quoted string literal is shaped
// like a bare service-route prefix constant — a single path segment,
// letters/digits/underscore/hyphen only, ending in exactly one trailing
// slash ("workshop/", "identity/", "community/"). LT-164 (docs/follow-up.md):
// live-verified against crAPI's own bundled JS, a microservice gateway's
// front end commonly stores each backend's route prefix as its own short
// constant, joined at call time with a separately-declared API path constant
// — neither half alone passes isCandidateEndpointString's "starts with / or
// http" gate, so extractJSEndpoints never sees the combination at all.
// Deliberately narrow (single segment, no embedded slash) to keep this from
// matching an unrelated short string that happens to end in "/".
var jsPathPrefixPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{1,20}/$`)

func isJSPathPrefixCandidate(s string) bool {
	return jsPathPrefixPattern.MatchString(s)
}

// isJSAPIPathBaseCandidate reports whether a quoted string literal is shaped
// like a bare (no leading slash) API route constant whose first segment is
// literally "api" — e.g. "api/mechanic/mechanic_report". Requiring the "api"
// first segment (rather than accepting any bare multi-segment string) keeps
// this tightly scoped to the concrete pattern LT-164 found live, matching
// this project's stated bias toward a doubtful pattern being left out rather
// than guessed (docs/follow-up.md, Phase 8 Step 3's own note on
// jsSecretPatterns). Plausibility/asset filtering is reused from the
// leading-slash case by checking "/"+s against the same helpers.
func isJSAPIPathBaseCandidate(s string) bool {
	if s == "" || strings.HasPrefix(s, "/") || strings.Contains(s, "://") {
		return false
	}
	segments := strings.Split(s, "/")
	if len(segments) < 2 || !strings.EqualFold(segments[0], "api") {
		return false
	}
	withSlash := "/" + s
	return IsPlausibleURLPath(withSlash) && !IsNonRouteAssetPath(withSlash)
}

// isJSQuerySuffixCandidate reports whether a quoted string literal is a bare
// keyless query-string literal — "?report_id=" — the same shape
// specwalk.go's OpenAPI walker already encodes for a documented-but-valueless
// query parameter (idShapedQueryCandidate's rawVal=="" case in suggest.go).
// LT-164: crAPI's own bundle builds a request URL as
// `prefix + apiPathConst + "?report_id=" + id`, so this exact literal shape
// is what completes the join into an id-shaped candidate.
var jsQuerySuffixPattern = regexp.MustCompile(`^\?[a-zA-Z][a-zA-Z0-9_]{1,30}=$`)

func isJSQuerySuffixCandidate(s string) bool {
	return jsQuerySuffixPattern.MatchString(s)
}

// jsPlaceholderSegment matches one whole path segment written as a client-side
// route placeholder, "<orderId>". A bundle declares a parameterised route as a
// template ("api/shop/orders/<orderId>") and fills the segment at call time.
var jsPlaceholderSegment = regexp.MustCompile(`^<([A-Za-z_][A-Za-z0-9_]{0,30})>$`)

// normalizeJSPathPlaceholders rewrites "<name>" path segments to the OpenAPI
// spelling "{name}", the form recon already treats as an identifier position
// (isSpecPathParam) and that no JS-syntax filter rejects. Only a whole segment
// counts: "a<b>c" is left alone and so still fails the plausibility check.
func normalizeJSPathPlaceholders(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		if m := jsPlaceholderSegment.FindStringSubmatch(seg); m != nil {
			segs[i] = "{" + m[1] + "}"
		}
	}
	return strings.Join(segs, "/")
}

// collectJSPathJoinParts classifies every quoted string literal in body into
// (at most) one of three join-part buckets — LT-164, docs/follow-up.md. Sorted
// and de-duplicated but not capped, so a caller that caps can say how many it
// cut; extractJSPathJoinParts is the capped form. A base written with "<name>"
// placeholders comes back in "{name}" form (LT-186).
func collectJSPathJoinParts(body string) (prefixes, bases, querySuffixes []string) {
	matches := jsQuotedStringRe.FindAllStringSubmatch(body, maxJSQuotedStringsPerAsset)
	seenPrefix, seenBase, seenSuffix := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, m := range matches {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		switch {
		case isJSPathPrefixCandidate(s):
			if !seenPrefix[s] {
				seenPrefix[s] = true
				prefixes = append(prefixes, s)
			}
		case isJSAPIPathBaseCandidate(normalizeJSPathPlaceholders(s)):
			s = normalizeJSPathPlaceholders(s)
			if !seenBase[s] {
				seenBase[s] = true
				bases = append(bases, s)
			}
		case isJSQuerySuffixCandidate(s):
			if !seenSuffix[s] {
				seenSuffix[s] = true
				querySuffixes = append(querySuffixes, s)
			}
		}
	}
	sort.Strings(prefixes)
	sort.Strings(bases)
	sort.Strings(querySuffixes)
	return prefixes, bases, querySuffixes
}

// extractJSPathJoinParts is collectJSPathJoinParts with each bucket capped at
// its maxJS* limit, silently. runJSStaticAnalysis caps for itself so it can warn.
func extractJSPathJoinParts(body string) (prefixes, bases, querySuffixes []string) {
	prefixes, bases, querySuffixes = collectJSPathJoinParts(body)
	prefixes, _ = capStrings(prefixes, maxJSPathPrefixes)
	bases, _ = capStrings(bases, maxJSPathBases)
	querySuffixes, _ = capStrings(querySuffixes, maxJSQuerySuffixes)
	return prefixes, bases, querySuffixes
}

// capStrings truncates xs to n and reports how many it cut.
func capStrings(xs []string, n int) (kept []string, cut int) {
	if len(xs) <= n {
		return xs, 0
	}
	return xs[:n], len(xs) - n
}

// minJSTieNameLen is the shortest identifier assignQuerySuffixes trusts as a
// tie. A minifier mangles local variables to one or two letters that recur all
// over a bundle, so two unrelated statements sharing "t" prove nothing; an
// object property such as GET_SERVICE_REPORT survives minification and does.
const minJSTieNameLen = 3

// assignQuerySuffixes decides which keyless query suffix belongs to which
// verified base route (LT-184, docs/follow-up.md). A bundle declares a route
// constant in one place (`GET_SERVICE_REPORT:"api/mechanic/mechanic_report"`)
// and completes it where it is used (`ig+sg.GET_SERVICE_REPORT+"?report_id="+n`),
// so a suffix is tied to a base when the identifier the base is declared under
// is the one immediately followed by the suffix literal. Before this the
// suffixes were crossed with every verified base: one real `?report_id=` route
// became a dozen look-alikes across unrelated paths, and each became an idor
// leaf.
//
// A suffix that ties to no verified base is attached only when exactly one base
// verified, where there is nothing to be ambiguous about; with several it is
// dropped rather than guessed. The result maps a base to its suffixes; a base
// with none is emitted bare by the caller.
func assignQuerySuffixes(body string, verifiedBases, suffixes []string) map[string][]string {
	out := map[string][]string{}
	if len(verifiedBases) == 0 || len(suffixes) == 0 {
		return out
	}
	declaredAs := map[string]map[string]bool{} // base -> identifiers it is declared under
	for _, b := range verifiedBases {
		re := regexp.MustCompile("([A-Za-z_$][\\w$]*)\\s*[:=]\\s*[\"'`]" + regexp.QuoteMeta(b) + "[\"'`]")
		names := map[string]bool{}
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			if len(m[1]) >= minJSTieNameLen {
				names[m[1]] = true
			}
		}
		declaredAs[b] = names
	}

	distinctBases := map[string]bool{}
	for _, b := range verifiedBases {
		distinctBases[b] = true
	}
	for _, s := range suffixes {
		re := regexp.MustCompile("([A-Za-z_$][\\w$]*)\\s*\\+\\s*[\"'`]" + regexp.QuoteMeta(s) + "[\"'`]")
		usedAfter := map[string]bool{}
		for _, m := range re.FindAllStringSubmatch(body, -1) {
			usedAfter[m[1]] = true
		}
		tied := false
		for b := range distinctBases {
			for name := range declaredAs[b] {
				if usedAfter[name] {
					out[b] = appendUnique(out[b], s)
					tied = true
				}
			}
		}
		if !tied && len(distinctBases) == 1 {
			for b := range distinctBases {
				out[b] = appendUnique(out[b], s)
			}
		}
	}
	for b := range out {
		sort.Strings(out[b])
	}
	return out
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// jsJoinPair is one candidate prefix+base combination, kept structured
// (rather than pre-concatenated) so verifyJSJoinBases can group
// candidates by their originating prefix for the per-prefix canary check
// below — string-splitting a joined "prefix+base" back apart would be
// ambiguous whenever one prefix is itself a suffix of another.
type jsJoinPair struct {
	Prefix, Base string
}

func (p jsJoinPair) joined() string { return p.Prefix + p.Base }

// jsJoinVerifyStatuses are the response statuses that count as "this route
// really exists" for a bare prefix+base join candidate — deliberately not a
// broad 2xx/3xx check like probeCommonPaths' host-level canary, since the
// discriminator that matters here is per-*prefix*, not per-host (see
// fetchJSPrefixCanary's own doc comment): a join candidate is far more
// likely to be real when it answers as a route that exists but rejects this
// unauthenticated/paramless request (401/403/400/422/405) or plainly
// succeeds (200/201) than when it 404s like a wrong base under a real prefix
// does.
var jsJoinVerifyStatuses = map[int]bool{
	http.StatusOK: true, http.StatusCreated: true,
	http.StatusBadRequest: true, http.StatusUnauthorized: true, http.StatusForbidden: true,
	http.StatusMethodNotAllowed: true, http.StatusUnprocessableEntity: true,
	// A route that throws on a request missing its parameter still exists: crAPI's
	// mechanic_report answers 500 to an authenticated GET with no report_id, where an
	// unknown path answers 404. Without this the one known-vulnerable route dropped out
	// of recon whenever recon carried a token (LT-186). 502/503/504 are infrastructure
	// answers, not route evidence, and stay out; the prefix canary still has to differ.
	http.StatusInternalServerError: true,
}

// fetchJSPrefixCanary GETs a guaranteed-nonexistent path under prefix once,
// returning its status — LT-164: live-verified against crAPI, one of its
// real services (identity/, a Spring Security gateway) answers 401 for
// *every* path under its prefix, real or not, authenticated or not,
// including a path that plainly doesn't exist. A bare jsJoinVerifyStatuses
// membership check alone can't tell that service's real routes apart from
// every other base joined onto the same prefix — it would accept all of
// them, turning one real endpoint into several same-confidence look-alikes
// and reintroducing exactly the "multiple distinct candidates" ambiguity
// this whole verification step exists to resolve (see
// verifyJSJoinBases' own doc comment). ok is false on a request error;
// the caller then skips the canary-diff check for that prefix rather than
// blocking every candidate under it.
func (r *Recon) fetchJSPrefixCanary(ctx context.Context, assetHost, prefix string) (status int, ok bool) {
	reqURL := strings.TrimRight(assetHost, "/") + "/" + prefix + strings.TrimPrefix(reconCanaryPath, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return 0, false
	}
	r.applyHeaders(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCanaryBodyRead))
	_ = resp.Body.Close()
	return resp.StatusCode, true
}

// jsJoinResult is what verifyJSJoinBases found and what it could not settle.
type jsJoinResult struct {
	Verified []jsJoinPair
	// Unsettled counts plain bases left unverified because the probe budget ran
	// out; Uninferred counts templated bases with no verified sibling to borrow
	// a prefix from. Both are reported, never silent.
	Unsettled, Uninferred int
}

func jsSegments(base string) []string { return strings.Split(strings.Trim(base, "/"), "/") }

// sharedLeadingSegments is how many leading path segments a and b have in common.
func sharedLeadingSegments(a, b string) int {
	as, bs := jsSegments(a), jsSegments(b)
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] {
		n++
	}
	return n
}

// preferSiblingPrefix orders prefixes for base: the prefix that verified the
// base sharing the most leading segments with it (two at least) comes first,
// the rest keep their order. A service owns a resource family, so this turns
// "try all four prefixes" into "try the likely one first".
func preferSiblingPrefix(prefixes []string, verified []jsJoinPair, base string) []string {
	best, bestPrefix := 1, ""
	for _, v := range verified {
		if n := sharedLeadingSegments(v.Base, base); n > best {
			best, bestPrefix = n, v.Prefix
		}
	}
	if bestPrefix == "" {
		return prefixes
	}
	out := make([]string, 0, len(prefixes))
	out = append(out, bestPrefix)
	for _, p := range prefixes {
		if p != bestPrefix {
			out = append(out, p)
		}
	}
	return out
}

// verifyJSJoinBases finds, for each base, the service prefix under which the
// route is real — LT-164's live-verification step, reworked in LT-186.
//
// A plain base is GETed under each prefix (sibling-preferred order) until one
// answers as a route (jsJoinVerifyStatuses) and differently from that prefix's
// canary (fetchJSPrefixCanary); the first such prefix wins, since a route lives
// in one service. Every probe spends one unit of *budget, shared across the run.
//
// A templated base ("api/shop/orders/{orderId}") is never requested: the literal
// placeholder answers 404 like any unknown path (measured on crAPI), and recon
// does not invent an id to put there. It borrows the prefix of a verified plain
// base that shares all of its leading static segments ("api/shop/orders" for
// "api/shop/orders/{orderId}"), on the same reasoning that a service owns a
// resource family. With fewer than two leading static segments, or no such
// sibling, it is left unverified and counted. Same per-host circuit breaker
// (hostErrors) and scope gate as every other live probe in this package.
func (r *Recon) verifyJSJoinBases(ctx context.Context, agg *aggregator, assetHost string, prefixes, bases []string, budget *int) jsJoinResult {
	var res jsJoinResult
	host := hostOnly(assetHost)
	var plain, templated []string
	for _, b := range bases {
		if strings.Contains(b, "{") {
			templated = append(templated, b)
		} else {
			plain = append(plain, b)
		}
	}
	if r.hostErrors.ShouldSkip(host) {
		res.Unsettled = len(plain)
		res.Uninferred = len(templated)
		return res
	}

	canaryByPrefix := map[string]int{}
	canaryFetched := map[string]bool{}
	for i, base := range plain {
		found := false
		for _, prefix := range preferSiblingPrefix(prefixes, res.Verified, base) {
			if *budget <= 0 {
				break
			}
			reqURL := strings.TrimRight(assetHost, "/") + "/" + prefix + base
			if r.scope != nil && !r.scope.Allowed(reqURL) {
				agg.addOutOfScope(hostOnly(reqURL))
				continue
			}
			if !canaryFetched[prefix] {
				if status, ok := r.fetchJSPrefixCanary(ctx, assetHost, prefix); ok {
					canaryByPrefix[prefix] = status
				}
				canaryFetched[prefix] = true
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
			if err != nil {
				continue
			}
			r.applyHeaders(req)
			*budget--
			resp, err := r.client.Do(req)
			if err != nil {
				if !isRequestTimeout(err) {
					r.hostErrors.RecordError(host)
				}
				continue
			}
			r.hostErrors.RecordSuccess(host)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCanaryBodyRead))
			_ = resp.Body.Close()
			if canaryStatus, ok := canaryByPrefix[prefix]; ok && resp.StatusCode == canaryStatus {
				continue // this prefix answers every path alike — not a real signal
			}
			if jsJoinVerifyStatuses[resp.StatusCode] {
				res.Verified = append(res.Verified, jsJoinPair{Prefix: prefix, Base: base})
				found = true
				break
			}
		}
		if !found && *budget <= 0 {
			// Out of probes: this base and every later plain one is unsettled.
			res.Unsettled += len(plain) - i
			break
		}
	}

	plainVerified := append([]jsJoinPair(nil), res.Verified...)
	for _, t := range templated {
		static := 0
		for _, seg := range jsSegments(t) {
			if strings.Contains(seg, "{") {
				break
			}
			static++
		}
		seen := map[string]bool{}
		if static >= 2 {
			for _, v := range plainVerified {
				if sharedLeadingSegments(v.Base, t) >= static && !seen[v.Prefix] {
					seen[v.Prefix] = true
					res.Verified = append(res.Verified, jsJoinPair{Prefix: v.Prefix, Base: t})
				}
			}
		}
		if len(seen) == 0 {
			res.Uninferred++
		}
	}
	return res
}

// jsSecretPattern is one curated, high-signal secret pattern — deliberately
// small (Phase 8 Step 3, docs/follow-up.md: "a doubtful pattern is left out,
// not guessed", feeding the project's <5% false-positive target). group
// selects which regex submatch is the value to redact/entropy-check (0 =
// whole match); entropyFloor > 0 marks a shape-only pattern (no fixed
// vendor prefix) that also needs Shannon-entropy + placeholder screening.
type jsSecretPattern struct {
	kind         string
	severity     string
	re           *regexp.Regexp
	group        int
	entropyFloor float64
}

var jsSecretPatterns = []jsSecretPattern{
	// AWS access/session key IDs: a fixed 4-letter prefix + 16 fixed-width
	// base32-ish chars — effectively zero false-positive rate on its own.
	{kind: "aws-access-key", severity: "high", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	// Google API keys always start "AIzaSy" and are a fixed 39 chars.
	{kind: "google-api-key", severity: "medium", re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{kind: "slack-token", severity: "high", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,72}\b`)},
	// GitHub's current fine-grained/classic token prefixes.
	{kind: "github-token", severity: "critical", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{kind: "private-key", severity: "critical", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	// The one shape-only pattern — no vendor-fixed prefix, so it leans on
	// the entropy floor + placeholder screen below to cut noise.
	{kind: "hardcoded-bearer-token", severity: "medium",
		re:    regexp.MustCompile(`(?i)authorization["']?\s*[:=]\s*["']Bearer\s+([A-Za-z0-9\-_.=]{20,})["']`),
		group: 1, entropyFloor: 3.0},
}

// bearerPlaceholderMarkers are substrings (case-insensitive) that mark a
// Bearer-token literal as sample/placeholder text rather than a real leaked
// credential — checked before the entropy floor since a long repetitive
// placeholder can still clear a low entropy threshold.
var bearerPlaceholderMarkers = []string{
	"your_token", "your-token", "yourtoken", "changeme", "example",
	"xxxx", "placeholder", "token_here", "test_token", "sample",
	"<token>", "{{", "}}", "insert_token", "replace_me", "dummy", "fake",
}

// shannonEntropy returns the Shannon entropy of s in bits per character —
// low for repetitive/placeholder text, high for a genuinely random token.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// redactSecret keeps only the first/last few characters of a matched secret
// — enough to confirm the finding without the real value ever leaving this
// process into a ReconResult / JSON export.
func redactSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// extractJSSecrets scans body for jsSecretPatterns and returns one
// JSSecretFact per accepted hit, each carrying a 1-based line number and a
// redacted match — never the real secret value.
func extractJSSecrets(assetURL, body string) []JSSecretFact {
	var out []JSSecretFact
	for _, pat := range jsSecretPatterns {
		locs := pat.re.FindAllStringSubmatchIndex(body, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			if pat.group > 0 {
				gi := pat.group * 2
				if gi+1 >= len(loc) || loc[gi] < 0 {
					continue
				}
				start, end = loc[gi], loc[gi+1]
			}
			value := body[start:end]
			if pat.entropyFloor > 0 {
				lower := strings.ToLower(value)
				placeholder := false
				for _, m := range bearerPlaceholderMarkers {
					if strings.Contains(lower, m) {
						placeholder = true
						break
					}
				}
				if placeholder || shannonEntropy(value) < pat.entropyFloor {
					continue
				}
			}
			line := strings.Count(body[:start], "\n") + 1
			out = append(out, JSSecretFact{
				URL: assetURL, Line: line, Kind: pat.kind,
				Severity: pat.severity, Redacted: redactSecret(value),
			})
		}
	}
	return out
}

// cloudBucketRef is one AWS S3 / GCS bucket URL shape found in already-
// fetched text (a JS body or an endpoint URL) — P1-5, docs/follow-up.md.
type cloudBucketRef struct {
	kind string // "s3" | "gcp"
	url  string // the canonical bucket URL, host- or path-style as found
}

// The path-style patterns require the literal scheme immediately before the
// shared-bucket host ("https://s3.amazonaws.com/bucket") — without that
// anchor they also fire inside a host-style URL
// ("https://bucket.s3.amazonaws.com/key"), misreading the object key as a
// second, bogus bucket name.
var (
	s3BucketHostRe  = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b`)
	s3BucketPathRe  = regexp.MustCompile(`(?i)https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\b`)
	gcsBucketHostRe = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9_.-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b`)
	gcsBucketPathRe = regexp.MustCompile(`(?i)https?://storage\.googleapis\.com/([a-z0-9][a-z0-9_.-]{1,61}[a-z0-9])\b`)
)

// extractCloudBucketRefs finds AWS S3 / GCS bucket-URL shapes in text,
// deduped by (kind, url) within this one call.
func extractCloudBucketRefs(text string) []cloudBucketRef {
	seen := map[string]bool{}
	var refs []cloudBucketRef
	add := func(kind, rawURL string) {
		key := kind + "|" + rawURL
		if seen[key] {
			return
		}
		seen[key] = true
		refs = append(refs, cloudBucketRef{kind: kind, url: rawURL})
	}
	for _, m := range s3BucketHostRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("s3", "https://"+bucket+".s3.amazonaws.com/")
	}
	for _, m := range s3BucketPathRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("s3", "https://s3.amazonaws.com/"+bucket+"/")
	}
	for _, m := range gcsBucketHostRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("gcp", "https://"+bucket+".storage.googleapis.com/")
	}
	for _, m := range gcsBucketPathRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("gcp", "https://storage.googleapis.com/"+bucket+"/")
	}
	return refs
}

// recordCloudBucketRef turns one discovered bucket-URL shape into recon
// facts, gated on the bucket's own scope check — never on the page that
// mentioned it. The corpus's aws/s3/gcp-tagged bucket-exposure templates
// (aws-object-listing, s3-username-disclosure, ...) need to run *against the
// bucket itself* to mean anything, so the TechFact is attached to the
// bucket's own host, and only once that host independently clears --scope:
// a page can reference any number of third-party buckets that have nothing
// to do with the target's own infrastructure, so a mention alone earns
// neither a scan nor a fact about the referencing host.
func (r *Recon) recordCloudBucketRef(agg *aggregator, ref cloudBucketRef) {
	bucketHost := hostOnly(ref.url)
	if r.scope != nil && !r.scope.Allowed(ref.url) {
		agg.addOutOfScope(bucketHost)
		return
	}
	agg.addEndpoint(EndpointFact{URL: ref.url, Method: http.MethodGet, Source: "js-static-cloud", Confidence: ConfidenceLow})
	agg.addTech(TechFact{Name: ref.kind, Host: bucketHost, Source: "js-static-cloud", Confidence: ConfidenceMedium})
}

// runJSStaticAnalysis is Phase 8 Step 3 (docs/17-implementation-plan-ph8.md):
// endpoint extraction, hardcoded-secret detection, and cloud-provider
// bucket-URL fingerprinting over Wave 3's already-fetched JS bodies — mostly
// pure functions over data recon already has in hand, no new request, no new
// dependency.
//
// LT-164 (docs/follow-up.md) is the one exception to "no new request": a
// microservice gateway's SPA bundle often builds its real request URLs at
// runtime from two or three separately-declared string constants (a
// service-route prefix, a bare API-path constant, a keyless query-string
// literal) that individually never pass extractJSEndpoints' "starts with /
// or http" gate. collectJSPathJoinParts reconstructs the
// candidate joins; verifyJSJoinBases GETs each one (capped at
// maxJSJoinProbes) so a wrong prefix+base combination — indistinguishable
// from the right one by shape alone — is pruned before it can multiply
// idor's own "multiple distinct candidates" ambiguity problem
// (idorCandidatesAndSeeds' doc comment) instead of resolving it. Live-
// verified 2026-09-19 against crAPI: its bundle declares `ig="workshop/"`
// and `sg.GET_SERVICE_REPORT="api/mechanic/mechanic_report"` separately, and
// builds the real request as `ig+sg.GET_SERVICE_REPORT+"?report_id="+id` —
// exactly this join shape, previously invisible to recon entirely because
// neither piece is independently endpoint-shaped.
//
// LT-144 (docs/follow-up.md): extractJSEndpoints's absolute-URL branch only
// checks path *shape* (IsPlausibleURLPath/IsNonRouteAssetPath), never host —
// a page can reference an absolute URL on a completely unrelated third-party
// domain (a namespace URI, a CDN, a vendor's own site) and that host must
// clear --scope before its fact is kept, exactly like recordCloudBucketRef
// already does for bucket URLs a few lines above. Silently dropping an
// out-of-scope endpoint here isn't enough on its own — addOutOfScope logs it
// the same way every other out-of-scope path in this codebase does, so a
// surprising extraction is loud, not silently absent.
func (r *Recon) runJSStaticAnalysis(ctx context.Context, agg *aggregator, assets []jsAsset) {
	endpointsAdded, secretsAdded := 0, 0
	endpointsTruncated, secretsTruncated := false, false
	joinCandidatesVerified := 0
	joinProbeBudget := maxJSJoinProbes
	joinBasesCut, joinUnsettled, joinUninferred := 0, 0, 0

	// LT-164 (docs/follow-up.md): runKatana's crawl commonly observes the
	// same asset URL more than once (the same bundle linked from several
	// pages at different depths) — assets carries every such observation
	// with no dedup of its own. That was low-stakes for the pre-existing
	// extractJSEndpoints/extractJSSecrets passes (redundant work, but each
	// duplicate literal endpoint mention collapsed away downstream), but
	// live-verified against crAPI it broke this pass' own join step badly:
	// duplicate asset entries meant the same verified join candidate got
	// re-emitted as a byte-identical, second EndpointFact, which
	// registry.Resolve turned into a genuine *second* idor leaf for the same
	// URL — the orchestrator dispatched the real endpoint three times in one
	// run (once per duplicate), burning its whole time budget re-confirming
	// a leaf that had already produced real findings on the first pass.
	// Deduping by asset URL up front fixes this at its source rather than
	// patching each downstream symptom.
	seenAssetURL := map[string]bool{}

	for _, asset := range assets {
		if seenAssetURL[asset.URL] {
			continue
		}
		seenAssetURL[asset.URL] = true

		for _, epURL := range extractJSEndpoints(asset.URL, asset.Body) {
			if endpointsAdded >= maxJSStaticEndpoints {
				endpointsTruncated = true
				break
			}
			if r.scope != nil && !r.scope.Allowed(epURL) {
				agg.addOutOfScope(hostOnly(epURL))
				continue
			}
			agg.addEndpoint(EndpointFact{URL: epURL, Method: http.MethodGet, Source: "js-static", Confidence: ConfidenceLow})
			endpointsAdded++
		}

		assetHost := ""
		if u, err := url.Parse(asset.URL); err == nil {
			assetHost = u.Scheme + "://" + u.Host
		}
		if assetHost != "" && endpointsAdded < maxJSStaticEndpoints && joinProbeBudget > 0 {
			prefixes, bases, querySuffixes := collectJSPathJoinParts(asset.Body)
			prefixes, _ = capStrings(prefixes, maxJSPathPrefixes)
			bases, cutBases := capStrings(bases, maxJSPathBases)
			querySuffixes, _ = capStrings(querySuffixes, maxJSQuerySuffixes)
			joinBasesCut += cutBases
			join := r.verifyJSJoinBases(ctx, agg, assetHost, prefixes, bases, &joinProbeBudget)
			joinUnsettled += join.Unsettled
			joinUninferred += join.Uninferred
			verified := join.Verified
			verifiedBases := make([]string, 0, len(verified))
			for _, pair := range verified {
				verifiedBases = append(verifiedBases, pair.Base)
			}
			suffixesByBase := assignQuerySuffixes(asset.Body, verifiedBases, querySuffixes)
			for _, pair := range verified {
				joinCandidatesVerified++
				pairURL := strings.TrimRight(assetHost, "/") + "/" + pair.joined()
				variants := suffixesByBase[pair.Base]
				if len(variants) == 0 {
					variants = []string{""}
				}
				for _, suffix := range variants {
					if endpointsAdded >= maxJSStaticEndpoints {
						endpointsTruncated = true
						break
					}
					epURL := pairURL + suffix
					if r.scope != nil && !r.scope.Allowed(epURL) {
						agg.addOutOfScope(hostOnly(epURL))
						continue
					}
					agg.addEndpoint(EndpointFact{URL: epURL, Method: http.MethodGet, Source: "js-static-joined", Confidence: ConfidenceLow})
					endpointsAdded++
				}
			}
		}

		for _, s := range extractJSSecrets(asset.URL, asset.Body) {
			if secretsAdded >= maxJSStaticSecrets {
				secretsTruncated = true
				break
			}
			agg.addSecret(s)
			secretsAdded++
		}

		for _, ref := range extractCloudBucketRefs(asset.Body) {
			r.recordCloudBucketRef(agg, ref)
		}
	}

	// Also check URLs already crawled by other Wave 3 passes — a bucket
	// referenced by a plain HTML tag (<img src>) rather than JS never
	// reaches the loop above. Snapshotted first since recordCloudBucketRef
	// can itself append to agg.endpoints (a self-referential match on the
	// js-static-cloud endpoint just added there just re-derives the same
	// already-recorded fact, not a new request, but iterating a live slice
	// while appending to it is needless subtlety to lean on).
	existingURLs := make([]string, len(agg.endpoints))
	for i, ep := range agg.endpoints {
		existingURLs[i] = ep.URL
	}
	for _, epURL := range existingURLs {
		for _, ref := range extractCloudBucketRefs(epURL) {
			r.recordCloudBucketRef(agg, ref)
		}
	}

	if endpointsTruncated {
		agg.addWarning("wave3: js-static: endpoint extraction hit its %d-candidate cap — more may be present in the crawled JS (Phase 8 Step 3)", maxJSStaticEndpoints)
	}
	if secretsTruncated {
		agg.addWarning("wave3: js-static: secret detection hit its %d-hit cap — more may be present in the crawled JS (Phase 8 Step 3)", maxJSStaticSecrets)
	}
	if joinBasesCut > 0 {
		agg.addWarning("wave3: js-static: %d API-route candidate(s) beyond the %d-per-bundle cap were not considered (LT-186)", joinBasesCut, maxJSPathBases)
	}
	if joinUnsettled > 0 {
		agg.addWarning("wave3: js-static: joined path-candidate verification hit its %d-probe run-wide budget — %d API-route candidate(s) were left unverified (LT-186)", maxJSJoinProbes, joinUnsettled)
	}
	if joinUninferred > 0 {
		agg.addWarning("wave3: js-static: %d parameterised API route(s) (\"<name>\" segments) had no live-verified sibling route to borrow a service prefix from and were not emitted (LT-186)", joinUninferred)
	}
	if secretsAdded > 0 {
		agg.addWarning("wave3: js-static: found %d hardcoded secret(s) in served JavaScript (Phase 8 Step 3) — see the ReconResult's \"secrets\" field", secretsAdded)
	}
	if joinCandidatesVerified > 0 {
		agg.addWarning("wave3: js-static: joined and live-verified %d service-prefix+API-path candidate(s) from separately-declared JS constants (LT-164)", joinCandidatesVerified)
	}
}
