package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// commonPaths are probed directly (via r.client, not katana) to map the
// shape of the app — distinct from misconfig's exposed-path checks, which
// look for bad *exposure* (docs/91-research-recon-phase.md §3, Wave 3).
var commonPaths = []string{
	"/api", "/graphql", "/swagger.json", "/.well-known/openapi.json", "/robots.txt", "/sitemap.xml",
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
	out, err := r.run(waveCtx, strings.Join(seeds, "\n"), "katana",
		"-silent", "-jsonl", "-jc", "-depth", "2", "-rate-limit", itoa(r.rateLimit), "-concurrency", itoa(r.concurrency))
	if err != nil {
		if isBinaryMissing(err) {
			agg.addWarning("wave3: %v — crawl skipped", err)
		} else {
			agg.addWarning("wave3: katana: %v", err)
		}
		return
	}

	seedHosts := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedHosts[hostOnly(s)] = true
	}

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
		method := rec.Request.Method
		if method == "" {
			method = http.MethodGet
		}
		agg.addEndpoint(EndpointFact{URL: rec.Request.Endpoint, Method: method, Source: "katana-crawl", Confidence: ConfidenceMedium})
	}
}

// probeCommonPaths GETs commonPaths against seed via the same rate-limited,
// circuit-broken httpclient.Client every detector uses — this is our own
// direct HTTP traffic, unlike the binary-shelled waves above.
func (r *Recon) probeCommonPaths(ctx context.Context, agg *aggregator, seed string) {
	base := strings.TrimRight(seed, "/")
	host := hostOnly(base)
	if r.hostErrors.ShouldSkip(host) {
		return
	}
	for _, path := range commonPaths {
		reqURL := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			continue
		}
		resp, err := r.client.Do(req)
		if err != nil {
			r.hostErrors.RecordError(host)
			continue
		}
		r.hostErrors.RecordSuccess(host)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			agg.addEndpoint(EndpointFact{URL: reqURL, Method: http.MethodGet, StatusCode: resp.StatusCode, Source: "wave3-common-path-probe", Confidence: ConfidenceHigh})
		}
	}
}

// tagAuthBoundary fetches seed's homepage once and tags an EndpointFact if
// it looks like a login/auth boundary — doesn't attempt to break anything.
func (r *Recon) tagAuthBoundary(ctx context.Context, agg *aggregator, seed string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, seed, nil)
	if err != nil {
		return
	}
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
