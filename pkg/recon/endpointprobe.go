package recon

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// endpointProbeTimeout bounds each LT-76 probe. The pass is capped at
// maxUnprobedEndpointProbes requests total, issued sequentially.
const endpointProbeTimeout = 10 * time.Second

// maxUnprobedEndpointProbes bounds LT-76's live-status pass so a large
// sitemap can't turn into a flood — the same "hints, not a crawl" ceiling
// LT-39 already puts on sitemap ingestion. 20 covers the auth/payment/OAuth
// surface a real robots/sitemap exposes without approaching a wordlist
// sweep (which stays the separate, opt-in --content-discovery item).
const maxUnprobedEndpointProbes = 20

// unprobedEndpointSources are the EndpointFact.Source values LT-76 will
// probe when they carry no observed status — paths a link-following crawl
// by definition can't reach because nothing links them, but the target
// itself advertises. A katana-crawl fact always already carries the status
// katana saw, so it is deliberately absent here.
var unprobedEndpointSources = map[string]bool{
	"robots-txt":  true,
	"sitemap-xml": true,
}

// interestingPathHints ranks an unprobed path by how likely a live status
// on it seeds a real authbypass / ssrf / redirect leaf (docs/follow-up.md
// LT-76 / LT-77). Earlier entries outrank later ones; a path matching none
// is still eligible but sorts last. Substring match, lower-cased.
var interestingPathHints = []string{
	"/oauth", "/sso", "/saml", "/openid", "/connect/authorize",
	"bounce", "callback", "/logout", "/signout", "/login", "/signin",
	"/pay", "/payment", "/checkout", "/wallet", "/billing",
	"/delete-account", "/account", "/u/", "/profile", "/settings",
	"/admin", "/internal", "/token", "/auth", "/session", "/api/",
}

// pathInterestRank returns a sortable rank for p — lower is more
// interesting. A path matching interestingPathHints[i] ranks i; one
// matching nothing ranks len(interestingPathHints).
func pathInterestRank(p string) int {
	lp := strings.ToLower(p)
	for i, hint := range interestingPathHints {
		if strings.Contains(lp, hint) {
			return i
		}
	}
	return len(interestingPathHints)
}

// probeUnprobedEndpoints issues one bounded, name-ranked GET each against
// the most interesting robots/sitemap paths that have no observed status
// yet, folding the result back onto the existing EndpointFact so
// resolveEndpointFacts treats it like any other observed endpoint (LT-76).
// Reuses recon's own rate-limited, circuit-broken client and the --scope
// gate; a redirect the client follows is recorded as final_url so LT-77's
// bounce/OAuth rule downstream can see the path redirects.
func (r *Recon) probeUnprobedEndpoints(ctx context.Context, agg *aggregator, seeds []string) {
	seedHosts := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedHosts[NormalizeHost(hostOnly(s))] = true
	}

	type candidate struct {
		idx  int
		rank int
	}
	var candidates []candidate
	for i := range agg.endpoints {
		ep := &agg.endpoints[i]
		if ep.StatusCode != 0 || !unprobedEndpointSources[ep.Source] {
			continue
		}
		host := hostOnly(ep.URL)
		if !seedHosts[NormalizeHost(host)] {
			if r.scope == nil || !r.scope.Allowed("https://"+host) {
				continue
			}
		}
		p := endpointPath(ep.URL)
		if p == "" || IsStaticAssetPath(p) || !IsPlausibleURLPath(p) {
			continue
		}
		candidates = append(candidates, candidate{idx: i, rank: pathInterestRank(p)})
	}
	if len(candidates) == 0 {
		return
	}
	sort.SliceStable(candidates, func(a, b int) bool { return candidates[a].rank < candidates[b].rank })
	if len(candidates) > maxUnprobedEndpointProbes {
		candidates = candidates[:maxUnprobedEndpointProbes]
	}

	// A no-redirect client so the first-hop status is what gets recorded —
	// a 302 on /accounts/bounce is the LT-77 signal, and following it to a
	// 200 would erase it. Bounded to maxUnprobedEndpointProbes sequential
	// requests; TLS posture matches recon's own client (ClientConfig).
	probe := &http.Client{
		Timeout: endpointProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // matches recon.ClientConfig / katana / httpx — internal-cert hosts must not fail closed
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer probe.CloseIdleConnections()

	answered, redirected := 0, 0
	for _, c := range candidates {
		ep := &agg.endpoints[c.idx]
		host := hostOnly(ep.URL)
		if r.hostErrors.ShouldSkip(host) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
		if err != nil {
			continue
		}
		r.applyHeaders(req)
		resp, err := probe.Do(req)
		if err != nil {
			if !isRequestTimeout(err) {
				r.hostErrors.RecordError(host)
			}
			continue
		}
		r.hostErrors.RecordSuccess(host)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxCanaryBodyRead))
		_ = resp.Body.Close()
		answered++
		ep.Method = http.MethodGet
		ep.StatusCode = resp.StatusCode
		ep.Confidence = ConfidenceMedium
		if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			redirected++
			ep.FinalURL = resolveLocation(ep.URL, loc)
			ep.RedirectChain = []string{itoa(resp.StatusCode) + " " + ep.URL, ep.FinalURL}
		}
	}
	if answered > 0 {
		agg.addWarning("wave3: probed %d unprobed robots/sitemap endpoint(s) for a live status (LT-76): %d answered, %d redirected", len(candidates), answered, redirected)
	}
}

// resolveLocation resolves a (possibly relative) Location header value
// against the request URL, returning loc unchanged if either can't parse.
func resolveLocation(reqURL, loc string) string {
	base, err := url.Parse(reqURL)
	if err != nil {
		return loc
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return base.ResolveReference(ref).String()
}
