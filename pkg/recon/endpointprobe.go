package recon

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	"docs-anchor": true, // LT-189: a documented route's live status says whether it needs auth
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
		if ep.StatusCode != 0 || !unprobedEndpointSources[ep.Source] || strings.Contains(ep.URL, "{") {
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
		// A documented route keeps its documented method (LT-189); only a fact with none
		// is taken to be a GET. The status is the status of this GET either way, which is
		// what says whether an anonymous request is turned away.
		if ep.Method == "" {
			ep.Method = http.MethodGet
		}
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

// maxTemplatedAuthBoundaryProbes bounds LT-191's companion pass to
// probeUnprobedEndpoints above, over the {param}-shaped routes JS-static
// analysis finds (LT-190) but, being a template with no id ever filled in,
// carries no live status at all — probeUnprobedEndpoints itself skips any
// URL containing "{" for exactly that reason.
// recon.SuggestAuthBypassPathsFromRecon needs a directly observed 401/403
// before it will build an authbypass leaf on a route like this
// (docs/follow-up.md's LT-190 follow-up entry), which no bare {param}
// literal can ever carry on its own — nothing has ever requested it.
// Capped the same way LT-76 is.
const maxTemplatedAuthBoundaryProbes = 15

// templatedAuthBoundaryProbeID is substituted for a route's one {...}
// segment before probing — small and inert, never claimed as a real
// object id (idor's own EndpointTemplate/EndpointSeedID stay on the
// original {param} fact this pass leaves untouched, since it appends a
// new fact rather than mutating that one): the probe only needs *a*
// response to the route's auth boundary, not the object at that id, so
// which small value it is doesn't matter.
const templatedAuthBoundaryProbeID = "1"

// singleTrailingParamPath matches a path whose only {...} segment is its
// final one — "/rest/basket/{param}", not "/a/{x}/b/{y}" or "/a/{x}/b" —
// so substituting one concrete value for it is unambiguous.
var singleTrailingParamPath = regexp.MustCompile(`^[^{}]*/\{[A-Za-z_][A-Za-z0-9_]*\}$`)

// substituteTrailingParam replaces rawURL's one trailing "{...}" segment
// (whatever name it carries — "{param}", "{id}") with value, returning ok
// false if rawURL has no "{...}" at all.
func substituteTrailingParam(rawURL, value string) (string, bool) {
	open := strings.LastIndex(rawURL, "{")
	closeIdx := strings.LastIndex(rawURL, "}")
	if open < 0 || closeIdx < open {
		return "", false
	}
	return rawURL[:open] + value + rawURL[closeIdx+1:], true
}

// probeTemplatedRouteAuthBoundary is LT-191's fix: fire one bounded,
// anonymous GET against a concrete substitution of each single-{param}
// JS-static/js-static-joined route recon found but never requested (the
// same route probeUnprobedEndpoints deliberately skips, for the same
// "still a template" reason), and record the result as a *new*
// EndpointFact — the original {param} fact is untouched, so idor's own
// candidate list is unaffected — when the response is 401/403, exactly
// the signal SuggestAuthBypassPathsFromRecon already looks for. Read-only
// and unauthenticated: a synthetic id is either free or belongs to
// someone else, and no ownership check this probe could pass or fail
// either way, since it carries no credential at all.
func (r *Recon) probeTemplatedRouteAuthBoundary(ctx context.Context, agg *aggregator, seeds []string) {
	seedHosts := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedHosts[NormalizeHost(hostOnly(s))] = true
	}

	seen := map[string]bool{}
	var candidates []string
	for _, ep := range agg.endpoints {
		if ep.Source != "js-static" && ep.Source != "js-static-joined" {
			continue
		}
		if !strings.Contains(ep.URL, "{") {
			continue
		}
		p := endpointPath(ep.URL)
		if p == "" || !singleTrailingParamPath.MatchString(p) || IsStaticAssetPath(p) {
			continue
		}
		concrete, ok := substituteTrailingParam(ep.URL, templatedAuthBoundaryProbeID)
		if !ok || !IsPlausibleURLPath(endpointPath(concrete)) || seen[concrete] {
			continue
		}
		host := hostOnly(concrete)
		if !seedHosts[NormalizeHost(host)] {
			if r.scope == nil || !r.scope.Allowed("https://"+host) {
				continue
			}
		}
		seen[concrete] = true
		candidates = append(candidates, concrete)
	}
	if len(candidates) == 0 {
		return
	}
	sort.Strings(candidates)
	if len(candidates) > maxTemplatedAuthBoundaryProbes {
		candidates = candidates[:maxTemplatedAuthBoundaryProbes]
	}

	// Same client shape as probeUnprobedEndpoints — bounded, no-redirect so
	// the first-hop status is what gets recorded, TLS posture matching
	// recon's own client.
	probe := &http.Client{
		Timeout: endpointProbeTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // matches recon.ClientConfig / katana / httpx — internal-cert hosts must not fail closed
			ForceAttemptHTTP2: true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer probe.CloseIdleConnections()

	answered, protected := 0, 0
	for _, concreteURL := range candidates {
		host := hostOnly(concreteURL)
		if r.hostErrors.ShouldSkip(host) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, concreteURL, nil)
		if err != nil {
			continue
		}
		// Deliberately no auth header applied — this pass asks "is the
		// route gated at all", the same anonymous-request shape
		// authbypass.checkMissingAuth itself uses.
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
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			protected++
			agg.addEndpoint(EndpointFact{
				URL: concreteURL, Method: http.MethodGet, StatusCode: resp.StatusCode,
				Source: "js-static-authcheck", Confidence: ConfidenceMedium,
			})
		}
	}
	if answered > 0 {
		agg.addWarning("wave3: probed %d templated route(s) for a live auth boundary (LT-191): %d answered, %d protected", len(candidates), answered, protected)
	}
}
