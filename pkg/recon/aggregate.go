package recon

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// aggregator accumulates facts across every wave into the final
// ReconResult (Wave 4: docs/91-research-recon-phase.md §3). It performs no
// scope check of its own — Wave 1/3 already excluded out-of-scope hosts
// before handing anything here, per the corrected ordering; aggregator only
// collects what earlier waves already decided.
type aggregator struct {
	target         string
	hosts          []HostFact
	endpoints      []EndpointFact
	techStack      []TechFact
	techIndex      map[techKey]int
	techSources    map[techKey][]string
	apiSpec        *APISpecFact
	signupEndpoint *SignupFact
	couponEndpoint *CouponFact
	secrets        []JSSecretFact
	outOfScope     []string
	warnings       []string
	outOfScopeM    map[string]bool

	// uniformResponses is set by probeCommonPaths (Wave 3) when a host
	// answers every probe with one generic page — see UniformResponseFact.
	// Keyed by NormalizeHost(Host), same convention as cdnEdgeHosts/addTech's
	// techIndex below (LT-14) — a www./differently-cased probe of the same
	// host collapses into the same entry rather than producing a spurious
	// second one. Per host, first writer wins (a later, weaker signal for
	// that same host never clears an earlier wall verdict). LT-140: widened
	// from a single first-host-wins fact to one verdict per host, so D6's
	// corpus-skip (LT-59) protects every walled host in a multi-host recon
	// run, not just the first one probed.
	uniformResponses map[string]UniformResponseFact

	// policy signals from Wave 0 (pkg/preflight's D2 input) — see PolicySignals.
	securityTxt       string
	robotsDisallowAll bool

	// cdnEdgeHosts maps a NormalizeHost'd hostname to the CDN/edge network its
	// ASN belongs to (LT-61) — set by Wave 1's ASN lookup, read by runNaabu to
	// skip a port scan that would only ever reach the CDN's POPs.
	cdnEdgeHosts map[string]string
}

// markCDNEdge records that host resolves into cdn's edge network (LT-61).
func (a *aggregator) markCDNEdge(host, cdn string) {
	if a.cdnEdgeHosts == nil {
		a.cdnEdgeHosts = make(map[string]string)
	}
	a.cdnEdgeHosts[NormalizeHost(host)] = cdn
}

// cdnEdgeFor returns the CDN name markCDNEdge recorded for host, if any.
func (a *aggregator) cdnEdgeFor(host string) (string, bool) {
	cdn, ok := a.cdnEdgeHosts[NormalizeHost(host)]
	return cdn, ok
}

// setUniformResponse records the first uniform-wall verdict seen for f's
// host (Phase 7 Step 4 D6; widened per-host by LT-140). Ignored once that
// host already has a verdict, and never overwritten by a later, weaker
// signal for the same host — a different host gets its own independent
// entry.
func (a *aggregator) setUniformResponse(f UniformResponseFact) {
	key := NormalizeHost(f.Host)
	if _, exists := a.uniformResponses[key]; exists {
		return
	}
	if a.uniformResponses == nil {
		a.uniformResponses = make(map[string]UniformResponseFact)
	}
	a.uniformResponses[key] = f
}

func (a *aggregator) addHost(h HostFact) {
	a.hosts = append(a.hosts, h)
}

func (a *aggregator) addEndpoint(e EndpointFact) {
	a.endpoints = append(a.endpoints, e)
}

// techKey identifies "the same observed technology" across independent
// detection passes — see addTech.
type techKey struct{ name, host string }

// addTech merges a new TechFact into an existing one sharing the same
// (Name, Host) rather than always appending — found live, 2026-09-01:
// httpx's own tech-detect (runHTTPX) and pkg/fingerprint's header/body/
// port/favicon signature matching (runWave2) both independently detect the
// same technology on the same host (e.g. "Cloudflare" via both) and were
// each appended unconditionally, producing two rows identical in Name and
// Host and differing only in Source/Confidence — indistinguishable from a
// raw duplicate to anyone reading the Tech Stack table, unlike addAPISpec/
// addOutOfScope below, which already dedup. A second, independent signal
// agreeing is real, useful corroboration (worth keeping, per this
// function's own prior "enrich, don't replace" comment on the caller side)
// — so it's merged into the existing fact's Source (comma-joined, each
// source listed once) and promotes Confidence to whichever pass reported
// it higher, rather than turned into a second row.
//
// Name is folded to lowercase for the dedup key only (the displayed row
// keeps whichever casing was observed first) — found live, 2026-09-04: a
// real target's Tech Stack showed both "LiteSpeed Cache" and "Litespeed
// Cache" as two distinct rows, httpx's own embedded Wappalyzer-style
// catalog apparently carrying both castings as separate fingerprint
// entries for the same real plugin. Case is never a meaningful
// distinction between two TechFacts the way Name/Host genuinely are, so
// treating it as one is the same kind of spurious-duplicate this
// function's own (Name, Host) merge already exists to close.
func (a *aggregator) addTech(t TechFact) {
	key := techKey{strings.ToLower(t.Name), NormalizeHost(t.Host)}
	if idx, ok := a.techIndex[key]; ok {
		existing := &a.techStack[idx]
		if !contains(a.techSources[key], t.Source) {
			a.techSources[key] = append(a.techSources[key], t.Source)
			existing.Source = strings.Join(a.techSources[key], ", ")
		}
		if confidenceRank(t.Confidence) > confidenceRank(existing.Confidence) {
			existing.Confidence = t.Confidence
		}
		return
	}
	if a.techIndex == nil {
		a.techIndex = make(map[techKey]int)
		a.techSources = make(map[techKey][]string)
	}
	a.techIndex[key] = len(a.techStack)
	a.techSources[key] = []string{t.Source}
	a.techStack = append(a.techStack, t)
}

// NormalizeHost folds a host into the form addTech's dedup key uses —
// found live, 2026-09-04 (LT-14, docs/follow-up.md): a real target's Tech
// Stack showed the same technology three times over, once each for
// "www.example.com", "Example.com" and "example.com" — httpx probes a
// target's bare/www./as-typed host variants independently (see
// recon.go/active.go's host-candidate generation), and each variant
// produces its own TechFact with a differently-cased or www.-prefixed
// Host, none of which collided with addTech's existing (lowercased-Name,
// raw-Host) key. Lowercasing here is the same normalization Name already
// gets; stripping one leading "www." reflects that a bug-bounty target's
// www.-prefixed host is conventionally the same site as its bare
// counterpart (both commonly resolve to the same origin/CDN edge), not a
// distinct one the way a genuine subdomain (a.example.com vs
// b.example.com, still kept distinct — see TestAddTech_DifferentHost_
// StaysDistinct) is. Exported so pkg/webui's collapseEndpoints (recon_view.go)
// can apply the identical normalization to its own display-table dedup key,
// which has the same latent gap.
func NormalizeHost(host string) string {
	return strings.TrimPrefix(strings.ToLower(host), "www.")
}

func confidenceRank(c string) int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// addAPISpec records spec's presence — first one wins, matching
// probeCommonPaths' own check order (docs/14-implementation-plan-ph5.md
// Step 7's UI-polish pass: an exposed OpenAPI/Swagger doc is a higher-value
// finding than a generic discovered endpoint, worth its own field instead of
// staying buried as just another EndpointFact row).
func (a *aggregator) addAPISpec(spec APISpecFact) {
	if a.apiSpec != nil {
		return
	}
	a.apiSpec = &spec
}

// setSignupEndpoint records the first signup/registration candidate found —
// a spec-derived hint (walkOpenAPISpec) and a path-guess probe
// (probeSignupCandidates) can both call this; first writer wins, and a
// spec-derived hint is always tried first per seed (higher precision than a
// path guess) so it naturally wins the race.
func (a *aggregator) setSignupEndpoint(f SignupFact) {
	if a.signupEndpoint == nil {
		a.signupEndpoint = &f
	}
}

// setCouponEndpoint records the first spec-derived coupon mint+apply
// candidate found (LT-135, docs/follow-up.md) — spec-only, no path-guess
// fallback (see CouponFact's doc comment for why), so first writer wins
// across every seed's spec walk.
func (a *aggregator) setCouponEndpoint(f CouponFact) {
	if a.couponEndpoint == nil {
		a.couponEndpoint = &f
	}
}

// addSecret records a JS-static-analysis secret hit (Phase 8 Step 3),
// capped at maxJSStaticSecrets total across a run — jsstatic.go enforces the
// cap so a truncation warning can name how many were dropped.
func (a *aggregator) addSecret(s JSSecretFact) {
	a.secrets = append(a.secrets, s)
}

func (a *aggregator) addOutOfScope(host string) {
	if a.outOfScopeM == nil {
		a.outOfScopeM = make(map[string]bool)
	}
	if a.outOfScopeM[host] {
		return
	}
	a.outOfScopeM[host] = true
	a.outOfScope = append(a.outOfScope, host)
}

func (a *aggregator) addWarning(format string, args ...any) {
	a.warnings = append(a.warnings, fmt.Sprintf(format, args...))
}

func (a *aggregator) finalize() *ReconResult {
	var policy *PolicySignals
	if a.securityTxt != "" || a.robotsDisallowAll {
		policy = &PolicySignals{SecurityTxt: a.securityTxt, RobotsDisallowAll: a.robotsDisallowAll}
	}
	// LT-140: uniformResponses is keyed by NormalizeHost for dedup, but the
	// output is a plain slice — sorted by that same key so the result is
	// deterministic (repeat runs / test fixtures don't depend on Go's
	// unordered map iteration).
	var uniform []UniformResponseFact
	if len(a.uniformResponses) > 0 {
		keys := make([]string, 0, len(a.uniformResponses))
		for k := range a.uniformResponses {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		uniform = make([]UniformResponseFact, 0, len(keys))
		for _, k := range keys {
			uniform = append(uniform, a.uniformResponses[k])
		}
	}
	return &ReconResult{
		Target:           a.target,
		Hosts:            a.hosts,
		Endpoints:        a.endpoints,
		TechStack:        a.techStack,
		APISpec:          a.apiSpec, // presence-only, never parsed — see pkg/recon package doc / doc14 Step 3 Context
		SignupEndpoint:   a.signupEndpoint,
		CouponEndpoint:   a.couponEndpoint,
		Secrets:          a.secrets,
		UniformResponses: uniform,
		AppSurface:       classifyAppSurface(a.endpoints, a.techStack, a.uniformResponses),
		OutOfScope:       a.outOfScope,
		Policy:           policy,
		Warnings:         a.warnings,
		GeneratedAt:      time.Now().UTC(),
	}
}

// classifyAppSurface synthesises recon's "is there a live app here" verdict
// (LT-68) from facts already collected. Deterministic and conservative: it
// only says "none" when a wall verdict is set or nothing served real
// content at all.
//
// LT-102: a UniformResponseFact is host-scoped (it names one host). On a
// multi-host recon result it must not, by itself, condemn the whole result
// to "none" — the four prior live rounds were all single walled hosts, but
// against a real estate of 20+ subdomains one WAF/catch-all host is normal
// while other hosts serve real applications. So the wall verdict is only
// honoured as "recon is blind" when no *other* host mapped a real
// application surface; otherwise the result is classified on the same
// live-endpoint scale as a wall-free run, with the wall noted in the reason.
//
// LT-140: uniform is now keyed by NormalizeHost(Host) and can carry more
// than one walled host — "blind" now means every host that mapped a real
// application surface is itself one of the walled hosts (not just a single
// named one), so a second/third wall in the same multi-host run is judged
// the same way a single one always was.
func classifyAppSurface(endpoints []EndpointFact, tech []TechFact, uniform map[string]UniformResponseFact) *AppSurfaceFact {
	live2xx, redirects := 0, 0
	realAppHosts := map[string]bool{}
	for _, ep := range endpoints {
		switch {
		case ep.StatusCode >= 200 && ep.StatusCode < 300:
			live2xx++
			if endpointShowsRealApp(ep) {
				if h := endpointHostNorm(ep.URL); h != "" {
					realAppHosts[h] = true
				}
			}
		case ep.StatusCode >= 300 && ep.StatusCode < 400:
			redirects++
		}
	}

	if len(uniform) > 0 {
		blind := true
		for h := range realAppHosts {
			if _, walled := uniform[h]; !walled {
				blind = false
				break
			}
		}
		wallHosts := make([]string, 0, len(uniform))
		var soleKind string
		for _, u := range uniform {
			wallHosts = append(wallHosts, u.Host)
			soleKind = u.Kind
		}
		sort.Strings(wallHosts)
		if blind {
			kind := soleKind
			if len(uniform) > 1 {
				kind = "uniform-response"
			}
			return &AppSurfaceFact{
				Verdict: "none",
				Reason:  fmt.Sprintf("every recon probe hit a %s wall — recon is blind from this vantage", kind),
			}
		}
		verdict := "thin"
		if len(realAppHosts) > 3 {
			verdict = "full"
		}
		wallDesc := fmt.Sprintf("a %s wall on %s", soleKind, wallHosts[0])
		if len(uniform) > 1 {
			wallDesc = fmt.Sprintf("a uniform-response wall on %d host(s) (%s)", len(uniform), strings.Join(wallHosts, ", "))
		}
		return &AppSurfaceFact{
			Verdict: verdict,
			Reason: fmt.Sprintf("%d host(s) mapped a real application surface (%s notwithstanding)",
				len(realAppHosts), wallDesc),
		}
	}

	switch {
	case live2xx == 0 && len(tech) == 0:
		reason := "no endpoint served a 2xx response and no technology was fingerprinted"
		if redirects > 0 {
			reason = "every reachable endpoint only redirected away and no technology was fingerprinted"
		}
		return &AppSurfaceFact{Verdict: "none", Reason: reason}
	case live2xx == 0:
		return &AppSurfaceFact{Verdict: "thin", Reason: "no endpoint served a 2xx response; only passive / fingerprint signal"}
	case live2xx <= 3:
		return &AppSurfaceFact{Verdict: "thin", Reason: fmt.Sprintf("%d endpoint(s) served real content", live2xx)}
	default:
		return &AppSurfaceFact{Verdict: "full", Reason: fmt.Sprintf("%d endpoint(s) served real content", live2xx)}
	}
}

// endpointShowsRealApp reports whether a 2xx EndpointFact is evidence its
// host runs an actual application — not a default server page, a
// challenge/error page, or a bare asset. Used only by classifyAppSurface's
// LT-102 multi-host guard, so it errs toward "yes": a crawled non-asset
// route, or any non-generic page title, is enough.
func endpointShowsRealApp(ep EndpointFact) bool {
	if ep.StatusCode < 200 || ep.StatusCode >= 300 {
		return false
	}
	if p := endpointPathOf(ep.URL); p != "" && p != "/" && !IsStaticAssetPath(p) {
		return true
	}
	t := strings.TrimSpace(ep.Title)
	return t != "" && !isGenericPageTitle(t)
}

// isGenericPageTitle matches the small set of page titles that mean "reachable
// but not an application" — a stock web-server landing page or a
// WAF/auth/error interstitial. Substring, case-insensitive.
func isGenericPageTitle(title string) bool {
	lt := strings.ToLower(title)
	for _, s := range []string{
		"401 authorization required", "403 forbidden", "404 not found",
		"400 bad request", "access denied", "attention required",
		"just a moment", "welcome to nginx", "apache http server test page",
		"apache2 ubuntu default page", "test page for the", "it works!",
		"site not found", "default web site page",
	} {
		if strings.Contains(lt, s) {
			return true
		}
	}
	return false
}

// endpointHostNorm is NormalizeHost of a URL's hostname ("" if unparseable).
func endpointHostNorm(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return NormalizeHost(u.Hostname())
}

// endpointPathOf returns a URL's path ("" if unparseable).
func endpointPathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}
