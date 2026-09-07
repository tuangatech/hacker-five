package recon

import (
	"fmt"
	"strings"
	"time"
)

// aggregator accumulates facts across every wave into the final
// ReconResult (Wave 4: docs/91-research-recon-phase.md §3). It performs no
// scope check of its own — Wave 1/3 already excluded out-of-scope hosts
// before handing anything here, per the corrected ordering; aggregator only
// collects what earlier waves already decided.
type aggregator struct {
	target      string
	hosts       []HostFact
	endpoints   []EndpointFact
	techStack   []TechFact
	techIndex   map[techKey]int
	techSources map[techKey][]string
	apiSpec     *APISpecFact
	outOfScope  []string
	warnings    []string
	outOfScopeM map[string]bool

	// uniformResponse is set by probeCommonPaths (Wave 3) when a host answers
	// every probe with one generic page — see UniformResponseFact. First
	// writer wins (recon usually has one directly-probed host); a later
	// seed's VerdictNone never clears an earlier wall verdict.
	uniformResponse *UniformResponseFact

	// policy signals from Wave 0 (pkg/preflight's D2 input) — see PolicySignals.
	securityTxt       string
	robotsDisallowAll bool
}

// setUniformResponse records the first uniform-wall verdict seen for a host
// (Phase 7 Step 4 D6). Ignored once one is set, and never overwritten by a
// later, weaker signal.
func (a *aggregator) setUniformResponse(f UniformResponseFact) {
	if a.uniformResponse == nil {
		a.uniformResponse = &f
	}
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
	return &ReconResult{
		Target:          a.target,
		Hosts:           a.hosts,
		Endpoints:       a.endpoints,
		TechStack:       a.techStack,
		APISpec:         a.apiSpec, // presence-only, never parsed — see pkg/recon package doc / doc14 Step 3 Context
		UniformResponse: a.uniformResponse,
		AppSurface:      classifyAppSurface(a.endpoints, a.techStack, a.uniformResponse),
		OutOfScope:      a.outOfScope,
		Policy:          policy,
		Warnings:        a.warnings,
		GeneratedAt:     time.Now().UTC(),
	}
}

// classifyAppSurface synthesises recon's "is there a live app here" verdict
// (LT-68) from facts already collected. Deterministic and conservative: it
// only says "none" when a wall verdict is set or nothing served real
// content at all.
func classifyAppSurface(endpoints []EndpointFact, tech []TechFact, uniform *UniformResponseFact) *AppSurfaceFact {
	if uniform != nil {
		return &AppSurfaceFact{
			Verdict: "none",
			Reason:  fmt.Sprintf("every recon probe hit a %s wall — recon is blind from this vantage", uniform.Kind),
		}
	}
	live2xx, redirects := 0, 0
	for _, ep := range endpoints {
		switch {
		case ep.StatusCode >= 200 && ep.StatusCode < 300:
			live2xx++
		case ep.StatusCode >= 300 && ep.StatusCode < 400:
			redirects++
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
