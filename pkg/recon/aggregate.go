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
	key := techKey{strings.ToLower(t.Name), t.Host}
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
	return &ReconResult{
		Target:      a.target,
		Hosts:       a.hosts,
		Endpoints:   a.endpoints,
		TechStack:   a.techStack,
		APISpec:     a.apiSpec, // presence-only, never parsed — see pkg/recon package doc / doc14 Step 3 Context
		OutOfScope:  a.outOfScope,
		Warnings:    a.warnings,
		GeneratedAt: time.Now().UTC(),
	}
}
