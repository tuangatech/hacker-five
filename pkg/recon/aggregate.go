package recon

import (
	"fmt"
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

func (a *aggregator) addTech(t TechFact) {
	a.techStack = append(a.techStack, t)
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
		APISpec:     nil, // spec parsing deferred — see pkg/recon package doc / doc14 Step 3 Context
		OutOfScope:  a.outOfScope,
		Warnings:    a.warnings,
		GeneratedAt: time.Now().UTC(),
	}
}
