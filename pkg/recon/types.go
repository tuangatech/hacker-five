// Package recon implements HackerFive's recon phase
// (docs/91-research-recon-phase.md, docs/14-implementation-plan-ph5.md Step
// 3's R1): a fixed set of waves, escalating from zero-touch to a bounded
// crawl, that turn a bare target into a structured ReconResult a future
// coordinator can reason over — never raw tool stdout. Every external
// ProjectDiscovery binary this package shells out to is invoked with fixed,
// non-agent-controlled arguments, the same scoped-subprocess precedent
// pkg/templatesync already sets for git — this is not a door back into
// "run arbitrary command" (doc90 Decision 2).
package recon

import "time"

// Depth controls how far Run escalates. Passive-first is the default, not a
// suggestion (docs/91-research-recon-phase.md §5): an operator can cap a run
// at DepthPassive for zero-footprint reconnaissance before deciding whether
// to go further.
type Depth string

const (
	// DepthPassive runs only Wave 0-1: zero-touch plus passive
	// subdomain/TLS/WHOIS enumeration. No packet reaches the target itself.
	DepthPassive Depth = "passive"
	// DepthActive adds Wave 2: DNS resolution, port scan, HTTP probing —
	// the standard first live-touch step.
	DepthActive Depth = "active"
	// DepthFull adds Wave 3: bounded crawl and common-path probing.
	DepthFull Depth = "full"
)

// Confidence values mirror pkg/agenttask.Confidence's string values (High/
// Medium/Low), not Finding.Confidence — doc91 §5 already corrected this
// exact conflation once (an earlier draft's HostFact.Confidence comment
// claimed to mirror Finding.Confidence, a distinct two-value field a
// detector sets after a Finding already exists).
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
)

// PortFact is one open port observed on a HostFact.
type PortFact struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "tcp" | "udp"
	Service  string `json:"service,omitempty"`
	Source   string `json:"source"`
}

// HostFact is one host recon discovered or was given, with every open port
// found on it. Notes carries free-form, human-readable facts that don't
// warrant their own typed field yet (WHOIS registrar/org text, an ASN
// summary line) — kept on the host they describe rather than invented a
// separate WHOIS/ASN fact type for this pass.
type HostFact struct {
	Host       string     `json:"host"`
	Ports      []PortFact `json:"ports,omitempty"`
	Notes      []string   `json:"notes,omitempty"`
	Source     string     `json:"source"`     // "passive-subdomain" | "dns-resolve" | "user-supplied" | ...
	Confidence string     `json:"confidence"` // ConfidenceHigh | ConfidenceMedium | ConfidenceLow
}

// EndpointFact is one URL recon observed to exist (crawled, probed, or
// derived from a discovered host).
type EndpointFact struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code,omitempty"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

// TechFact is one technology/framework signal observed on the target.
// Populated from httpx's own -tech-detect output (Source:
// "httpx-tech-detect") and from pkg/fingerprint's deterministic
// header/body/favicon/port signature matching, layered on top of the same
// signals rather than replacing them (Step 3's R7). Host is a correction
// found implementing R8 (Step 3b): the decision engine needs to know which
// host produced a given tech signal to set a PlanTree leaf's Target — an
// omission in this type's original Step 3a shape, fixed here before an
// external client (Phase 6) could ever depend on it missing.
type TechFact struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

// APISpecFact reserves the shape for a parsed OpenAPI/GraphQL SDL spec.
// Always nil in this pass — generic spec parsing is an explicit, named
// scope cut from docs/91-research-recon-phase.md §3's Wave 0/3 (see
// docs/14-implementation-plan-ph5.md Step 3's Context section); Wave 3 only
// detects a spec's presence as an EndpointFact, it doesn't parse one.
type APISpecFact struct {
	Kind string `json:"kind"` // "openapi" | "graphql-sdl"
	URL  string `json:"url"`
}

// ReconResult is the frozen, versioned output of a Run — see
// docs/schema/recon-result.schema.json. Never raw tool stdout in an agent's
// context (docs/91-research-recon-phase.md §4).
type ReconResult struct {
	Target      string         `json:"target"`
	Hosts       []HostFact     `json:"hosts,omitempty"`
	Endpoints   []EndpointFact `json:"endpoints,omitempty"`
	TechStack   []TechFact     `json:"tech_stack,omitempty"`
	APISpec     *APISpecFact   `json:"api_spec,omitempty"`
	OutOfScope  []string       `json:"out_of_scope,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
	GeneratedAt time.Time      `json:"generated_at"`
}
