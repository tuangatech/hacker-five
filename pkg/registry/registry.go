// Package registry implements the static, versioned capability registry
// and deterministic decision engine (docs/14-implementation-plan-ph5.md
// Step 3's R8, docs/90-research-hackerbot.md's Decision 6/Group I1/I3):
// Go data, not a model call, the same shape HexStrike AI's own internal
// dispatch code uses (TechnologyDetector/IntelligentDecisionEngine,
// confirmed by reading its source per doc90/doc14).
package registry

import "strings"

// Kind categorizes a Capability by what actually dispatches it.
type Kind string

const (
	KindDetector         Kind = "detector"
	KindReconTool        Kind = "recon-tool"
	KindTemplateCategory Kind = "template-category"
)

// Capability is one dispatchable thing a coordinator could choose to run —
// the registry entry shape doc90's I1 specifies: name, description,
// when_to_use/when_not_to_use, cost/risk, inputs_required.
type Capability struct {
	Name           string
	Kind           Kind
	Description    string
	WhenToUse      string
	WhenNotToUse   string
	Cost           string
	Risk           string
	InputsRequired []string
}

// Capabilities is the static registry — doc01's "Capabilities at a Glance"
// table is this registry's seed data (docs/01-overview-and-strategy.md),
// hand-transcribed here until doc15's tools.search/templates.search make it
// generated/machine-searchable instead.
var Capabilities = []Capability{
	// --- Detectors (pkg/detectors/) ---
	{
		Name:           "idor",
		Kind:           KindDetector,
		Description:    "Two-account baseline comparison across enumerated candidate IDs; falls back to a single-account heuristic (content-signature diff) when only one token is available.",
		WhenToUse:      "The target exposes an endpoint with a numeric/sequential ID parameter and at least one authenticated account token is available.",
		WhenNotToUse:   "No ID-shaped parameter is observable, or the endpoint has no authentication boundary at all (authbypass is the better fit).",
		Cost:           "Read-only; request volume scales with the candidate-ID range enumerated.",
		Risk:           "Read-only — no target state mutation.",
		InputsRequired: []string{"endpoint template with an {{id}} placeholder", "owner auth token", "other-account auth token (baseline mode) or none (heuristic mode)"},
	},
	{
		Name:           "misconfig",
		Kind:           KindDetector,
		Description:    "Fixed exposed-path/keyword/header checks (directory listing, comment leaks, missing security headers, disallowed methods, CORS, verbose errors, default creds) plus the synced nuclei-templates corpus.",
		WhenToUse:      "Any web-facing target — this is the broadest, lowest-risk, first detector to run against something new.",
		WhenNotToUse:   "Not useful once a target is already known to be a pure API with no static-asset/admin-panel surface.",
		Cost:           "Read-only; one fixed set of probe requests per target.",
		Risk:           "Read-only — no target state mutation.",
		InputsRequired: []string{"target URL"},
	},
	{
		Name:           "authbypass",
		Kind:           KindDetector,
		Description:    "Missing authentication, JWT alg:none/signature-stripping, offline JWT weak-secret dictionary check, bounded rate-limit-signal probe, cross-account token reuse, broken-session (logout-then-reuse) detection.",
		WhenToUse:      "The target has a distinct auth boundary (login endpoint, JWT-shaped tokens, protected paths) worth probing directly.",
		WhenNotToUse:   "No authentication mechanism is present at all, or protected-paths candidates aren't known yet (run recon/misconfig first).",
		Cost:           "Read-only except the broken-session check, which fires one real logout request against the owner token.",
		Risk:           "Mostly read-only; the broken-session check ends one real session (bounded, non-destructive, but a genuine state change).",
		InputsRequired: []string{"target URL", "protected-paths candidates", "owner auth token (most checks)"},
	},
	{
		Name:           "promptinjection",
		Kind:           KindDetector,
		Description:    "Template-driven (no Go package) — sends known injection payloads to a chat-shaped endpoint and marker-matches the response for a jailbreak/instruction-override tell.",
		WhenToUse:      "The target exposes an LLM-backed chat/assistant endpoint.",
		WhenNotToUse:   "No LLM-backed surface exists on the target.",
		Cost:           "Read-only; one request per template.",
		Risk:           "Read-only — no target state mutation.",
		InputsRequired: []string{"chat endpoint URL"},
	},
	{
		Name:           "ssrf",
		Kind:           KindDetector,
		Description:    "Non-blind internal-target checks, scheme-based checks (file://, gopher://), and OOB-blind checks via a self-hosted Interactsh-protocol server.",
		WhenToUse:      "The target accepts a URL-shaped parameter (webhook, callback, import-from-URL, PDF/image-fetch-from-URL).",
		WhenNotToUse:   "No URL-accepting parameter is observable, or no self-hosted OOB server is configured and only the non-blind checks are wanted.",
		Cost:           "Read-only; request volume scales with the number of candidate parameters and payload variants.",
		Risk:           "Read-only against the target; the OOB-blind check contacts a self-hosted server the operator controls, never a silent public default.",
		InputsRequired: []string{"target URL", "candidate URL-accepting parameter name(s)", "an --oob-server URL (blind check only)"},
	},
	{
		Name:           "businesslogic",
		Kind:           KindDetector,
		Description:    "Coupon self-mint/reuse/apply and apply-race (concurrent-fire, last-byte-sync) checks — the only detector with mutating checks.",
		WhenToUse:      "A real coupon/discount/credit flow exists on the target and the operator has explicitly opted into mutating checks.",
		WhenNotToUse:   "--allow-writes was not passed — these checks are skipped with a warning, never run silently.",
		Cost:           "Mutating: mints/applies real coupons, fires concurrent requests for the race check.",
		Risk:           "The one detector that changes target state — gated behind the explicit --allow-writes flag, never implied.",
		InputsRequired: []string{"target URL", "--allow-writes", "coupon mint/apply endpoint paths", "owner auth token"},
	},
	// --- Recon tools (pkg/recon/, shelled out via fixed subprocess calls) ---
	{Name: "subfinder", Kind: KindReconTool, Description: "Passive subdomain/DNS enumeration (Wave 1).", WhenToUse: "Any domain-shaped target, before any active probe.", WhenNotToUse: "Target is a bare IP with no domain to enumerate against.", Cost: "Zero-touch against the target — queries third-party passive OSINT sources only.", Risk: "Read-only, no direct target contact.", InputsRequired: []string{"a domain"}},
	{Name: "tlsx", Kind: KindReconTool, Description: "TLS certificate SAN inspection (Wave 1) — a common source of sibling environments a wordlist alone would miss.", WhenToUse: "Target serves TLS.", WhenNotToUse: "Target is plaintext HTTP only.", Cost: "One TLS handshake per host.", Risk: "Read-only.", InputsRequired: []string{"a host:port"}},
	{Name: "dnsx", Kind: KindReconTool, Description: "DNS resolution of Wave 1's scope-filtered host list (Wave 2) — filters \"used to exist\" from \"resolves today.\"", WhenToUse: "Always, before naabu/httpx, once depth escalates past passive.", WhenNotToUse: "Passive-only runs (--recon-depth passive).", Cost: "One DNS query per candidate host.", Risk: "Read-only.", InputsRequired: []string{"a host list"}},
	{Name: "naabu", Kind: KindReconTool, Description: "Port scan of live hosts (Wave 2), top-N common ports by default — the Go-native substitute for nmap this project uses.", WhenToUse: "Once a host is confirmed live.", WhenNotToUse: "Passive-only runs.", Cost: "Bounded by --top-ports; not a full 65535 sweep by default.", Risk: "Active network probing of the target — respects the same rate-limit defaults as every other wave.", InputsRequired: []string{"a live host"}},
	{Name: "httpx", Kind: KindReconTool, Description: "HTTP(S) probe/fingerprint of live host:ports (Wave 2) — status, title, redirect chain, server header, and Wappalyzer-style tech detection; feeds pkg/fingerprint's deterministic tech-signature layer.", WhenToUse: "Once a host is confirmed live.", WhenNotToUse: "Passive-only runs.", Cost: "One or more HTTP requests per host:port.", Risk: "Active HTTP probing of the target.", InputsRequired: []string{"a live host:port"}},
	{Name: "katana", Kind: KindReconTool, Description: "Bounded crawl of discovered web hosts (Wave 3), including JS-bundle endpoint extraction via its own -jc flag.", WhenToUse: "--recon-depth full, once at least one live HTTP host is confirmed.", WhenNotToUse: "passive/active-only runs.", Cost: "Bounded by an explicit depth limit — not an uncontrolled spider.", Risk: "Active crawling of the target, capped by scope + depth.", InputsRequired: []string{"a live URL"}},
	{Name: "interactsh", Kind: KindReconTool, Description: "First-party Interactsh-protocol client (pkg/oob) for OOB callback correlation — shared by ssrf today, later blind XSS/SQLi checks.", WhenToUse: "A blind (no direct response signal) vulnerability check needs proof of an actual outbound request.", WhenNotToUse: "No self-hosted OOB server is configured.", Cost: "One registration + one poll per check run.", Risk: "Contacts only a self-hosted server the operator controls, never a silent public default.", InputsRequired: []string{"a self-hosted Interactsh server URL"}},
	// --- Template categories (YAML, nuclei-compatible + HackerFive-native) ---
	{Name: "native-stateful-templates", Kind: KindTemplateCategory, Description: "IDOR baseline, prompt injection, business logic — request-chaining/stateful checks with no Nuclei equivalent.", WhenToUse: "The vulnerability class inherently needs multi-request state (two accounts, a chat turn, a coupon lifecycle).", WhenNotToUse: "A single stateless request/response check suffices — use a nuclei-compatible template instead.", Cost: "Varies by template.", Risk: "Varies by template — businesslogic's mutating templates are --allow-writes-gated.", InputsRequired: []string{"varies by template"}},
	{Name: "nuclei-misconfig-templates", Kind: KindTemplateCategory, Description: "Misconfiguration, exposed-panels, technology-detection templates, synced from the upstream nuclei-templates corpus.", WhenToUse: "Any web-facing target.", WhenNotToUse: "N/A — broadly applicable.", Cost: "One request per matcher.", Risk: "Read-only (matcher-only, no exploitation).", InputsRequired: []string{"target URL"}},
	{Name: "nuclei-planned-tags", Kind: KindTemplateCategory, Description: "SSTI, XXE, path traversal, open redirect, CVE-tagged templates from the same synced corpus — enabling existing upstream tags via this decision engine, not authoring new templates.", WhenToUse: "A TechFact/tag match indicates one of these classes is plausible for the fingerprinted stack.", WhenNotToUse: "No corroborating tech signal exists yet.", Cost: "One request per matcher.", Risk: "Read-only (matcher-only, no exploitation).", InputsRequired: []string{"target URL", "a matching tag"}},
	{Name: "subdomain-takeover", Kind: KindTemplateCategory, Description: "Native, recon-derived check for a dangling CNAME — a byproduct of Wave 1's passive subdomain enumeration.", WhenToUse: "A discovered subdomain's CNAME points at a deprovisioned third-party service.", WhenNotToUse: "No dangling CNAME pattern observed.", Cost: "One DNS lookup.", Risk: "Read-only.", InputsRequired: []string{"a discovered subdomain"}},
}

// Find returns the Capability with the given Name, if one exists.
func Find(name string) (Capability, bool) {
	for _, c := range Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return Capability{}, false
}

// Search returns every Capability whose Name/Description/WhenToUse/
// WhenNotToUse contains query, case-insensitive substring match — the
// `tools.search` MCP tool's backing lookup (doc15 Step 1, doc90 I1).
// Deliberately a linear scan with no ranking/scoring: Capabilities is a
// small, hand-authored list (~20 entries as of this writing), so a simple
// substring match is instant and needs no more machinery than this.
func Search(query string) []Capability {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var matches []Capability
	for _, c := range Capabilities {
		if strings.Contains(strings.ToLower(c.Name), q) ||
			strings.Contains(strings.ToLower(c.Description), q) ||
			strings.Contains(strings.ToLower(c.WhenToUse), q) ||
			strings.Contains(strings.ToLower(c.WhenNotToUse), q) {
			matches = append(matches, c)
		}
	}
	return matches
}
