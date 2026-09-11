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
//
// BodyLen/ContentType/Title (LT-30b, docs/follow-up.md) carry just enough of
// the response shape for a downstream soft-404 / catch-all check to tell a
// real distinct resource from a SPA shell served for every path — populated
// by probeCommonPaths' own direct GET and by httpx (-cl/-ct/-title). Both
// BodyLen == 0 and ContentType == "" mean "recon didn't measure this"
// (a katana-crawl fact, a wave0 fact), not "empty body / no type" — a
// consumer must treat that as unknown and not filter on it.
type EndpointFact struct {
	URL         string `json:"url"`
	Method      string `json:"method"`
	StatusCode  int    `json:"status_code,omitempty"`
	BodyLen     int    `json:"body_len,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	Source      string `json:"source"`
	Confidence  string `json:"confidence"`

	// AuthRequired is set (LT-90, docs/follow-up.md) only on a Source
	// "api-spec" fact: the OpenAPI document declares this route needs
	// authentication (operation-level `security`, else the document
	// default). The decision engine turns a parameterless auth-required
	// spec route into an authbypass "should reject me" candidate. Absent /
	// false on every other fact and on a spec route the doc leaves open.
	AuthRequired bool `json:"auth_required,omitempty"`

	// RedirectChain / FinalURL are populated (LT-64, docs/follow-up.md) only
	// when httpx followed a redirect whose final host differs from the
	// probed host — a cross-host redirect. RedirectChain is one
	// "<status> <url>" string per hop; FinalURL is where the chain landed.
	// StatusCode then stays the *first* hop's status (the 3xx), never the
	// final 2xx, so a consumer sees "this host redirected away" instead of a
	// fabricated 200 for content another host served — the linkpop.com →
	// www.shopify.com case that seeded a whole wrong template class.
	// BodyLen/ContentType/Title/tech are left off such a record for the same
	// reason. An empty pair is the common case (no cross-host redirect).
	RedirectChain []string `json:"redirect_chain,omitempty"`
	FinalURL      string   `json:"final_url,omitempty"`

	// BodyParamKeys is set (LT-96, docs/follow-up.md) only on a Source
	// "api-spec" fact whose documented operation has a `requestBody` JSON
	// schema: the request-body property names the spec declares, names
	// only — no values invented, same principle GET's keyless query-key
	// folding already uses. SuggestSSRFBodyParamsFromRecon matches these
	// against a curated keyword set the same way SuggestSSRFParamsFromRecon
	// does for query params, closing the gap where an attacker-controlled
	// URL is taken in a JSON body field (e.g. crAPI's contact_mechanic)
	// rather than a query string.
	BodyParamKeys []string `json:"body_param_keys,omitempty"`
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

// JSSecretFact is a hardcoded secret found in a served JavaScript bundle
// (Phase 8 Step 3, docs/follow-up.md: LinkFinder/SecretFinder-style static
// analysis over Wave 3's already-fetched .js bodies — no re-fetch). Redacted
// keeps only enough of the match to confirm the finding without ever
// carrying the real secret value in the ReconResult / a JSON export.
type JSSecretFact struct {
	URL      string `json:"url"`      // the JS bundle it was found in
	Line     int    `json:"line"`     // 1-based line number within that bundle
	Kind     string `json:"kind"`     // "aws-access-key" | "google-api-key" | "slack-token" | "github-token" | "private-key" | "hardcoded-bearer-token"
	Severity string `json:"severity"` // mirrors detectors.Finding.Severity's vocabulary
	Redacted string `json:"redacted"` // first/last few characters only — never the full secret
}

// SignupFact records a candidate account-registration endpoint recon found —
// presence and shape only, like APISpecFact: recon never confirms the route
// actually creates an account, just that it looks like one exists.
// pkg/provision (--auto-provision-account) decides what to do with it. Set
// either from an OpenAPI operation whose operationId/summary names it as a
// signup route (specwalk.go's signupOperationHint, higher precision — Method
// is the operation's own documented method) or, when no spec is available, a
// path-guess probe against a curated candidate list (crawl.go's
// signupPathCandidates, lower precision — Method defaults to POST, since a
// real signup route is virtually always POST). First one found wins; a
// spec-derived hint is tried before the path-guess fallback per host, so it
// naturally takes precedence.
type SignupFact struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// CouponFact records a candidate coupon/promo mint-and-apply endpoint pair
// recon found from an OpenAPI spec — LT-135, docs/follow-up.md.
// pkg/detectors/businesslogic is otherwise hardcoded to crAPI's own coupon
// routes and field names (DefaultCouponMintPath/ApplyPath, "coupon_code"/
// "amount"); this fact carries both the real paths and the real request
// field names a spec-documented target actually uses, so the detector can
// fire against a non-crAPI target without an operator hand-supplying four
// flags. CodeField/AmountField are matched by keyword against the mint
// operation's own declared requestBody schema property names (specwalk.go's
// BodyParamKeys machinery, LT-96) — never invented. Spec-derived only,
// deliberately no path-guess fallback (unlike SignupFact): a coupon-mint
// endpoint is POST-only and mutating, so guessing a path and firing a blind
// POST during recon would violate the read-only recon invariant outright,
// not just be lower-confidence.
type CouponFact struct {
	MintURL     string `json:"mint_url"`
	MintMethod  string `json:"mint_method"`
	ApplyURL    string `json:"apply_url"`
	ApplyMethod string `json:"apply_method"`
	CodeField   string `json:"code_field"`
	AmountField string `json:"amount_field"`
}

// APISpecFact records that a machine-readable API spec was found publicly
// reachable — presence only, never parsed; generic spec parsing is still an
// explicit, named scope cut from docs/91-research-recon-phase.md §3's Wave
// 0/3 (see docs/14-implementation-plan-ph5.md Step 3's Context section).
// Set when a common-path probe (probeCommonPaths' specPaths) hits a known
// spec URL, in addition to — not instead of — the usual EndpointFact.
type APISpecFact struct {
	Kind string `json:"kind"` // "openapi" | "graphql-sdl"
	URL  string `json:"url"`
}

// PolicySignals carries the raw, unparsed policy-relevant artifacts Wave 0
// fetches (one GET each) — input to pkg/preflight's D2 pre-flight check
// (doc15 Step 3). Never parsed for meaning here: security.txt has no standard
// "no scanners" field and robots.txt is a crawler convention, so these only
// ever produce a non-blocking warning. The hard block comes from the
// operator's policy.yaml, not from anything in here.
type PolicySignals struct {
	SecurityTxt       string `json:"security_txt,omitempty"`        // body, truncated to a scan-only length
	RobotsDisallowAll bool   `json:"robots_disallow_all,omitempty"` // robots.txt has "User-agent: *" + "Disallow: /"
}

// UniformResponseFact records that one host answers effectively every
// request with one generic page rather than routing — a WAF/bot/auth block
// wall ("waf-block") or a SPA-shell / storage-bucket catch-all ("catchall").
// Set by probeCommonPaths (Wave 3) from the guaranteed-nonexistent canary
// probe plus the host's root response, via pkg/uniformwall.Classify — the
// one primitive Phase 7 Step 4's D6 wires into the decision engine
// (reconShowsAdminSurface stops trusting a blanket 403 as an admin surface,
// LT-58) and the scan engine (skip the per-target template corpus, LT-59).
// BlockedRatio is the fraction of this host's Wave 3 HTTP probes that came
// back intercepted (canary-shaped or 401/403/429) — at ~1.0, recon is
// effectively blind here and plan says so (LT-62). ReconResult.UniformResponses
// holds one of these per walled host (LT-140) — see UniformWallHosts /
// UniformResponseForHost for the common lookups.
type UniformResponseFact struct {
	Host         string  `json:"host"`
	Kind         string  `json:"kind"` // "waf-block" | "catchall"
	CanaryStatus int     `json:"canary_status,omitempty"`
	BlockedRatio float64 `json:"blocked_ratio,omitempty"`
}

// AppSurfaceFact is recon's one-line verdict on whether there is a live
// application here worth planning against, synthesised from signals the
// result already carries (a uniform-wall verdict, how many endpoints
// answered 2xx, whether anything was fingerprinted). Without it a
// decommissioned or fully-walled asset still produced a multi-leaf plan and
// a multi-minute scan with nothing to find (docs/follow-up.md LT-68).
// Verdict is one of:
//   - "none": nothing to scan from this vantage — a WAF/catch-all wall, or
//     no endpoint served real content and no technology was fingerprinted.
//   - "thin": reachable but sparse — a live root and little else.
//   - "full": a real mapped surface (several live endpoints / actionable tech).
type AppSurfaceFact struct {
	Verdict string `json:"verdict"` // "none" | "thin" | "full"
	Reason  string `json:"reason"`
}

// ReconResult is the frozen, versioned output of a Run — see
// docs/schema/recon-result.schema.json. Never raw tool stdout in an agent's
// context (docs/91-research-recon-phase.md §4).
type ReconResult struct {
	Target           string                `json:"target"`
	Hosts            []HostFact            `json:"hosts,omitempty"`
	Endpoints        []EndpointFact        `json:"endpoints,omitempty"`
	TechStack        []TechFact            `json:"tech_stack,omitempty"`
	APISpec          *APISpecFact          `json:"api_spec,omitempty"`
	SignupEndpoint   *SignupFact           `json:"signup_endpoint,omitempty"`
	CouponEndpoint   *CouponFact           `json:"coupon_endpoint,omitempty"`
	Secrets          []JSSecretFact        `json:"secrets,omitempty"`
	UniformResponses []UniformResponseFact `json:"uniform_responses,omitempty"`
	AppSurface       *AppSurfaceFact       `json:"app_surface,omitempty"`
	OutOfScope       []string              `json:"out_of_scope,omitempty"`
	Policy           *PolicySignals        `json:"policy,omitempty"`
	Warnings         []string              `json:"warnings,omitempty"`
	GeneratedAt      time.Time             `json:"generated_at"`
}
