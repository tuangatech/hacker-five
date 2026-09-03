package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// recognizedDetectors is the set of --detector values accepted.
var recognizedDetectors = map[string]bool{
	"idor":          true,
	"misconfig":     true,
	"authbypass":    true,
	"ssrf":          true,
	"businesslogic": true,
}

// Config is passed from the CLI into the Engine.
type Config struct {
	Targets            []string
	TemplatePaths      []string
	Tags               []string // from --tags; a loaded template fires only if it carries at least one of these (OR match, mirrors upstream Nuclei's -tags). Empty = no filtering
	TemplateID         string   // narrows loaded templates to an exact id: match, unlike Tags (which matches a template's tags: block, never its id:) — pkg/mcpserver's executor uses this for a single-template plan leaf (doc15 Step 2 addendum); "" = no ID filtering
	Concurrency        int
	RateLimit          int
	ProxyURL           string
	Timeout            time.Duration
	OutputFormat       string // from --format: "json" (default), "markdown", "html", or "hackerone-json" — see reporter.ExporterFor
	OutputPath         string // from --output/-o; "" = stdout
	Detector           string // "idor" or "misconfig"
	EndpointTemplate   string // e.g. "/workshop/api/mechanic/mechanic_report?report_id={{id}}" — joined with each target to build the idor.Detector endpointTemplate; stopgap until Phase 1b's template engine can supply this from a YAML file instead of a flag
	Insecure           bool   // maps to httpclient.Config.InsecureSkipVerify; default false
	HostErrorThreshold int    // 0 = use hosterrors.DefaultThreshold

	AuthToken      string // primary/"owner" account token — from --auth-token or HACKERFIVE_AUTH_TOKEN, never hardcoded
	OtherAuthToken string // second, unrelated account token used for IDOR baseline comparison; optional, but required for high-confidence IDOR findings

	// AuthHeaderName/AuthHeaderFormat override idor.Detector's AND
	// authbypass.Detector's default "Authorization: Bearer <token>" scheme —
	// some real targets (e.g. vAPI, see docs/10-implementation-plan-ph1b.md's
	// Future Enhancement #6) use a different header name and/or value shape.
	// Applied to whichever detector --detector actually selects; a single
	// scan run only targets one auth scheme, so sharing these fields (rather
	// than duplicating a second idor-only/authbypass-only pair) matches how
	// the rest of Config already works. "" means "use that detector's own
	// default" for that half. AuthHeaderFormat, if non-empty, must contain
	// the literal placeholder "{token}".
	AuthHeaderName   string
	AuthHeaderFormat string

	// ScopeFile is the path from --scope — a target/host allow-list, checked
	// before each target is dispatched (pkg/scanner/scope). "" means no
	// enforcement: every existing documented lab-target workflow keeps
	// working unmodified without this flag (see
	// docs/11-implementation-plan-ph2.md Step 0's design tradeoff).
	ScopeFile string

	// Scope, if set, is a pre-parsed allow-list checked in preference to
	// ScopeFile — for a caller that already has scope in memory (pkg/mcpserver's
	// MCP tool handlers, doc15 Step 1) rather than a path on the server's own
	// filesystem. loadScope's warn-and-continue-if-neither-is-set behavior
	// (the CLI's existing default for a human-typed command) is unchanged;
	// only a caller that actually sets one of these two fields opts in.
	Scope *scope.Scope

	// ProtectedPaths are candidate endpoint paths (from --protected-paths)
	// the authbypass detector's missing-authentication check fires an
	// unauthenticated request against — required for --detector authbypass,
	// same shape as idor's --endpoint requirement.
	ProtectedPaths []string

	// LoginPaths/LogoutPaths (from --login-paths/--logout-paths, comma-
	// separated) override authbypass.LoginPaths/LogoutPaths' fixed default
	// candidate lists, which live-verified (docs/11-implementation-plan-ph2.md
	// Step 5) match neither crAPI's nor vAPI's real routes. Empty means "use
	// authbypass's own package defaults" for that half.
	LoginPaths  []string
	LogoutPaths []string

	// ExtraHeaders (from repeatable --header "Name: Value" flags) are static
	// HTTP headers applied to every request the Nuclei-compatible and native
	// template engines fire (pkg/template/{nuclei,native}.Executor.
	// WithHeaders) — the only way today to carry a session cookie or other
	// credential a target's login flow issued into a template-driven scan,
	// since neither template format's variable substitution has a
	// CLI-supplied placeholder for one (docs/11-implementation-plan-ph2.md
	// Step 5). Does not affect --detector idor/misconfig/authbypass's own
	// flag-driven requests, only template-fired ones. nil/empty is a no-op.
	ExtraHeaders map[string]string

	// SSRFParams are candidate query parameter names (from repeatable
	// --ssrf-param) the ssrf detector's non-blind and scheme-based checks
	// fire against — required for --detector ssrf, same shape as
	// authbypass's ProtectedPaths requirement. A real target rarely exposes
	// exactly one URL-accepting parameter name ("webhook", "callback",
	// "image_url" are all common), so this is genuinely repeatable
	// (StringArrayVar), not a single comma-separated flag — see
	// docs/13-implementation-plan-ph4.md Step 2.
	SSRFParams []string

	// OOBServers are the base URL(s) of Interactsh-protocol server(s) (from
	// repeatable --oob-server) the ssrf detector's blind callback check
	// polls for interactions, tried in order with automatic fallback. As of
	// 2026-09-02 (docs/discussions.md, user's explicit choice), cmd/
	// hackerfive/scan.go's --oob-server defaults to ssrf.DefaultOOBServers
	// (2 of ProjectDiscovery's public pool) when the flag is omitted
	// entirely — a real, informed leak-tradeoff default now, not the prior
	// "empty unless explicitly opted in" behavior. Empty only when the CLI's
	// --no-oob is passed or the Web UI's OOB servers field is cleared; empty
	// skips the blind check silently, the non-blind/scheme-based checks
	// still run without it. See docs/13-implementation-plan-ph4.md's design
	// tension 1 for the underlying leak-tradeoff reasoning, which is
	// unchanged — only the default acceptance of it changed.
	OOBServers []string

	// AllowWrites (from --allow-writes) gates every mutating check the
	// businesslogic detector's Run performs — coupon self-mint/apply, the
	// concurrent-fire apply race. Absent (the default, false), those checks
	// are skipped with a stderr warning printed once per scan
	// (pkg/scanner/engine.go), not a Validate()-time error — unset is a
	// normal, expected mode (a read-only run against --detector
	// businesslogic simply finds nothing), same treatment as ScopeFile's
	// absence. This is CLAUDE.md's one explicit, opt-in exception to the
	// read/enumerate-only rule, scoped specifically to this flag/detector.
	AllowWrites bool

	// CouponMintPath/CouponApplyPath (from --coupon-mint-path/
	// --coupon-apply-path) override businesslogic.DefaultCouponMintPath/
	// DefaultCouponApplyPath for a target other than crAPI. "" preserves
	// that half's package default.
	CouponMintPath  string
	CouponApplyPath string

	// RaceConcurrency (from --race-concurrency) overrides
	// businesslogic.DefaultRaceConcurrency — how many simultaneous requests
	// the apply-race check's last-byte-sync client fires. 0 preserves the
	// package default.
	RaceConcurrency int

	// IDORPreview (from --idor-preview) fires one extra preflight GET against
	// the resolved --endpoint before idor's real ID-enumeration loop begins,
	// logging its status/body-length — closes the "a wrong EndpointTemplate
	// silently yields zero findings" gap named in
	// docs/14-implementation-plan-ph5.md Step 7. Off by default so an
	// existing scripted/CLI-only invocation sees no behavior change unless
	// it asks for it; pkg/webui's Launch page always sets this true, since a
	// Web UI operator benefits from the honesty check unconditionally.
	IDORPreview bool
}

// ValidateOptions lets a caller defer or waive specific requiredness
// checks — used by pkg/webui's Launch page, which either fills a field from
// the ReconResult a background recon phase produces (EndpointTemplate/
// ProtectedPaths/SSRFParams — doc14 Step 7), or, for SkipAuthTokenRequired,
// permanently allows a detector to start without a token it can never get
// from recon (a credential is never recon-derivable — see the
// credential-fields limit named in doc14 Step 7's Design section).
// SkipAuthTokenRequired is safe specifically for idor/authbypass because
// each has at least one check whose own logic is already meaningful with an
// empty token (idor's heuristic-mode signature comparison; authbypass's
// missing-auth probe and login rate-limit signal) — every other check in
// each detector already early-returns to a no-op internally when the token
// it specifically needs is empty (pkg/detectors/idor, pkg/detectors/
// authbypass), so nothing breaks by letting the whole detector still start.
// businesslogic has no such check (both mint/apply operations are
// inherently "as a logged-in account" and already early-return with an
// empty token) — its AuthToken requirement stays unconditional, deliberately
// with no skip option, since running it without a token would only waste a
// full extra template-corpus pass for zero possible finding.
type ValidateOptions struct {
	SkipEndpointRequired       bool // idor's EndpointTemplate may be blank for now
	SkipProtectedPathsRequired bool // authbypass's ProtectedPaths may be blank for now
	SkipSSRFParamsRequired     bool // ssrf's SSRFParams may be blank for now
	SkipAuthTokenRequired      bool // idor/authbypass may run fully unauthenticated

	// SkipDetectorRequired allows Detector == "" to pass validation — a
	// templates-only run with no built-in detector, dispatching whatever
	// TemplateID/Tags narrows the loaded corpus to instead. Used by
	// pkg/mcpserver's executor for a PlanTree leaf whose Detector is a
	// specific template ID (an R8 template-tag match or an I4
	// use_existing_tag decision naming a template rather than one of the 5
	// built-in detector names) — see doc15 Step 2's addendum. The CLI never
	// sets this; --detector stays required there.
	SkipDetectorRequired bool
}

// Validate rejects configurations that can't produce a meaningful scan.
func (c Config) Validate() error {
	return c.validate(ValidateOptions{})
}

// ValidateWithOptions is Validate with the two recon-fillable requiredness
// checks individually skippable — see ValidateOptions.
func (c Config) ValidateWithOptions(opts ValidateOptions) error {
	return c.validate(opts)
}

func (c Config) validate(opts ValidateOptions) error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("validating config: at least one target is required")
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("validating config: concurrency must be > 0, got %d", c.Concurrency)
	}
	if c.RateLimit <= 0 {
		return fmt.Errorf("validating config: rate limit must be > 0, got %d", c.RateLimit)
	}
	detectorOK := recognizedDetectors[c.Detector] || (c.Detector == "" && opts.SkipDetectorRequired)
	if !detectorOK {
		return fmt.Errorf("validating config: unrecognized detector %q", c.Detector)
	}
	if c.Detector == "idor" && c.AuthToken == "" && c.OtherAuthToken == "" && !opts.SkipAuthTokenRequired {
		return fmt.Errorf("validating config: idor detector requires --auth-token or --other-auth-token (or their env var equivalents)")
	}
	if c.Detector == "idor" && c.EndpointTemplate == "" && !opts.SkipEndpointRequired {
		return fmt.Errorf("validating config: idor detector requires --endpoint")
	}
	if c.Detector == "authbypass" && c.AuthToken == "" && !opts.SkipAuthTokenRequired {
		return fmt.Errorf("validating config: authbypass detector requires --auth-token (or its env var equivalent)")
	}
	if c.Detector == "authbypass" && len(c.ProtectedPaths) == 0 && !opts.SkipProtectedPathsRequired {
		return fmt.Errorf("validating config: authbypass detector requires --protected-paths")
	}
	if c.Detector == "ssrf" && len(c.SSRFParams) == 0 && !opts.SkipSSRFParamsRequired {
		return fmt.Errorf("validating config: ssrf detector requires at least one --ssrf-param")
	}
	if c.Detector == "businesslogic" && c.AuthToken == "" {
		return fmt.Errorf("validating config: businesslogic detector requires --auth-token (or its env var equivalent)")
	}
	if c.AuthHeaderFormat != "" && !strings.Contains(c.AuthHeaderFormat, "{token}") {
		return fmt.Errorf("validating config: --auth-header-format must contain a {token} placeholder, got %q", c.AuthHeaderFormat)
	}
	if c.ProxyURL != "" {
		if _, err := url.Parse(c.ProxyURL); err != nil {
			return fmt.Errorf("validating config: invalid --proxy URL: %w", err)
		}
	}
	return nil
}
