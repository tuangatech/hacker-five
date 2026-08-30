package scanner

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// recognizedDetectors is the set of --detector values accepted.
var recognizedDetectors = map[string]bool{
	"idor":       true,
	"misconfig":  true,
	"authbypass": true,
	"ssrf":       true,
}

// Config is passed from the CLI into the Engine.
type Config struct {
	Targets            []string
	TemplatePaths      []string
	Tags               []string // from --tags; a loaded template fires only if it carries at least one of these (OR match, mirrors upstream Nuclei's -tags). Empty = no filtering
	Concurrency        int
	RateLimit          int
	ProxyURL           string
	Timeout            time.Duration
	OutputFormat       string // fixed "json" in Phase 1a — no CLI flag selects it yet
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

	// OOBServer is the base URL of a self-hosted, user-run
	// Interactsh-protocol server (from --oob-server) the ssrf detector's
	// blind callback check polls for interactions. "" (the default) skips
	// that check silently — the non-blind/scheme-based checks still run
	// without it. Deliberately never a public default server, per
	// docs/13-implementation-plan-ph4.md's design tension 1 (avoiding
	// target-request-data leakage to a third party outside the engagement's
	// authorized scope).
	OOBServer string
}

// Validate rejects configurations that can't produce a meaningful scan.
func (c Config) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("validating config: at least one target is required")
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("validating config: concurrency must be > 0, got %d", c.Concurrency)
	}
	if c.RateLimit <= 0 {
		return fmt.Errorf("validating config: rate limit must be > 0, got %d", c.RateLimit)
	}
	if !recognizedDetectors[c.Detector] {
		return fmt.Errorf("validating config: unrecognized detector %q", c.Detector)
	}
	if c.Detector == "idor" && c.AuthToken == "" && c.OtherAuthToken == "" {
		return fmt.Errorf("validating config: idor detector requires --auth-token or --other-auth-token (or their env var equivalents)")
	}
	if c.Detector == "idor" && c.EndpointTemplate == "" {
		return fmt.Errorf("validating config: idor detector requires --endpoint")
	}
	if c.Detector == "authbypass" && c.AuthToken == "" {
		return fmt.Errorf("validating config: authbypass detector requires --auth-token (or its env var equivalent)")
	}
	if c.Detector == "authbypass" && len(c.ProtectedPaths) == 0 {
		return fmt.Errorf("validating config: authbypass detector requires --protected-paths")
	}
	if c.Detector == "ssrf" && len(c.SSRFParams) == 0 {
		return fmt.Errorf("validating config: ssrf detector requires at least one --ssrf-param")
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
