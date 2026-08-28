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

	// AuthHeaderName/AuthHeaderFormat override idor.Detector's default
	// "Authorization: Bearer <token>" scheme — some real targets (e.g. vAPI,
	// see docs/10-implementation-plan-ph1b.md's Future Enhancement #6) use a
	// different header name and/or value shape. "" means "use
	// idor.Detector's own default" for that half. AuthHeaderFormat, if
	// non-empty, must contain the literal placeholder "{token}".
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
