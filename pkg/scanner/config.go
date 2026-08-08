package scanner

import (
	"fmt"
	"net/url"
	"time"
)

// recognizedDetectors is the set of --detector values accepted in Phase 1a.
var recognizedDetectors = map[string]bool{
	"idor": true,
}

// Config is passed from the CLI into the Engine.
type Config struct {
	Targets            []string
	TemplatePaths      []string
	Concurrency        int
	RateLimit          int
	ProxyURL           string
	Timeout            time.Duration
	OutputFormat       string // fixed "json" in Phase 1a — no CLI flag selects it yet
	OutputPath         string // from --output/-o; "" = stdout
	Detector           string // "idor" is the only recognized value in Phase 1a
	EndpointTemplate   string // e.g. "/identity/api/v2/user/dashboard/{{id}}" — joined with each target to build the idor.Detector endpointTemplate; stopgap until Phase 1b's template engine can supply this from a YAML file instead of a flag
	Insecure           bool   // maps to httpclient.Config.InsecureSkipVerify; default false
	HostErrorThreshold int    // 0 = use hosterrors.DefaultThreshold

	AuthToken      string // primary/"owner" account token — from --auth-token or HACKERFIVE_AUTH_TOKEN, never hardcoded
	OtherAuthToken string // second, unrelated account token used for IDOR baseline comparison; optional, but required for high-confidence IDOR findings
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
	if c.ProxyURL != "" {
		if _, err := url.Parse(c.ProxyURL); err != nil {
			return fmt.Errorf("validating config: invalid --proxy URL: %w", err)
		}
	}
	return nil
}
