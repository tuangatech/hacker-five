package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tuangatech/hacker-five/pkg/scanner"
)

func validConfig() scanner.Config {
	return scanner.Config{
		Targets:     []string{"http://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "misconfig",
	}
}

func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(c scanner.Config) scanner.Config
		wantErr string
	}{
		{
			name:   "valid misconfig config",
			mutate: func(c scanner.Config) scanner.Config { return c },
		},
		{
			name:    "no targets",
			mutate:  func(c scanner.Config) scanner.Config { c.Targets = nil; return c },
			wantErr: "at least one target is required",
		},
		{
			name:    "zero concurrency",
			mutate:  func(c scanner.Config) scanner.Config { c.Concurrency = 0; return c },
			wantErr: "concurrency must be > 0",
		},
		{
			name:    "negative rate limit",
			mutate:  func(c scanner.Config) scanner.Config { c.RateLimit = -1; return c },
			wantErr: "rate limit must be > 0",
		},
		{
			name:    "unrecognized detector",
			mutate:  func(c scanner.Config) scanner.Config { c.Detector = "nope"; return c },
			wantErr: `unrecognized detector "nope"`,
		},
		{
			name:    "empty detector without SkipDetectorRequired",
			mutate:  func(c scanner.Config) scanner.Config { c.Detector = ""; return c },
			wantErr: `unrecognized detector ""`,
		},
		{
			name: "idor without any token",
			mutate: func(c scanner.Config) scanner.Config {
				c.Detector = "idor"
				c.EndpointTemplate = "/api/users/{{id}}"
				return c
			},
			wantErr: "idor detector requires --auth-token or --other-auth-token",
		},
		{
			name: "idor without endpoint",
			mutate: func(c scanner.Config) scanner.Config {
				c.Detector = "idor"
				c.AuthToken = "tok"
				return c
			},
			wantErr: "idor detector requires --endpoint",
		},
		{
			name: "idor with token and endpoint is valid",
			mutate: func(c scanner.Config) scanner.Config {
				c.Detector = "idor"
				c.AuthToken = "tok"
				c.EndpointTemplate = "/api/users/{{id}}"
				return c
			},
		},
		{
			name:    "invalid proxy URL",
			mutate:  func(c scanner.Config) scanner.Config { c.ProxyURL = "://not-a-url"; return c },
			wantErr: "invalid --proxy URL",
		},
		{
			name:    "auth header format missing token placeholder",
			mutate:  func(c scanner.Config) scanner.Config { c.AuthHeaderFormat = "Token xyz"; return c },
			wantErr: "--auth-header-format must contain a {token} placeholder",
		},
		{
			name: "auth header format with placeholder is valid",
			mutate: func(c scanner.Config) scanner.Config {
				c.AuthHeaderName = "Authorization-Token"
				c.AuthHeaderFormat = "{token}"
				return c
			},
		},
		{
			name:    "authbypass without auth token",
			mutate:  func(c scanner.Config) scanner.Config { c.Detector = "authbypass"; c.ProtectedPaths = []string{"/admin"}; return c },
			wantErr: "authbypass detector requires --auth-token",
		},
		{
			name:    "authbypass without protected paths",
			mutate:  func(c scanner.Config) scanner.Config { c.Detector = "authbypass"; c.AuthToken = "tok"; return c },
			wantErr: "authbypass detector requires --protected-paths",
		},
		{
			name: "authbypass with token and protected paths is valid",
			mutate: func(c scanner.Config) scanner.Config {
				c.Detector = "authbypass"
				c.AuthToken = "tok"
				c.ProtectedPaths = []string{"/admin"}
				return c
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.mutate(validConfig())
			err := cfg.Validate()
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestConfigValidateWithOptions_SkipDetectorRequired confirms the escape
// hatch used by pkg/mcpserver's executor for a specific-template PlanTree
// leaf (doc15 Step 2 addendum): Detector == "" only ever passes with this
// option explicitly set — Validate() (no options) keeps rejecting it, per
// the table above, so a CLI-driven config (which never sets this) is
// unaffected.
func TestConfigValidateWithOptions_SkipDetectorRequired(t *testing.T) {
	cfg := validConfig()
	cfg.Detector = ""
	cfg.TemplateID = "some-template-id"

	err := cfg.ValidateWithOptions(scanner.ValidateOptions{SkipDetectorRequired: true})
	assert.NoError(t, err)

	err = cfg.ValidateWithOptions(scanner.ValidateOptions{})
	assert.ErrorContains(t, err, `unrecognized detector ""`)
}
