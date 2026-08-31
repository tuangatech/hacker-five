// Package eval implements Phase 5 Step 1's "G1" eval harness stub
// (docs/14-implementation-plan-ph5.md): a fixed challenge set, run against
// the real hackerfive scan CLI, with a binary pass/fail per challenge. It
// answers a different question than scripts/measure-fp-rate.sh (which asks
// "did we introduce a new false positive?") — G1 asks "for each known real
// vulnerability in a lab target, did today's CLI actually find it?" — while
// reading the exact same fixtures, not a parallel manifest.
package eval

import (
	"os"
	"sync"
)

// templatesDir mirrors measure-fp-rate.sh's own TEMPLATES_DIR selection.
func templatesDir() string {
	if info, err := os.Stat(".nuclei-templates-cache"); err == nil && info.IsDir() {
		return ".nuclei-templates-cache"
	}
	return "./templates/"
}

var (
	emptyTemplatesOnce sync.Once
	emptyTemplatesPath string
)

// emptyTemplatesDir returns a lazily-created, empty directory — used to
// isolate the authbypass detector's own timing from the nuclei-template
// layer. Live-verified 2026-08-30 (docs/20-setup-testing-targets-macos.md's
// vAPI section): without a --templates override, vAPI's generic 500
// catch-all makes authbypass's rate-limit-signal check + the shared retry
// middleware stall for minutes — real, target-specific behavior, not a bug
// this harness works around by hiding it, just isolates it from an
// unrelated slow layer so the run finishes within this harness's timeout.
func emptyTemplatesDir() string {
	emptyTemplatesOnce.Do(func() {
		dir, err := os.MkdirTemp("", "hackerfive-eval-empty-templates-*")
		if err != nil {
			panic(err)
		}
		emptyTemplatesPath = dir
	})
	return emptyTemplatesPath
}

// Scenario is one measure() call from scripts/measure-fp-rate.sh, re-expressed
// so this harness can invoke the same CLI command and grade the result
// against the same tests/fixtures/expected-findings/*.json fixture.
type Scenario struct {
	Name         string
	ExpectedFile string
	RequiredEnv  []string // scenario is skipped, not failed, if any is unset
	Args         func() []string
	// SkipPrefixes lists expected_id_prefixes entries this Scenario's own
	// Args deliberately can't produce (e.g. an empty --templates override
	// applied for a reason unrelated to the fixture) — graded as skipped,
	// not failed. Each entry used here must be explained in a comment on
	// the Scenario itself; this is not a general-purpose escape hatch.
	SkipPrefixes []string
}

// Scenarios mirrors scripts/measure-fp-rate.sh's six measure() calls
// 1:1 — keep both in sync if either changes.
var Scenarios = []Scenario{
	{
		// scripts/measure-fp-rate.sh: "crAPI" measure() call.
		Name:         "crAPI",
		ExpectedFile: "tests/fixtures/expected-findings/crapi.json",
		RequiredEnv:  []string{"CRAPI_BASE_URL", "CRAPI_OWNER_TOKEN", "CRAPI_OTHER_TOKEN"},
		Args: func() []string {
			return []string{
				"scan", "-t", os.Getenv("CRAPI_BASE_URL"),
				"--detector", "idor",
				"--endpoint", "/workshop/api/mechanic/mechanic_report?report_id={{id}}",
				"--auth-token", os.Getenv("CRAPI_OWNER_TOKEN"),
				"--other-auth-token", os.Getenv("CRAPI_OTHER_TOKEN"),
				"--templates", templatesDir(),
			}
		},
	},
	{
		// scripts/measure-fp-rate.sh: "crAPI (authbypass)" measure() call.
		Name:         "crAPI (authbypass)",
		ExpectedFile: "tests/fixtures/expected-findings/crapi-authbypass.json",
		RequiredEnv:  []string{"CRAPI_BASE_URL", "CRAPI_OWNER_TOKEN", "CRAPI_OTHER_TOKEN"},
		Args: func() []string {
			return []string{
				"scan", "-t", os.Getenv("CRAPI_BASE_URL"),
				"--detector", "authbypass",
				"--auth-token", os.Getenv("CRAPI_OWNER_TOKEN"),
				"--other-auth-token", os.Getenv("CRAPI_OTHER_TOKEN"),
				"--login-paths", "/identity/api/auth/login",
				"--protected-paths", "/identity/api/v2/user/dashboard,/identity/api/v2/vehicle/vehicles,/identity/api/v2/user/videos/convert_video,/community/api/v2/community/posts/recent,/workshop/api/shop/products,/workshop/api/shop/orders/all,/workshop/api/management/users/all,/workshop/api/mechanic/,/workshop/api/mechanic/service_requests,/workshop/api/shop/return_qr_code",
			}
		},
	},
	{
		// scripts/measure-fp-rate.sh: "DVWA" measure() call. Unlike that
		// script, DVWA_COOKIE is required (not optional) here: without it,
		// DVWA's login redirect hides the xss-/sqli- targets entirely (per
		// tests/fixtures/expected-findings/dvwa.json's own description),
		// and a per-challenge pass/fail run would misreport that as a real
		// failure rather than the documented, expected behavior.
		Name:         "DVWA",
		ExpectedFile: "tests/fixtures/expected-findings/dvwa.json",
		RequiredEnv:  []string{"DVWA_BASE_URL", "DVWA_COOKIE"},
		Args: func() []string {
			return []string{
				"scan", "-t", os.Getenv("DVWA_BASE_URL"),
				"--detector", "misconfig",
				"--templates", templatesDir(),
				"--header", "Cookie: " + os.Getenv("DVWA_COOKIE") + "; security=low",
			}
		},
	},
	{
		// scripts/measure-fp-rate.sh: "Juice Shop" measure() call.
		Name:         "Juice Shop",
		ExpectedFile: "tests/fixtures/expected-findings/juiceshop.json",
		RequiredEnv:  []string{"JUICESHOP_BASE_URL"},
		Args: func() []string {
			return []string{
				"scan", "-t", os.Getenv("JUICESHOP_BASE_URL"),
				"--detector", "misconfig",
				"--templates", templatesDir(),
			}
		},
	},
	{
		// scripts/measure-fp-rate.sh: "vAPI" measure() call. Deliberately
		// "./templates/", not templatesDir() — vAPI's dev-mode server can't
		// handle the full synced corpus in reasonable time (see that
		// script's own comment and tests/integration/vapi_auth_test.go).
		Name:         "vAPI",
		ExpectedFile: "tests/fixtures/expected-findings/vapi.json",
		RequiredEnv:  []string{"VAPI_BASE_URL"},
		Args: func() []string {
			return []string{
				"scan", "-t", os.Getenv("VAPI_BASE_URL"),
				"--detector", "misconfig",
				"--templates", "./templates/",
			}
		},
	},
	{
		// scripts/measure-fp-rate.sh: "vAPI (authbypass)" measure() call,
		// with one deliberate deviation: an explicit empty --templates
		// override (emptyTemplatesDir, see its doc comment) to avoid the
		// live-verified 2026-08-30 hang against vAPI's dev-mode server. The
		// bash script's own call has no --templates override, so it also
		// gets the nuclei-template layer's findings additively (per
		// vapi-authbypass.json's own description) — this Scenario
		// intentionally doesn't, so those three prefixes are graded as
		// skipped here, not failed.
		Name:         "vAPI (authbypass)",
		ExpectedFile: "tests/fixtures/expected-findings/vapi-authbypass.json",
		RequiredEnv:  []string{"VAPI_BASE_URL", "VAPI_OWNER_TOKEN", "VAPI_OTHER_TOKEN"},
		SkipPrefixes: []string{
			"nuclei-http-missing-security-headers",
			"nuclei-missing-cookie-samesite-strict",
			"nuclei-php-detect",
		},
		Args: func() []string {
			return []string{
				"scan", "-t", os.Getenv("VAPI_BASE_URL"),
				"--detector", "authbypass",
				"--auth-token", os.Getenv("VAPI_OWNER_TOKEN"),
				"--other-auth-token", os.Getenv("VAPI_OTHER_TOKEN"),
				"--auth-header-name", "Authorization-Token",
				"--auth-header-format", "{token}",
				"--protected-paths", "/vapi/api1/user/5,/vapi/api1/user/6",
				"--templates", emptyTemplatesDir(),
			}
		},
	},
}
