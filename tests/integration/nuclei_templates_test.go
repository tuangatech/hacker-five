//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiTemplates loads the synced upstream templates and runs them
// against DVWA and/or Juice Shop if configured. Opt-in: skipped unless
// NUCLEI_TEMPLATES_DIR is set (defaults to .nuclei-templates-cache, see
// scripts/sync-nuclei-templates.sh / `make templates-sync`).
//
// Per docs/10-implementation-plan-ph1b.md Step 2's "Realistic yield" note:
// neither DVWA nor Juice Shop has a dedicated upstream template, so most
// live findings are expected from the technologies category (e.g. Angular
// detection against Juice Shop) — a low or zero count from
// exposed-panels/misconfiguration against either target is expected, not a
// bug, since neither app runs the panels/frameworks those templates target.
// This test therefore asserts load success strictly, but only logs (does
// not assert a minimum on) live finding counts.
func TestNucleiTemplates(t *testing.T) {
	dir := os.Getenv("NUCLEI_TEMPLATES_DIR")
	if dir == "" {
		// go test's working directory is this package's own directory
		// (tests/integration/), not the repo root `make templates-sync`
		// runs from — so the default must point back up to it.
		dir = "../../.nuclei-templates-cache"
	}
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("templates directory %q not found — run `make templates-sync` first (see scripts/sync-nuclei-templates.sh)", dir)
	}

	templates, errs := nuclei.LoadDir(dir)
	t.Logf("loaded %d templates, %d rejected (raw:/payloads:/disallowed-block templates are expected here)", len(templates), len(errs))
	require.GreaterOrEqualf(t, len(templates), 50, "expected at least 50 templates to parse successfully from %q", dir)

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 25,
	}, httpclient.WithRetry(1, 200*time.Millisecond))
	executor := nuclei.New(client)

	// runAgainst deliberately doesn't fail the test on a per-template error
	// (a context-deadline timeout from a many-path panel template, or a
	// connection error against an unreachable target) — with ~3,000+ real
	// templates in the synced set, a handful of individual timeouts is
	// expected noise, not evidence the engine itself is broken; errCount is
	// logged so a systemic problem (most/all templates erroring) is still
	// visible.
	runAgainst := func(t *testing.T, targetName, baseURL string) {
		t.Helper()
		var findings []detectors.Finding
		errCount := 0
		for _, tmpl := range templates {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			fs, err := executor.Run(ctx, baseURL, tmpl)
			cancel()
			if err != nil {
				errCount++
				continue
			}
			findings = append(findings, fs...)
		}
		t.Logf("%s: %d findings, %d template errors, across %d templates", targetName, len(findings), errCount, len(templates))
	}

	if dvwaURL := os.Getenv("DVWA_BASE_URL"); dvwaURL != "" {
		t.Run("DVWA", func(t *testing.T) { runAgainst(t, "DVWA", dvwaURL) })
	}
	if juiceShopURL := os.Getenv("JUICESHOP_BASE_URL"); juiceShopURL != "" {
		t.Run("JuiceShop", func(t *testing.T) { runAgainst(t, "JuiceShop", juiceShopURL) })
	}
}
