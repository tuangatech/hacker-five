//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/misconfig"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestVAPI runs misconfig + the synced Nuclei-compatible template set
// against a live vAPI instance. Opt-in: skipped unless VAPI_BASE_URL is set
// (see docs/20-setup-testing-targets.md's vAPI section for bringing it up).
//
// IDOR is deliberately NOT tested here, despite vAPI having a real BOLA
// (API1UsersController::show — no check that the requested id belongs to
// the authenticated user, confirmed by reading its source). Every vAPI
// endpoint authenticates via a custom "Authorization-Token:
// base64(user:pass)" header, not "Authorization: Bearer <token>", which
// idor.Detector doesn't support — a real gap, recorded as a Future
// Enhancement candidate (configurable auth-header scheme) in
// docs/10-implementation-plan-ph1b.md rather than solved here.
func TestVAPI(t *testing.T) {
	baseURL := os.Getenv("VAPI_BASE_URL")
	if baseURL == "" {
		t.Skip("set VAPI_BASE_URL to run this test, e.g. http://localhost:8000")
	}

	client := httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))

	t.Run("misconfig", func(t *testing.T) {
		detector := misconfig.New(client)
		findings, err := detector.Run(context.Background(), baseURL, "")
		require.NoError(t, err)

		// Real, live-verified minimum (see docs/20-setup-testing-targets.md's
		// vAPI section): 4 missing-header + 3 disallowed-method findings.
		require.GreaterOrEqual(t, len(findings), 7, "expected at least the 4 missing-header + 3 disallowed-method findings against vAPI")
		for _, f := range findings {
			require.Equal(t, "misconfig", f.Type)
		}
	})

	t.Run("nuclei", func(t *testing.T) {
		// Deliberately the small curated sample set here, not the full
		// synced corpus (.nuclei-templates-cache, ~2,500 templates) that
		// TestNucleiTemplates runs against DVWA/Juice Shop: verified live
		// that vAPI's dev-mode Laravel server (php artisan serve, no
		// production web server in front) can't handle that many sequential
		// requests in any reasonable time — a full-corpus run here still
		// hadn't finished after 20 minutes (vs. ~140s against DVWA/Juice
		// Shop), almost certainly every slow/timed-out request paying the
		// full 10s timeout x up to 3 retries. Real, observed constraint of
		// this specific target, not an engine problem — see
		// docs/20-setup-testing-targets.md's vAPI section.
		dir := os.Getenv("NUCLEI_TEMPLATES_DIR")
		if dir == "" {
			dir = "../../templates/nuclei-samples"
		}
		if _, err := os.Stat(dir); err != nil {
			t.Skipf("templates directory %q not found", dir)
		}

		templates, _ := nuclei.LoadDir(dir)
		executor := nuclei.New(client)

		var findingIDs []string
		for _, tmpl := range templates {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			fs, err := executor.Run(ctx, baseURL, tmpl)
			cancel()
			if err != nil {
				continue
			}
			for _, f := range fs {
				findingIDs = append(findingIDs, f.ID)
			}
		}

		// Real, live-verified minimum: http-missing-security-headers and
		// php-detect both fire (Laravel serves X-Powered-By: PHP, and misses
		// most security headers by default).
		require.NotEmpty(t, findingIDs, "expected at least one Nuclei-template finding against vAPI")
	})
}
