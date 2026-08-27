//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/detectors/misconfig"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestVAPI runs misconfig + the synced Nuclei-compatible template set
// against a live vAPI instance. Opt-in: skipped unless VAPI_BASE_URL is set
// (see docs/20-setup-testing-targets.md's vAPI section for bringing it up).
//
// IDOR is covered separately, by TestIDORAgainstVAPI below — see that test's
// doc comment for the auth-header scheme this needed (Future Enhancement #6).
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

// TestIDORAgainstVAPI runs the real IDOR detector against a live vAPI
// instance, exercising Future Enhancement #6 (configurable auth-header
// scheme, docs/10-implementation-plan-ph1b.md). Reading vAPI's source
// confirms a real bug structurally identical to crAPI's:
// API1UsersController::show (routes/api.php: "GET api1/user/{id}") calls
// API1Users::find($id) with no check that $id belongs to the authenticated
// user (API5UsersController::show is the *fixed* counterpart — it adds
// ->where('id', $id)). But every vAPI endpoint authenticates via a custom
// "Authorization-Token: base64(username:password)" header, not
// "Authorization: Bearer <token>" — idor.Detector.fetch hardcoded the latter
// until WithAuthHeader made it configurable.
//
// Opt-in: skipped unless VAPI_BASE_URL, VAPI_OWNER_TOKEN, and
// VAPI_OTHER_TOKEN are set. VAPI_*_TOKEN are each an already-computed
// base64(username:password) value for one real vAPI account — e.g.
// `printf '%s' 'owner@example.com:password' | base64` — not raw
// credentials, matching every other *_TOKEN env var this project uses.
// There's no known-safe scripted signup for vAPI accounts (unlike
// tests/integration/scripts/crapi_setup.sh for crAPI), so both accounts must
// be created manually via vAPI's web UI first.
func TestIDORAgainstVAPI(t *testing.T) {
	baseURL := os.Getenv("VAPI_BASE_URL")
	ownerToken := os.Getenv("VAPI_OWNER_TOKEN")
	otherToken := os.Getenv("VAPI_OTHER_TOKEN")
	if baseURL == "" || ownerToken == "" || otherToken == "" {
		t.Skip("set VAPI_BASE_URL, VAPI_OWNER_TOKEN, and VAPI_OTHER_TOKEN to run this test (each token is base64(username:password) for a real vAPI account)")
	}

	client := httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))

	strategy := idor.SequentialIntStrategy{Start: 1, End: 20}
	detector := idor.New(client, strategy, idor.WithAuthHeader("Authorization-Token", "{token}"))

	endpointTemplate := baseURL + "/api1/user/{{id}}"
	findings, err := detector.Run(context.Background(), endpointTemplate, ownerToken, otherToken)
	require.NoError(t, err)

	require.NotEmpty(t, findings, "expected at least one IDOR finding against vAPI's api1/user/{id} BOLA")
	for _, f := range findings {
		assert.Equal(t, "idor", f.Type)
		assert.Equal(t, "high", f.Confidence)
	}
}
