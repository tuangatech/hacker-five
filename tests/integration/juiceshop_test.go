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
)

// TestMisconfigJuiceShop runs the misconfiguration detector against a live
// Juice Shop instance. Opt-in: skipped unless JUICESHOP_BASE_URL is set (see
// docs/20-setup-testing-targets.md's Juice Shop section for bringing it up).
//
// Nuclei-compatible template coverage against Juice Shop already exists —
// see TestNucleiTemplates's JuiceShop subtest in nuclei_templates_test.go
// (added during Step 2's live verification: http-missing-security-headers
// and owasp-juice-shop-detect both fire for real) — not duplicated here.
func TestMisconfigJuiceShop(t *testing.T) {
	baseURL := os.Getenv("JUICESHOP_BASE_URL")
	if baseURL == "" {
		t.Skip("set JUICESHOP_BASE_URL to run this test, e.g. http://localhost:3000")
	}

	client := httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))

	detector := misconfig.New(client)
	findings, err := detector.Run(context.Background(), baseURL, "")
	require.NoError(t, err)

	// Real, live-verified minimum (see docs/20-setup-testing-targets.md's
	// Juice Shop caveat): 2 missing-header + 3 disallowed-method findings,
	// after the .htpasswd false-positive fix. Exposed-path findings vary
	// (security.txt is real but borderline-informational), so not asserted.
	require.GreaterOrEqual(t, len(findings), 5, "expected at least the 2 missing-header + 3 disallowed-method findings against Juice Shop")
	for _, f := range findings {
		require.Equal(t, "misconfig", f.Type)
	}
}
