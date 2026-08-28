//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/authbypass"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// TestAuthBypassAgainstCRAPI runs the real authbypass detector against a
// live crAPI instance, using the same OpenAPI-spec-driven protected-path
// list docs/11-implementation-plan-ph2.md Step 5's breadth pass
// live-verified (2026-08-28): 2 original identity endpoints plus 8 more
// spanning crAPI's community/workshop microservices. The alg:none JWT
// bypass turned out to be systemic across all three services, not isolated
// to identity — see docs/20-setup-testing-targets.md's crAPI section for
// the full write-up and independent curl re-verification.
//
// Opt-in: skipped unless CRAPI_BASE_URL and both account tokens are set
// (see tests/integration/scripts/crapi_setup.sh).
func TestAuthBypassAgainstCRAPI(t *testing.T) {
	baseURL := os.Getenv("CRAPI_BASE_URL")
	ownerToken := os.Getenv("CRAPI_OWNER_TOKEN")
	otherToken := os.Getenv("CRAPI_OTHER_TOKEN")
	if baseURL == "" || ownerToken == "" || otherToken == "" {
		t.Skip("set CRAPI_BASE_URL, CRAPI_OWNER_TOKEN, and CRAPI_OTHER_TOKEN to run this test (see tests/integration/scripts/crapi_setup.sh)")
	}

	client := httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))

	detector := authbypass.New(client, authbypass.WithLoginPaths([]string{"/identity/api/auth/login"}))

	protectedPaths := []string{
		"/identity/api/v2/user/dashboard",
		"/identity/api/v2/vehicle/vehicles",
		"/identity/api/v2/user/videos/convert_video",
		"/community/api/v2/community/posts/recent",
		"/workshop/api/shop/products",
		"/workshop/api/shop/orders/all",
		"/workshop/api/management/users/all",
		"/workshop/api/mechanic/",
		"/workshop/api/mechanic/service_requests",
		"/workshop/api/shop/return_qr_code",
	}

	findings, err := detector.Run(context.Background(), baseURL, ownerToken, otherToken, protectedPaths)
	require.NoError(t, err)

	// Real, live-verified minimum (docs/20-setup-testing-targets.md's crAPI
	// section): 2 identity alg:none + 7 breadth alg:none + 1
	// signature-stripped + 1 missing-auth = 11 high-confidence findings.
	// Asserting 10 rather than 11 to leave a little slack for a target that
	// isn't byte-identical to the instance this was measured against, not
	// because the real number is uncertain.
	require.GreaterOrEqual(t, len(findings), 10, "expected at least 10 real authbypass findings against crAPI's identity/community/workshop microservices")
	for _, f := range findings {
		assert.Equal(t, "authbypass", f.Type)
	}
}
