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

func newVAPIAuthbypassClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))
}

// TestAuthBypassAgainstVAPI_API1 exercises vAPI's api1 module, whose custom
// "Authorization-Token: base64(username:password)" header scheme
// authbypass.Detector only supports via WithAuthHeader (Future
// Enhancement #6). Real, live-verified result (docs/20-setup-testing-targets.md's
// vAPI section, 2026-08-28): checkTokenReuse fires against
// /vapi/api1/user/{id} — it returns identical content regardless of which
// account's token is used, the same underlying BOLA the IDOR detector
// already finds (see TestIDORAgainstVAPI in vapi_auth_test.go), now also
// caught through authbypass's own lens.
//
// Asserting >=1, not >=2 for the two candidate IDs below: this lab
// instance's user-ID sequence drifts every time a test run (this one
// included) signs up throwaway accounts, so IDs 5/6 don't reliably belong
// to two existing, comparable accounts by the time this runs — a
// checkTokenReuse finding only registers for an ID whose owner-token
// request itself succeeds (see detector.go), so which of the two IDs fires
// depends on lab state, not on whether the BOLA is real. One real finding
// is still proof the underlying bug fires; requiring exactly 2 would be
// over-fit to a mutable target's current row count, not a stronger check.
//
// Opt-in: skipped unless VAPI_BASE_URL, VAPI_OWNER_TOKEN, and
// VAPI_OTHER_TOKEN are set — each token is base64(username:password) for a
// real vAPI account, same convention as TestIDORAgainstVAPI.
func TestAuthBypassAgainstVAPI_API1(t *testing.T) {
	baseURL := os.Getenv("VAPI_BASE_URL")
	ownerToken := os.Getenv("VAPI_OWNER_TOKEN")
	otherToken := os.Getenv("VAPI_OTHER_TOKEN")
	if baseURL == "" || ownerToken == "" || otherToken == "" {
		t.Skip("set VAPI_BASE_URL, VAPI_OWNER_TOKEN, and VAPI_OTHER_TOKEN to run this test (each token is base64(username:password) for a real vAPI account)")
	}

	detector := authbypass.New(newVAPIAuthbypassClient(),
		authbypass.WithAuthHeader("Authorization-Token", "{token}"),
	)

	findings, err := detector.Run(context.Background(), baseURL, ownerToken, otherToken, []string{"/vapi/api1/user/5", "/vapi/api1/user/6"})
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(findings), 1, "expected at least 1 token-reuse finding against vAPI's api1/user/{id} BOLA")
	for _, f := range findings {
		assert.Equal(t, "authbypass", f.Type)
	}
}

// TestAuthBypassAgainstVAPI_JWTUser exercises vAPI's separate jwt/user
// module (JustWeakTokenController), which uses a real JWT via a plain
// "Authorization-Token: <jwt>" header (no base64/username:password
// encoding, unlike api1) — a different auth scheme from API1, so this is a
// separate detector.Run call rather than combined into
// TestAuthBypassAgainstVAPI_API1. Real, live-verified result
// (docs/20-setup-testing-targets.md's vAPI section, 2026-08-28): the
// module's JWT::decode($token, $key, array('HS256','none')) call really
// does accept alg:none — 2 critical findings (alg:none,
// signature-stripped) plus 1 high broken-session finding (the module has
// no server-side logout at all), independently re-confirmed by hand-forging
// a role:admin token and retrieving the module's flag directly.
//
// Opt-in: skipped unless VAPI_BASE_URL and VAPI_JWT_USER_TOKEN are set.
// VAPI_JWT_USER_TOKEN is a real JWT from POSTing a fresh, unique username to
// /vapi/jwt/user — see docs/20-setup-testing-targets.md for the exact
// registration flow (a reused username hits a real DB unique-constraint
// collision and 500s, not a HackerFive bug).
func TestAuthBypassAgainstVAPI_JWTUser(t *testing.T) {
	baseURL := os.Getenv("VAPI_BASE_URL")
	ownerToken := os.Getenv("VAPI_JWT_USER_TOKEN")
	if baseURL == "" || ownerToken == "" {
		t.Skip("set VAPI_BASE_URL and VAPI_JWT_USER_TOKEN to run this test (a real JWT from POSTing a fresh username to /vapi/jwt/user — see docs/20-setup-testing-targets.md)")
	}

	detector := authbypass.New(newVAPIAuthbypassClient(),
		authbypass.WithAuthHeader("Authorization-Token", "{token}"),
	)

	findings, err := detector.Run(context.Background(), baseURL, ownerToken, "", []string{"/vapi/jwt/user"})
	require.NoError(t, err)

	require.GreaterOrEqual(t, len(findings), 3, "expected at least 3 findings (alg:none, signature-stripped, broken-session) against vAPI's jwt/user module")
	for _, f := range findings {
		assert.Equal(t, "authbypass", f.Type)
	}
}
