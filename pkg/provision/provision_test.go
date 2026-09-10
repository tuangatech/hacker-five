package provision

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func testClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{Timeout: 5 * time.Second, MaxRedirects: 5})
}

// TestProvisionAccount_TokenInSignupResponse covers the direct case: the
// signup response itself carries a usable token, no login fallback needed.
func TestProvisionAccount_TokenInSignupResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/identity/api/auth/signup", r.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Contains(t, body["email"], "@example.com")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"direct-signup-token-abc"}`)
	}))
	defer srv.Close()

	res, err := ProvisionAccount(context.Background(), testClient(), srv.URL+"/identity/api/auth/signup", http.MethodPost, "hf+{{rand}}@example.com")
	require.NoError(t, err)
	assert.Equal(t, "direct-signup-token-abc", res.Token)
	assert.Contains(t, res.Email, "@example.com")
}

// TestProvisionAccount_TokenViaLoginFallback covers the crAPI-shaped case
// (tests/integration/scripts/crapi_setup.sh): signup succeeds but returns no
// token, so ProvisionAccount falls back to logging in with the credentials
// it just created.
func TestProvisionAccount_TokenViaLoginFallback(t *testing.T) {
	var createdEmail, createdPassword string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity/api/auth/signup":
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			createdEmail, _ = body["email"].(string)
			createdPassword, _ = body["password"].(string)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"created"}`) // no token here — crAPI's real shape
		case "/identity/api/auth/login":
			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, createdEmail, body["email"])
			assert.Equal(t, createdPassword, body["password"])
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"login-fallback-token-xyz"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	res, err := ProvisionAccount(context.Background(), testClient(), srv.URL+"/identity/api/auth/signup", http.MethodPost, "hf+{{rand}}@example.com")
	require.NoError(t, err)
	assert.Equal(t, "login-fallback-token-xyz", res.Token)
}

// TestProvisionAccount_NestedTokenField covers a "{"data": {"token": ...}}"
// shape one level deep.
func TestProvisionAccount_NestedTokenField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"access_token":"nested-token-123"}}`)
	}))
	defer srv.Close()

	res, err := ProvisionAccount(context.Background(), testClient(), srv.URL+"/register", http.MethodPost, "hf+{{rand}}@example.com")
	require.NoError(t, err)
	assert.Equal(t, "nested-token-123", res.Token)
}

// TestProvisionAccount_EmailVerificationGated_FailsClosed covers the named,
// accepted limitation: neither the signup response nor the login fallback
// ever carries a token (an email-verification gate), so ProvisionAccount
// must return a clear error rather than hang or fabricate a token.
func TestProvisionAccount_EmailVerificationGated_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"status":"pending email verification"}`)
		case "/login":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, err := ProvisionAccount(context.Background(), testClient(), srv.URL+"/register", http.MethodPost, "hf+{{rand}}@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email verification")
}

// TestProvisionAccount_SignupFails_ReturnsError covers a non-2xx signup
// response (e.g. the endpoint doesn't actually accept this body shape).
func TestProvisionAccount_SignupFails_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := ProvisionAccount(context.Background(), testClient(), srv.URL+"/register", http.MethodPost, "hf+{{rand}}@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 400")
}

// TestProvisionAccount_EmptyEmailTemplate_ReturnsError guards the "no
// default/fabricated email domain, ever" design rule — a blank template must
// fail fast rather than inventing one.
func TestProvisionAccount_EmptyEmailTemplate_ReturnsError(t *testing.T) {
	_, err := ProvisionAccount(context.Background(), testClient(), "https://example.com/register", http.MethodPost, "")
	require.Error(t, err)
}

func TestRenderEmailTemplate_SubstitutesRand(t *testing.T) {
	a := renderEmailTemplate("you+{{rand}}@yourdomain.com")
	b := renderEmailTemplate("you+{{rand}}@yourdomain.com")
	assert.NotEqual(t, a, b, "each call should get a fresh random token")
	assert.NotContains(t, a, "{{rand}}")
}

func TestSiblingLoginURL(t *testing.T) {
	assert.Equal(t, "https://x.example/identity/api/auth/login", siblingLoginURL("https://x.example/identity/api/auth/signup"))
	assert.Equal(t, "https://x.example/auth/login", siblingLoginURL("https://x.example/auth/register"))
}
