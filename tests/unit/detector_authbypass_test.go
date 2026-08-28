package unit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/authbypass"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func newAuthBypassClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

// signedJWT builds a real, well-formed HS256 JWT signed with secret — used
// both for a "real" ownerToken and for a deliberately-weak-secret token.
func signedJWT(t *testing.T, secret string) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user1"}).SignedString([]byte(secret))
	require.NoError(t, err)
	return tok
}

// jwtIsTampered inspects an incoming bearer token and reports whether it's
// one of the alg:none/signature-stripped bypass shapes — used by mock
// servers simulating a vulnerable (or safe) backend's JWT verification.
func jwtIsTampered(bearer string) bool {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return false
	}
	if parts[2] == "" {
		return true // signature-stripped variant
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return false
	}
	alg, _ := header["alg"].(string)
	return strings.EqualFold(alg, "none")
}

func bearerFrom(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func TestAuthBypassMissingAuth_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("dashboard"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", "", []string{"/admin"})
	require.NoError(t, err)

	got := withPrefix(findings, "authbypass-missing-auth-")
	require.Len(t, got, 1)
	assert.Equal(t, "authbypass", got[0].Type)
	assert.Equal(t, "high", got[0].Severity)
}

func TestAuthBypassMissingAuth_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" && r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", "", []string{"/admin"})
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "authbypass-missing-auth-"))
}

func TestAuthBypassJWTAlgNone_Hit(t *testing.T) {
	owner := signedJWT(t, "realsecret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Vulnerable backend: accepts any tampered variant without checking
		// the signature.
		if jwtIsTampered(bearerFrom(r)) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("profile data"))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, owner, "", []string{"/profile"})
	require.NoError(t, err)

	got := withPrefix(findings, "authbypass-jwt-")
	require.NotEmpty(t, got)
	for _, f := range got {
		assert.Equal(t, "critical", f.Severity)
	}
}

func TestAuthBypassJWTAlgNone_NoFinding(t *testing.T) {
	owner := signedJWT(t, "realsecret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/profile" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Safe backend: rejects every tampered variant.
		if jwtIsTampered(bearerFrom(r)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, owner, "", []string{"/profile"})
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "authbypass-jwt-alg-none"))
	assert.Empty(t, withPrefix(findings, "authbypass-jwt-signature-stripped"))
}

// TestAuthBypassJWTWeakSecret_Hit locks in the offline-only property
// docs/follow-up.md requires: the weak-secret check must never send the
// candidate secrets to the server. Proven black-box here by counting total
// requests the mock server receives — with empty protectedPaths and no
// otherToken, only checkRateLimitSignal's login-path discovery loop (one
// request per authbypass.LoginPaths entry, all 404) can generate traffic;
// if the weak-secret check made even one network call, the count would be
// higher than len(authbypass.LoginPaths).
func TestAuthBypassJWTWeakSecret_Hit(t *testing.T) {
	owner := signedJWT(t, "secret") // "secret" is in authbypass.WeakJWTSecrets

	var requestCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, owner, "", nil)
	require.NoError(t, err)

	got := withPrefix(findings, "authbypass-jwt-weak-secret")
	require.Len(t, got, 1)
	assert.Equal(t, "critical", got[0].Severity)

	assert.Equal(t, int64(len(authbypass.LoginPaths)), atomic.LoadInt64(&requestCount),
		"weak-secret check must make zero network requests — any extra request beyond the login-path discovery loop means it leaked onto the wire")
}

func TestAuthBypassJWTWeakSecret_NoFinding(t *testing.T) {
	owner := signedJWT(t, "a-genuinely-strong-and-unguessable-secret-value")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, owner, "", nil)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "authbypass-jwt-weak-secret"))
}

func TestAuthBypassRateLimitSignal_NoThrottling_Hit(t *testing.T) {
	var loginRequests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			atomic.AddInt64(&loginRequests, 1)
			w.WriteHeader(http.StatusUnauthorized) // "invalid credentials", never throttled
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", "", nil)
	require.NoError(t, err)

	got := withPrefix(findings, "authbypass-no-rate-limit-")
	require.Len(t, got, 1)
	assert.Equal(t, "medium", got[0].Severity)
	assert.Equal(t, "low", got[0].Confidence)

	// One discovery request + the fixed probe count, never more.
	wantMax := int64(11)
	assert.LessOrEqual(t, atomic.LoadInt64(&loginRequests), wantMax)
}

func TestAuthBypassRateLimitSignal_Throttled_NoFinding(t *testing.T) {
	var loginRequests int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n := atomic.AddInt64(&loginRequests, 1)
		if n >= 3 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "", "", nil)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "authbypass-no-rate-limit-"))
	assert.LessOrEqual(t, atomic.LoadInt64(&loginRequests), int64(4),
		"probe loop must stop as soon as a throttling signal appears, not keep going to the cap")
}

func TestAuthBypassTokenReuse_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/me" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("same content regardless of account"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", "other-token", []string{"/me"})
	require.NoError(t, err)

	got := withPrefix(findings, "authbypass-token-reuse-")
	require.Len(t, got, 1)
	assert.Equal(t, "low", got[0].Confidence)
}

func TestAuthBypassTokenReuse_NoFinding_DifferentContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/me" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch bearerFrom(r) {
		case "owner-token":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":"owner","email":"owner@example.com"}`))
		case "other-token":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":"other","email":"other@example.com"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", "other-token", []string{"/me"})
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "authbypass-token-reuse-"))
}

func TestAuthBypassBrokenSession_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logout":
			w.WriteHeader(http.StatusOK)
		case "/profile":
			// Still accepts the token even after logout.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("still logged in"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", "", []string{"/profile"})
	require.NoError(t, err)

	got := withPrefix(findings, "authbypass-broken-session-")
	require.Len(t, got, 1)
	assert.Equal(t, "high", got[0].Severity)
}

func TestAuthBypassBrokenSession_NoFinding(t *testing.T) {
	var loggedOut int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logout":
			atomic.StoreInt64(&loggedOut, 1)
			w.WriteHeader(http.StatusOK)
		case "/profile":
			if atomic.LoadInt64(&loggedOut) == 1 {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	detector := authbypass.New(newAuthBypassClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", "", []string{"/profile"})
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "authbypass-broken-session-"))
}
