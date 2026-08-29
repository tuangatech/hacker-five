package webui

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":     true,
		"::1":           true,
		"localhost":     true,
		"":              true,
		"0.0.0.0":       false,
		"192.168.1.10":  false,
		"example.com":   false,
	}
	for host, want := range cases {
		assert.Equal(t, want, isLoopbackHost(host), "host=%q", host)
	}
}

func TestNewNonLoopbackAuth_LoopbackHost_Disabled(t *testing.T) {
	auth, err := newNonLoopbackAuth("127.0.0.1")
	require.NoError(t, err)
	assert.False(t, auth.enabled)
	assert.Equal(t, "http://x", auth.BootstrapURL("http://x"), "loopback bind must never require a token")
}

func TestNewNonLoopbackAuth_NonLoopbackHost_Enabled(t *testing.T) {
	auth, err := newNonLoopbackAuth("0.0.0.0")
	require.NoError(t, err)
	assert.True(t, auth.enabled)
	assert.NotEmpty(t, auth.secret)
	assert.Contains(t, auth.BootstrapURL("http://x:8877"), auth.secret)
}

func TestNonLoopbackAuthMiddleware_LoopbackNeverGates(t *testing.T) {
	auth, err := newNonLoopbackAuth("127.0.0.1")
	require.NoError(t, err)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil) // no token, no cookie
	auth.middleware(next).ServeHTTP(w, r)

	assert.True(t, called)
}

func TestNonLoopbackAuthMiddleware_NonLoopback_NoCredentials_Rejected(t *testing.T) {
	auth, err := newNonLoopbackAuth("0.0.0.0")
	require.NoError(t, err)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	auth.middleware(next).ServeHTTP(w, r)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestNonLoopbackAuthMiddleware_CorrectToken_SetsCookieAndStripsURL confirms
// the handoff doc12's review requested: the bootstrap token appears in the
// URL exactly once, then becomes a cookie — not repeated on every request.
func TestNonLoopbackAuthMiddleware_CorrectToken_SetsCookieAndStripsURL(t *testing.T) {
	auth, err := newNonLoopbackAuth("0.0.0.0")
	require.NoError(t, err)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/scans/new?token="+auth.secret, nil)
	auth.middleware(next).ServeHTTP(w, r)

	assert.False(t, called, "the token request itself must redirect, not fall through to next")
	assert.Equal(t, http.StatusFound, w.Code)

	loc := w.Header().Get("Location")
	assert.Equal(t, "/scans/new", loc, "the redirect target must have the token query param stripped")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, tokenCookieName, cookies[0].Name)
	assert.Equal(t, auth.secret, cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly)
}

func TestNonLoopbackAuthMiddleware_ValidCookie_AllowsAccess(t *testing.T) {
	auth, err := newNonLoopbackAuth("0.0.0.0")
	require.NoError(t, err)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/scans/new", nil)
	r.AddCookie(&http.Cookie{Name: tokenCookieName, Value: auth.secret})
	auth.middleware(next).ServeHTTP(w, r)

	assert.True(t, called)
}

func TestNonLoopbackAuthMiddleware_WrongToken_Rejected(t *testing.T) {
	auth, err := newNonLoopbackAuth("0.0.0.0")
	require.NoError(t, err)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/?token=totally-wrong", nil)
	auth.middleware(next).ServeHTTP(w, r)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
