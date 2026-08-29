package webui

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSRFToken_SetsNewCookieOnFirstCall(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	token, err := csrfToken(w, r)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, csrfCookieName, cookies[0].Name)
	assert.Equal(t, token, cookies[0].Value)
	assert.True(t, cookies[0].HttpOnly, "the CSRF cookie must be HttpOnly — nothing client-side needs to read it")
}

func TestCSRFToken_ReusesExistingCookie(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "existing-token"})

	token, err := csrfToken(w, r)
	require.NoError(t, err)
	assert.Equal(t, "existing-token", token)
	assert.Empty(t, w.Result().Cookies(), "must not set a new cookie when one already exists")
}

func TestCSRFMiddleware_GETPassesThroughWithoutCheck(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil) // no cookie, no token — GET must not care
	csrfMiddleware(next).ServeHTTP(w, r)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCSRFMiddleware_POSTMissingCookie_Rejected(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{csrfFormField: {"anything"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	csrfMiddleware(next).ServeHTTP(w, r)

	assert.False(t, called, "handler must not run without a CSRF cookie")
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_POSTMismatchedToken_Rejected(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{csrfFormField: {"wrong-token"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "real-token"})
	csrfMiddleware(next).ServeHTTP(w, r)

	assert.False(t, called)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestCSRFMiddleware_POSTMatchingToken_Allowed(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{csrfFormField: {"real-token"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "real-token"})
	csrfMiddleware(next).ServeHTTP(w, r)

	assert.True(t, called)
}
