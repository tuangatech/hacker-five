package webui

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const csrfCookieName = "hf_csrf"
const csrfFormField = "csrf_token"

// randomHex returns a cryptographically random, hex-encoded string of n
// bytes — shared by the CSRF cookie, job IDs, and the non-loopback
// bootstrap token (auth.go), one primitive instead of three copies.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// csrfToken returns the current request's CSRF token, setting a new
// HttpOnly cookie first if one isn't already present. HttpOnly is safe
// here specifically because nothing client-side ever needs to read this
// cookie: the server embeds its value into the form's hidden input at
// render time (see templates/new_scan.html), and only compares the cookie
// against that hidden field server-side on submit — the classic
// double-submit-cookie pattern, with the cookie itself never exposed to
// page JS.
func csrfToken(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
		return c.Value, nil
	}
	token, err := randomHex(16)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return token, nil
}

// readCSRFCookie returns the current request's CSRF cookie value, or "" if
// none is set yet — for a render path that can't safely mint a new cookie
// (headers already flushed, e.g. scanEvents' SSE stream once it's started
// writing). Unlike csrfToken, never sets a cookie itself; a caller in that
// position instead relies on an earlier GET/POST on the same job having
// already set one, which is true for every real page flow that reaches
// this point (an SSE connection is only ever opened from a scan-status page
// the browser already loaded via csrfToken).
func readCSRFCookie(r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil {
		return c.Value
	}
	return ""
}

// csrfMiddleware guards every state-changing request generically (any
// method other than GET/HEAD/OPTIONS), so a future POST/PUT/DELETE route
// (e.g. Week 23's POST /templates/sync) gets this protection for free
// rather than needing its own copy.
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie(csrfCookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, "missing CSRF cookie", http.StatusForbidden)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if r.PostFormValue(csrfFormField) != cookie.Value {
			http.Error(w, "invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
