package webui

import (
	"net"
	"net/http"
	"net/url"
)

const tokenCookieName = "hf_token"
const tokenQueryParam = "token"

// isLoopbackHost reports whether host is safe to bind without requiring a
// token — 127.0.0.1/::1 per doc12's literal wording, plus the equally
// common "localhost" spelling (net.ParseIP doesn't resolve hostnames, so
// it's special-cased) — consistent with the doc's "it's your own machine"
// trust model, not a new capability.
func isLoopbackHost(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// nonLoopbackAuth gates every request once --host is set to anything other
// than loopback, per docs/12-implementation-plan-ph3.md's "Attack surface &
// hardening" section and its reviewed token-in-URL mitigation: one secret,
// generated once at startup, used both as the bootstrap ?token= value and
// (once presented correctly) as the session cookie's value — the URL token
// is a one-time bootstrap, not something every subsequent request repeats.
type nonLoopbackAuth struct {
	enabled bool
	secret  string
}

func newNonLoopbackAuth(host string) (*nonLoopbackAuth, error) {
	if isLoopbackHost(host) {
		return &nonLoopbackAuth{enabled: false}, nil
	}
	secret, err := randomHex(24)
	if err != nil {
		return nil, err
	}
	return &nonLoopbackAuth{enabled: true, secret: secret}, nil
}

// BootstrapURL returns the token-bearing URL to print at startup — "" when
// auth isn't enabled (loopback bind).
func (a *nonLoopbackAuth) BootstrapURL(base string) string {
	if !a.enabled {
		return base
	}
	return base + "/?" + tokenQueryParam + "=" + a.secret
}

func (a *nonLoopbackAuth) middleware(next http.Handler) http.Handler {
	if !a.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(tokenCookieName); err == nil && c.Value == a.secret {
			next.ServeHTTP(w, r)
			return
		}

		if r.URL.Query().Get(tokenQueryParam) == a.secret {
			http.SetCookie(w, &http.Cookie{
				Name:     tokenCookieName,
				Value:    a.secret,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			// Strip the token from the URL before redirecting — the whole
			// point of the handoff is that the token appears in exactly one
			// URL (this request), not in every request/log line after.
			clean := &url.URL{Path: r.URL.Path}
			q := r.URL.Query()
			q.Del(tokenQueryParam)
			clean.RawQuery = q.Encode()
			http.Redirect(w, r, clean.String(), http.StatusFound)
			return
		}

		http.Error(w, "missing or invalid access token", http.StatusUnauthorized)
	})
}
