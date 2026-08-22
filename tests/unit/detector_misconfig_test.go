package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/detectors/misconfig"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func newMisconfigClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

func runMisconfig(t *testing.T, handler http.HandlerFunc) []detectors.Finding {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	detector := misconfig.New(newMisconfigClient())
	findings, err := detector.Run(context.Background(), server.URL, "")
	require.NoError(t, err)
	return findings
}

// withPrefix filters findings down to those whose ID starts with prefix, so
// each test only asserts on the rule category it's exercising and ignores
// incidental findings from the server's default (empty) responses to every
// other check the detector also fires.
func withPrefix(findings []detectors.Finding, prefix string) []detectors.Finding {
	var out []detectors.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.ID, prefix) {
			out = append(out, f)
		}
	}
	return out
}

func TestMisconfigExposedPath_Hit(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("DB_PASSWORD=hunter2\nAPP_KEY=abc"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-exposed-path-.env")
	require.Len(t, got, 1)
	assert.Equal(t, "misconfig", got[0].Type)
	assert.Equal(t, "high", got[0].Confidence)
}

func TestMisconfigExposedPath_CustomNotFoundPage_NoFinding(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Nothing to see here</html>"))
	})

	got := withPrefix(findings, "misconfig-exposed-path-.env")
	assert.Empty(t, got)
}

func TestMisconfigMissingHeaders_AllAbsent(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-missing-header-")
	assert.Len(t, got, 4) // CSP, X-Frame-Options, HSTS, X-Content-Type-Options
}

func TestMisconfigMissingHeaders_AllPresent(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Strict-Transport-Security", "max-age=63072000")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-missing-header-")
	assert.Empty(t, got)
}

func TestMisconfigMethod_PUTAccepted(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-method-put-")
	require.Len(t, got, 1)
	assert.Equal(t, "medium", got[0].Severity)
}

func TestMisconfigMethod_PUTRejected(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-method-put-")
	assert.Empty(t, got)
}

func TestMisconfigCORS_WildcardWithCredentials(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-cors")
	require.Len(t, got, 1)
	assert.Equal(t, "high", got[0].Severity)
}

func TestMisconfigCORS_WildcardWithoutCredentials_NoFinding(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-cors")
	assert.Empty(t, got)
}

func TestMisconfigVerboseError_Matched(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" && r.URL.RawQuery == "id=%27" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Traceback (most recent call last):\n  File \"app.py\", line 1"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-verbose-error-.env")
	require.Len(t, got, 1)
}

func TestMisconfigDefaultCreds_Succeed(t *testing.T) {
	// Only the admin:admin pair against /login succeeds — the other two
	// /login pairs (test:test, admin:password) fall through to the
	// invalid-credentials response, so exactly one finding is expected.
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == "admin" {
				http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc123"})
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>invalid credentials</html>"))
			return
		}
		if r.URL.Path == "/dashboard" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-default-creds-login")
	require.Len(t, got, 1)
	assert.Equal(t, "critical", got[0].Severity)
}

func TestMisconfigDefaultCreds_Fail(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>invalid credentials</html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-default-creds-")
	assert.Empty(t, got)
}
