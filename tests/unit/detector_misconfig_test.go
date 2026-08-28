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

// TestMisconfigExposedPath_HtpasswdRealHash_Hit and
// TestMisconfigExposedPath_HtpasswdSPAFallback_NoFinding lock in a real,
// live-found false-positive fix: the .htpasswd rule's keyword used to be a
// bare ":", which any HTTP-200 catch-all response (e.g. an SPA's
// index.html fallback for unmatched paths) trivially contains somewhere in
// its own markup — found against a live Juice Shop instance (see
// docs/20-setup-testing-targets.md). The keywords are now real htpasswd
// hash-format markers instead.
func TestMisconfigExposedPath_HtpasswdRealHash_Hit(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.htpasswd" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("admin:$apr1$SXBrCpTP$FhrjmwCTf.6UbYEHnPa1O0"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-exposed-path-.htpasswd")
	require.Len(t, got, 1)
	assert.Equal(t, "high", got[0].Severity)
}

func TestMisconfigExposedPath_HtpasswdSPAFallback_NoFinding(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		// An SPA-style catch-all: HTTP 200 for any unmatched path, body is
		// the same index.html shell every time — real markup contains a
		// bare ":" (e.g. inside a URL) but no real htpasswd hash format.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><link href="https://fonts.googleapis.com"></head></html>`))
	})

	got := withPrefix(findings, "misconfig-exposed-path-.htpasswd")
	assert.Empty(t, got)
}

// TestMisconfigDirListing_SubpathHit locks in the real gap Future
// Enhancement #4 closes: templates/nuclei-samples/dvwa-php/dir-listing.yaml
// only checks root, but DVWA's actual directory listing lives at /docs/ —
// misconfig.Detector must find it on its own, without any template loaded.
func TestMisconfigDirListing_SubpathHit(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/docs/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><title>Index of /docs</title><body>Index of /docs</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-dir-listing-")
	require.Len(t, got, 1)
	assert.Equal(t, "misconfig-dir-listing-docs", got[0].ID)
	assert.Equal(t, "low", got[0].Severity)
	assert.Equal(t, "high", got[0].Confidence)
}

// TestMisconfigDirListing_CaseInsensitiveMarker proves the check matches
// directory-listing banners regardless of case — real servers don't all
// render "Index of /" with that exact casing, and the sample YAML template
// this mirrors already matches case-insensitively.
func TestMisconfigDirListing_CaseInsensitiveMarker(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/uploads/" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("INDEX OF /UPLOADS"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	got := withPrefix(findings, "misconfig-dir-listing-")
	require.Len(t, got, 1)
	assert.Equal(t, "misconfig-dir-listing-uploads", got[0].ID)
}

// TestMisconfigDirListing_NoMarker_NoFinding mirrors the ExposedPaths
// false-positive-safety tests: a 200 response alone (no directory-listing
// banner in the body) must not be flagged.
func TestMisconfigDirListing_NoMarker_NoFinding(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Nothing to see here</html>"))
	})

	got := withPrefix(findings, "misconfig-dir-listing-")
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
