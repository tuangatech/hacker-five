package unit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// TestMisconfigCommentLeak_Hit and TestMisconfigCommentLeak_NoFinding cover
// Phase 2 Step 4's information-disclosure extension
// (docs/11-implementation-plan-ph2.md) — checkCommentLeaks fetches root only
// and flags a debug-leftover pattern inside an actual HTML comment.
func TestMisconfigCommentLeak_Hit(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><!-- TODO: remove before deploy --></body></html>"))
	})

	got := withPrefix(findings, "misconfig-comment-leak")
	require.Len(t, got, 1)
	assert.Equal(t, "low", got[0].Severity)
	assert.Equal(t, "high", got[0].Confidence)
}

func TestMisconfigCommentLeak_NoFinding(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>a real console.log( call in inline JS, not a comment</body></html>"))
	})

	got := withPrefix(findings, "misconfig-comment-leak")
	assert.Empty(t, got, "console.log( outside an HTML comment must not be flagged — see rules.go's CommentLeakPatterns doc comment for why the bare pattern was dropped")
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

// TestMisconfigWAFBlocked_SuppressesContentFindingsButNotBehaviorChecks locks
// in a real live-found false-positive fix: against a real Akamai-fronted
// target, every ExposedPaths probe (including root) came back as an
// identical "Access Denied" block page whose boilerplate text (the echoed
// request path, a "https://errors.edgesuite.net/..." reference link)
// trivially satisfied keyword rules like {Path: "/debug", Keywords:
// ["debug", ...]}, producing a 100% false-positive run — see
// docs/13-implementation-plan-ph4.md's Step 4 live-verification notes. The
// content-dependent checks must be suppressed once a guaranteed-nonexistent
// canary path also comes back with that same block-page shape; checks that
// don't depend on response body content (disallowed-method here) must keep
// working regardless.
func TestMisconfigWAFBlocked_SuppressesContentFindingsButNotBehaviorChecks(t *testing.T) {
	wafBody := []byte(`<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>You don't have permission to access "debug" on this server.<P>Reference #18.abc123<P>https://errors.edgesuite.net/18.abc123</BODY></HTML>`)

	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(wafBody)
	})

	waf := withPrefix(findings, "misconfig-waf-blocked")
	require.Len(t, waf, 1)
	assert.Equal(t, "low", waf[0].Severity)
	assert.Equal(t, "low", waf[0].Confidence)

	assert.Empty(t, withPrefix(findings, "misconfig-exposed-path-"), "exposed-path findings must be suppressed against a uniform WAF block page")
	assert.Empty(t, withPrefix(findings, "misconfig-missing-header-"), "missing-header findings must be suppressed — the checked response is the WAF page, not the real app")

	method := withPrefix(findings, "misconfig-method-put-")
	require.Len(t, method, 1, "PUT-accepted must still fire — disallowed-method checks aren't fooled by content-based WAF suppression")
}

// TestMisconfigWAFBlocked_NotTriggeredBy200Catchall guards the fix's own
// false-positive mode: an SPA-style 200-for-everything catch-all is a
// normal, common, already-tolerated pattern (see
// TestMisconfigExposedPath_CustomNotFoundPage_NoFinding) and must not be
// mistaken for a WAF block page, or real comment-leak/missing-header
// findings on such a target would be silently suppressed too.
func TestMisconfigWAFBlocked_NotTriggeredBy200Catchall(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>SPA shell</body></html>`))
	})
	assert.Empty(t, withPrefix(findings, "misconfig-waf-blocked"), "a 200 catch-all is a normal pattern, not a WAF signal")
}

// TestMisconfigExposedPath_SPAEchoedPathFalsePositive_Suppressed locks in a
// second real live-found false-positive, distinct from the WAF case above:
// a real Next.js SPA (Meesho's www.meesho.com, 2026-08-30) served the exact
// same app shell for every path, HTTP 200, with the requested path echoed
// into a canonical-URL tag — response body length correlated byte-for-byte
// with each requested path's character count. Common short keywords
// ("debug", "admin", "graphql" via a bundled error-reporting SDK's own
// embedded "errors" string) trivially satisfied ExposedPaths rules on every
// probe. The original WAF fix didn't catch this because it only compared
// against the canary when the canary itself looked suspicious (403/401/
// 429/503) — a canary that legitimately returns 200 (this exact SPA
// pattern) was deliberately left unsuppressed, which was too narrow: see
// looksLikeBaselinePage's doc comment for why path-comparative checks
// (exposed-path here) must suppress regardless of baseline status.
func TestMisconfigExposedPath_SPAEchoedPathFalsePositive_Suppressed(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		path := strings.TrimPrefix(r.URL.Path, "/")
		_, _ = fmt.Fprintf(w, `<html><head><link rel="canonical" href="https://example.com/%s"/></head><body>%s</body></html>`,
			path, strings.Repeat("filler content ", 200))
	})

	assert.Empty(t, withPrefix(findings, "misconfig-exposed-path-"),
		`a 200 SPA catch-all that echoes the requested path (e.g. in a canonical-URL tag) must not false-positive just because the echoed text happens to satisfy a keyword rule like {Path: "/debug", Keywords: ["debug"]}`)
}

// TestMisconfigDefaultCreds_CookieOnEveryResponse_NotFlagged locks in the
// other real live-found false positive from the same Meesho run: a
// "critical" successful admin/admin login fired against what the evidence
// itself showed was a 404 routing error ("Cannot POST /admin/login"),
// because the old heuristic treated any Set-Cookie header as proof of
// success — this real production site sets a tracking/session cookie on
// every response regardless of outcome. loginSucceeded now requires a real
// difference from a known-wrong baseline attempt at the same path, not
// just "a cookie showed up."
func TestMisconfigDefaultCreds_CookieOnEveryResponse_NotFlagged(t *testing.T) {
	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		// Every response — including the baseline's known-wrong attempt —
		// gets the same tracking cookie and the same 404, mirroring
		// Meesho's real /admin/login behavior.
		http.SetCookie(w, &http.Cookie{Name: "tracking", Value: "abc123"})
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Cannot POST /admin/login"))
	})

	assert.Empty(t, withPrefix(findings, "misconfig-default-creds-"),
		"a Set-Cookie header present on every response (success or not) must not be treated as evidence of a successful login on its own")
}

// TestMisconfigWAFBlocked_EngagesMidRun_RootChecksStillCaught locks in a
// third real live-found bug from the same Meesho run, distinct from the
// first two: the WAF's blocking is stateful/rate-based, not a static rule
// — the start-of-scan canary probe got through with 200 (so no
// misconfig-waf-blocked note fired, and exposed-path/dir-listing checks
// ran unsuppressed against real 200 responses), but by the time
// checkMissingHeaders fetched root later in the same run, the target had
// started blocking with 403 — reproducing the exact false positive the
// original fix was built to catch, just arriving mid-scan instead of at
// the start. checkCommentLeaks/checkMissingHeaders now re-probe the
// baseline fresh, immediately before evaluating root's response, instead
// of trusting Run's single start-of-scan snapshot.
func TestMisconfigWAFBlocked_EngagesMidRun_RootChecksStillCaught(t *testing.T) {
	var rootOrCanaryCount int32
	wafBody := []byte(`<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>Blocked.<P>Reference #18.abc123<P>https://errors.edgesuite.net/18.abc123</BODY></HTML>`)

	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || strings.Contains(r.URL.Path, "hackerfivebaselinecanary") {
			n := atomic.AddInt32(&rootOrCanaryCount, 1)
			if n == 1 {
				// The very first canary probe — Run's start-of-scan
				// baseline — succeeds normally.
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("<html><body>normal page shell, no CSP header</body></html>"))
				return
			}
			// Every later root/canary probe — i.e. once
			// checkCommentLeaks/checkMissingHeaders re-probe — is
			// WAF-blocked, simulating a WAF that only engages partway
			// through a scan.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(wafBody)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	assert.Empty(t, withPrefix(findings, "misconfig-missing-header-"),
		"missing-header must re-probe the baseline fresh, not rely on Run's stale start-of-scan snapshot, to catch a WAF that only engages partway through a scan")
	assert.Empty(t, withPrefix(findings, "misconfig-comment-leak"))
}

// TestMisconfigWAFBlocked_RootConsistentlyBlockedCanaryConsistentlyOK locks
// in a fourth real live-found bug, distinct from mid-run engagement: five
// consecutive curl pairs against a real Akamai-fronted target (2026-08-30)
// confirmed root ("/") is *consistently* WAF-blocked (403) while a random
// nonexistent path is *consistently* allowed through (200) — not timing
// flakiness, a genuine path-specific WAF rule. No amount of re-probing the
// canary closer in time helps here, because canary and root get
// structurally different treatment from this WAF regardless of when
// they're compared. looksLikeInterceptedPage/looksLikeBaselinePage now
// also recognize the block page by its own content signature
// (knownWAFBlockPageMarkers), independent of any canary comparison.
func TestMisconfigWAFBlocked_RootConsistentlyBlockedCanaryConsistentlyOK(t *testing.T) {
	wafBody := []byte(`<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY><H1>Access Denied</H1>You don't have permission to access "/" on this server.<P>Reference #18.abc123<P>https://errors.edgesuite.net/18.abc123</BODY></HTML>`)

	findings := runMisconfig(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write(wafBody)
			return
		}
		if strings.Contains(r.URL.Path, "hackerfivebaselinecanary") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>normal canary response</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	assert.Empty(t, withPrefix(findings, "misconfig-missing-header-"),
		"a WAF that blocks root specifically (while a canary path sails through) must be caught by content-signature recognition, since baseline comparison alone can't distinguish this from root legitimately having its own real response")
	assert.Empty(t, withPrefix(findings, "misconfig-comment-leak"))
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
