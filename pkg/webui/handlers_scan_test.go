package webui

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/recon"
)

// newTestServer wraps a real Server's handler chain (routes + CSRF +
// non-loopback-auth middleware) in an httptest.Server — the same
// "httptest.Server as the real target" pattern tests/unit/engine_test.go
// already establishes, applied here to the web UI itself.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	// Isolate defaultWebTemplateDirs' templatesync.DefaultSyncDir() lookup
	// from this machine's real synced-corpus state — without this, a
	// machine that has actually run 'hackerfive templates sync' (this repo's
	// own dev environment has, from Week 19's live verification) would have
	// every test scan here load the full ~3469-template synced corpus
	// instead of just the bundled dir, making tests slow and dependent on
	// real environment state rather than hermetic. os.UserConfigDir() only
	// honors XDG_CONFIG_HOME on Linux — on Darwin it's always
	// $HOME/Library/Application Support, so HOME must be overridden too
	// (found 2026-08-31: XDG_CONFIG_HOME alone silently did nothing on a
	// macOS dev machine that had ever run a real sync, and this test timed
	// out against the real 3469-template corpus instead).
	tmpHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpHome)
	t.Setenv("HOME", tmpHome)

	srv, err := New(Options{Host: "127.0.0.1", Port: 0})
	require.NoError(t, err)
	srv.handlers.baseCtx = context.Background() // ListenAndServe normally sets this; bypassed here since we never call it

	ts := httptest.NewServer(srv.httpServer.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func cookieValue(t *testing.T, jar *cookiejar.Jar, rawURL, name string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// TestEndToEnd_StartScan_ProducesRealFindings drives the whole flow a real
// browser session would: GET the form for a CSRF cookie, POST a scan against
// a real httptest target, then poll GET /scans/{id} until the background
// scan finishes and its real finding appears.
func TestEndToEnd_StartScan_ProducesRealFindings(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // no security headers -> misconfig findings
	}))
	t.Cleanup(target.Close)

	ts := newTestServer(t)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal, "GET / must set a CSRF cookie")

	form := url.Values{
		"csrf_token":    {csrfVal},
		"target":        {target.URL},
		"run_misconfig": {"on"},
		"rate_limit":    {"50"},
		"concurrency":   {"5"},
		"authorized":    {"on"},
	}
	resp, err = client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))

	jobURL := resp.Header.Get("HX-Push-Url")
	require.NotEmpty(t, jobURL, "POST /scans must set HX-Push-Url so the browser's address bar points at the real job")
	require.True(t, strings.HasPrefix(jobURL, "/scans/"))

	// Polls the export endpoint directly rather than scanning the HTML page's
	// text for "misconfig"/"done" — the page now also carries those exact
	// substrings before the scan actually finishes (sse-close="done" in the
	// markup; a "running: misconfig" phase badge and a "running detector:
	// misconfig" log line once the detector starts, both real, both wanted),
	// so a loose substring check on the page would pass prematurely. A real
	// finding in the exported JSON is the actual signal this test wants.
	require.Eventually(t, func() bool {
		r, err := client.Get(ts.URL + jobURL + "/export.json")
		if err != nil {
			return false
		}
		b, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			return false
		}
		return strings.Contains(string(b), `"type": "misconfig"`)
	}, 5*time.Second, 50*time.Millisecond, "expected a real misconfig finding once the background scan finishes")

	// Export must produce real JSON output from the same findings.
	exportResp, err := client.Get(ts.URL + jobURL + "/export.json")
	require.NoError(t, err)
	exportBody, err := io.ReadAll(exportResp.Body)
	require.NoError(t, err)
	require.NoError(t, exportResp.Body.Close())
	assert.Contains(t, string(exportBody), `"type": "misconfig"`)

	// A job already finished by the time /events is hit must return its
	// final state immediately, not hang open.
	eventsResp, err := client.Get(ts.URL + jobURL + "/events")
	require.NoError(t, err)
	eventsBody, err := io.ReadAll(eventsResp.Body)
	require.NoError(t, err)
	require.NoError(t, eventsResp.Body.Close())
	assert.Contains(t, string(eventsBody), "event: done")
}

func TestStartScan_MissingCSRFCookie_Rejected(t *testing.T) {
	ts := newTestServer(t)

	form := url.Values{"csrf_token": {"whatever"}, "target": {"http://example.com"}, "run_misconfig": {"on"}, "authorized": {"on"}}
	resp, err := http.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestStartScan_MissingAuthorizationCheckbox_RerendersFormWithError(t *testing.T) {
	ts := newTestServer(t)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	resp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)

	form := url.Values{
		"csrf_token":    {csrfVal},
		"target":        {"http://example.com"},
		"run_misconfig": {"on"},
		// "authorized" deliberately omitted
	}
	resp, err = client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	assert.Contains(t, string(body), "authorized to scan")
	assert.Contains(t, string(body), "example.com", "the form must echo back what the operator already typed, not lose it")
}

func TestScanStatus_UnknownJobID_404(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/scans/does-not-exist")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestScanCatchup_UnknownJobID_404 confirms the new /catchup route (the
// htmx:sseOpen-triggered re-sync, added to close the SSE-subscription race
// where a fast job can finish before the browser's own connection opens)
// 404s the same way every other job-scoped route already does.
func TestScanCatchup_UnknownJobID_404(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/scans/does-not-exist/catchup")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestScanCatchup_RendersCurrentPhaseAndReconResult_AsOOBSwaps is the direct
// regression test for the SSE-subscription-race fix: it builds a job whose
// state (phase + a real ReconResult) was set entirely before any client ever
// subscribed — exactly what a fast job racing ahead of a browser's SSE
// connection looks like — then confirms /catchup's response carries that
// current state as an "innerHTML:#selector"-style OOB swap targeting
// #progress/#recon-results specifically, not a same-id outerHTML swap: the
// latter would replace those elements with new nodes, detaching the SSE
// extension's already-bound sse-swap listener from the live page.
func TestScanCatchup_RendersCurrentPhaseAndReconResult_AsOOBSwaps(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.SetRunning()
	job.SetPhase("misconfig")
	job.SetReconResult(&recon.ReconResult{
		Target: "https://example.com",
		Hosts:  []recon.HostFact{{Host: "example.com", Source: "httpx", Confidence: recon.ConfidenceHigh}},
	})
	h.store.Add(job)

	resp, err := http.Get(ts.URL + "/scans/job1/catchup")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	html := string(body)
	assert.Contains(t, html, `hx-swap-oob="innerHTML:#progress"`, "must target #progress's content only, never replace the element itself")
	assert.Contains(t, html, `hx-swap-oob="innerHTML:#recon-results"`, "must target #recon-results' content only, never replace the element itself")
	assert.NotContains(t, html, `id="progress"`, "must not re-emit an element with this id — that would be a second #progress node in the DOM after an outerHTML-style swap")
	assert.NotContains(t, html, `id="recon-results"`)
	assert.Contains(t, html, "running: misconfig")
	assert.Contains(t, html, "example.com")
}

func TestSplitCSV(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, splitCSV(" a, b ,,"))
	assert.Nil(t, splitCSV(""))
}

func TestParseHeaderLines(t *testing.T) {
	got, err := parseHeaderLines("Cookie: a=b; c=d\nX-Custom:value\n")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"Cookie": "a=b; c=d", "X-Custom": "value"}, got)
}

func TestParseHeaderLines_MissingColon_Errors(t *testing.T) {
	_, err := parseHeaderLines("not-a-header-line")
	assert.Error(t, err)
}
