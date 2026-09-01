//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/webui"
)

// freeLoopbackPort finds an unused TCP port on 127.0.0.1 by binding then
// immediately releasing it — a small, accepted TOCTOU race (another
// process could grab the same port before webui.New's own listener does),
// standard practice for tests that need a real, ephemeral HTTP server.
func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	return port
}

// TestWebUILaunchReconAndPlanPreview_AgainstCRAPI drives the real HTTP
// unified-launch recon flow (GET / -> POST /scans with run_recon=on and no
// detectors checked -> poll GET /scans/{id} -> GET /plan-preview) against a
// real, running webui.Server and real crAPI. Updated 2026-09-01 for the
// unified-launch-page redesign (doc14 Step 6): recon is no longer a separate
// /recon page/route, it's an optional phase of the same Job a detector scan
// uses — this test now exercises that phase in isolation (no detector
// checkboxes), which is the exact "recon-only" path the redesign is meant to
// still support. Opt-in via CRAPI_BASE_URL, same convention every other
// live-target test in this package uses.
func TestWebUILaunchReconAndPlanPreview_AgainstCRAPI(t *testing.T) {
	target := os.Getenv("CRAPI_BASE_URL")
	if target == "" {
		t.Skip("set CRAPI_BASE_URL to run this test (e.g. http://localhost:8888)")
	}

	port := freeLoopbackPort(t)
	srv, err := webui.New(webui.Options{Host: "127.0.0.1", Port: port})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- srv.ListenAndServe(ctx) }()
	defer func() {
		cancel()
		select {
		case <-serveErrCh:
		case <-time.After(15 * time.Second):
			t.Log("webui server did not shut down within 15s of context cancellation")
		}
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	require.Eventually(t, func() bool {
		resp, err := client.Get(base + "/")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "webui server never became reachable on %s", base)

	// The double-submit CSRF cookie GET / just set carries the same value
	// the form's hidden csrf_token field would — no need to parse the HTML
	// to extract it (pkg/webui/csrf.go's csrfToken).
	homeURL, err := url.Parse(base)
	require.NoError(t, err)
	var csrfToken string
	for _, c := range jar.Cookies(homeURL) {
		if c.Name == "hf_csrf" {
			csrfToken = c.Value
		}
	}
	require.NotEmpty(t, csrfToken, "expected GET / to set the hf_csrf cookie")

	form := url.Values{
		"target":      {target},
		"run_recon":   {"on"},
		"depth":       {"active"},
		"rate_limit":  {"50"},
		"concurrency": {"25"},
		"authorized":  {"on"},
		"csrf_token":  {csrfToken},
		// deliberately no run_misconfig/run_idor/run_authbypass — this run
		// exercises the recon-only path the unified page still supports.
	}
	postResp, err := client.PostForm(base+"/scans", form)
	require.NoError(t, err)
	postBody, err := io.ReadAll(postResp.Body)
	require.NoError(t, postResp.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, postResp.StatusCode, "POST /scans failed: %s", postBody)

	pushURL := postResp.Header.Get("HX-Push-Url")
	require.NotEmpty(t, pushURL, "expected startLaunch to set HX-Push-Url with the new job's path")
	jobID := strings.TrimPrefix(pushURL, "/scans/")
	require.NotEmpty(t, jobID)

	var statusBody string
	require.Eventually(t, func() bool {
		resp, err := client.Get(base + pushURL)
		if err != nil {
			return false
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return false
		}
		statusBody = string(body)
		// Deliberately not "status-badge\">done" — a completed wave (e.g.
		// wave0) renders that exact same badge text long before the whole
		// job does; "recon complete:" is the log line runLaunchRecon emits
		// only once the recon phase has actually finished (found the hard
		// way: this exact false-positive match against a mid-run job).
		return strings.Contains(statusBody, "recon complete:")
	}, 3*time.Minute, 2*time.Second, "job %s's recon phase never completed (last body: %s)", jobID, statusBody)

	require.Contains(t, statusBody, "OpenResty", "expected the real scan status page to render crAPI's OpenResty tech fact from its recon phase")

	planResp, err := client.Get(base + "/plan-preview?job=" + jobID)
	require.NoError(t, err)
	planBody, err := io.ReadAll(planResp.Body)
	require.NoError(t, planResp.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, planResp.StatusCode)
	html := string(planBody)

	require.Contains(t, html, "Read-only")
	require.Contains(t, html, "misconfig")
	require.Contains(t, html, "idor")
	require.Contains(t, html, "authbypass")
	// Which tech fact(s) render as the unresolved leaf(s) varies run-to-run
	// (live httpx tech-detect against a live container isn't perfectly
	// deterministic — found empirically running the sibling
	// TestReconAndPlan_AgainstCRAPI in this same package), so this only
	// asserts the structural guarantee — Decision 6's "a leaf the registry
	// can't match stays visible" promise renders as a real badge on a real
	// page — not which exact tech name triggers it.
	require.Contains(t, html, "badge-unresolved")
}
