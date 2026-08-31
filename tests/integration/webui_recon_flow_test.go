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

// TestWebUIReconAndPlanPreview_AgainstCRAPI drives the real HTTP recon ->
// plan-preview flow (GET /recon -> POST /recon -> poll GET /recon/{id} ->
// GET /plan-preview) against a real, running webui.Server and real crAPI —
// closing the gap doc14 Step 4's own Verification section named honestly
// ("no browser-automation tool available in this environment... a full
// visual pass is still worth doing manually before considering this fully
// done"). Not a browser/visual test — a real end-to-end HTTP regression
// test replacing that session's ad hoc curl run. Opt-in via CRAPI_BASE_URL,
// same convention every other live-target test in this package uses.
func TestWebUIReconAndPlanPreview_AgainstCRAPI(t *testing.T) {
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
		resp, err := client.Get(base + "/recon")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "webui server never became reachable on %s", base)

	// The double-submit CSRF cookie GET /recon just set carries the same
	// value the form's hidden csrf_token field would — no need to parse
	// the HTML to extract it (pkg/webui/csrf.go's csrfToken).
	reconURL, err := url.Parse(base)
	require.NoError(t, err)
	var csrfToken string
	for _, c := range jar.Cookies(reconURL) {
		if c.Name == "hf_csrf" {
			csrfToken = c.Value
		}
	}
	require.NotEmpty(t, csrfToken, "expected GET /recon to set the hf_csrf cookie")

	form := url.Values{
		"target":      {target},
		"depth":       {"active"},
		"rate_limit":  {"50"},
		"concurrency": {"25"},
		"csrf_token":  {csrfToken},
	}
	postResp, err := client.PostForm(base+"/recon", form)
	require.NoError(t, err)
	postBody, err := io.ReadAll(postResp.Body)
	require.NoError(t, postResp.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, postResp.StatusCode, "POST /recon failed: %s", postBody)

	pushURL := postResp.Header.Get("HX-Push-Url")
	require.NotEmpty(t, pushURL, "expected startRecon to set HX-Push-Url with the new job's path")
	jobID := strings.TrimPrefix(pushURL, "/recon/")
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
		if strings.Contains(statusBody, `class="error"`) {
			t.Fatalf("recon job %s failed: %s", jobID, statusBody)
		}
		return strings.Contains(statusBody, "Preview Plan")
	}, 3*time.Minute, 2*time.Second, "recon job %s never reached done (last body: %s)", jobID, statusBody)

	require.Contains(t, statusBody, "OpenResty", "expected the real recon status page to render crAPI's OpenResty tech fact")

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
