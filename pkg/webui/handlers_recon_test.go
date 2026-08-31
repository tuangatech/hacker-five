package webui

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/recon"
)

// newTestServerHandlers is newTestServer's (handlers_scan_test.go) sibling —
// same construction, but also returns *handlers so a test can inject a
// ReconJob directly into h.reconStore without running a real recon.Run.
func newTestServerHandlers(t *testing.T) (*httptest.Server, *handlers) {
	t.Helper()
	// Isolates both templatesync.DefaultSyncDir() and toolsync.DefaultInstallDir()
	// from this machine's real state — os.UserConfigDir() only honors
	// XDG_CONFIG_HOME on Linux, always $HOME/Library/Application Support on
	// Darwin, so HOME must be overridden too (same fix handlers_scan_test.go's
	// newTestServer needed after a real `hackerfive templates sync` run on
	// this dev machine broke its own isolation the same way).
	tmpHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpHome)
	t.Setenv("HOME", tmpHome)

	srv, err := New(Options{Host: "127.0.0.1", Port: 0})
	require.NoError(t, err)
	srv.handlers.baseCtx = context.Background()

	ts := httptest.NewServer(srv.httpServer.Handler)
	t.Cleanup(ts.Close)
	return ts, srv.handlers
}

// fixtureReconResult is a hand-built ReconResult covering every fact type
// recon_status.html renders — used instead of a real recon.Run so this test
// doesn't need real ProjectDiscovery binaries in CI (Step 3b already
// live-verified the real recon.Run/registry.Resolve path; this test checks
// rendering, not recon correctness).
func fixtureReconResult() *recon.ReconResult {
	return &recon.ReconResult{
		Target: "https://example.com",
		Hosts: []recon.HostFact{
			{
				Host:       "example.com",
				Ports:      []recon.PortFact{{Port: 443, Protocol: "tcp", Service: "https", Source: "naabu"}},
				Notes:      []string{"registrar: Example Registrar"},
				Source:     "passive-subdomain",
				Confidence: recon.ConfidenceHigh,
			},
		},
		Endpoints: []recon.EndpointFact{
			{URL: "https://example.com/api/openapi.json", Method: "GET", StatusCode: 200, Source: "probe-common-paths", Confidence: recon.ConfidenceMedium},
		},
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "example.com", Source: "httpx-tech-detect", Confidence: recon.ConfidenceHigh},
		},
		OutOfScope:  []string{"other.example.com"},
		Warnings:    []string{"subfinder binary not found — Wave 1 subdomain enumeration skipped"},
		GeneratedAt: time.Now(),
	}
}

func TestReconStatus_RendersHostsTechWarningsFromFixture(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newReconJob("job1", "https://example.com", "active", "", noopReconProgressRender)
	job.MarkDone(fixtureReconResult(), nil)
	h.reconStore.Add(job)

	resp, err := http.Get(ts.URL + "/recon/job1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, "example.com")
	assert.Contains(t, html, "PHP")
	assert.Contains(t, html, "subfinder binary not found")
	assert.Contains(t, html, "other.example.com")
	assert.Contains(t, html, "/plan-preview?job=job1")
}

func TestReconStatus_GuidedMode_LinksToGuidedScanPlanNotPlanPreview(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newReconJob("job1", "https://example.com", "active", "guided", noopReconProgressRender)
	job.MarkDone(fixtureReconResult(), nil)
	h.reconStore.Add(job)

	resp, err := http.Get(ts.URL + "/recon/job1")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, "/guided-scan/plan?job=job1")
	assert.NotContains(t, html, "/plan-preview?job=job1")
}

func TestReconStatus_RendersWaveProgress(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newReconJob("job1", "https://example.com", "active", "", noopReconProgressRender)
	job.SetRunning()
	job.SetWaveStatus("wave0", "done")
	job.SetWaveStatus("wave1", "running")
	h.reconStore.Add(job)

	resp, err := http.Get(ts.URL + "/recon/job1")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, "wave0")
	assert.Contains(t, html, "wave1")
}

func TestReconStatus_UnknownJob_404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)

	resp, err := http.Get(ts.URL + "/recon/does-not-exist")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}
