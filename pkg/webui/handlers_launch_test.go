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

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// newTestServerHandlers is newTestServer's (handlers_scan_test.go) sibling —
// same construction, but also returns *handlers so a test can inject a
// *Job directly into h.store (with a recon result already set) without
// running a real recon.Run.
func newTestServerHandlers(t *testing.T) (*httptest.Server, *handlers) {
	t.Helper()
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

func newTestJobWithRecon(id string, result *recon.ReconResult) *Job {
	j := newJob(id, "https://example.com", noopFindingRender, noopLogRender, noopProgressRender)
	j.SetReconResult(result)
	j.MarkDone(nil)
	return j
}

// fixtureReconResult is a hand-built ReconResult covering every fact type
// the results page renders — used instead of a real recon.Run so tests
// don't need real ProjectDiscovery binaries in CI.
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

func TestBucketMatchedCapabilities(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{
		ID: "root",
		Children: []*agenttask.PlanNode{{
			ID: "host:example.com",
			Children: []*agenttask.PlanNode{
				{ID: "l1", Detector: "misconfig", Status: agenttask.StatusPending, Rationale: "tech fact \"OpenResty\" matched registry capability \"misconfig\""},
				{ID: "l2", Detector: "idor", Status: agenttask.StatusPending, Rationale: "tech fact \"OpenResty\" matched registry capability \"idor\""},
				{ID: "l3", Detector: "authbypass", Status: agenttask.StatusPending},
				{ID: "l4", Detector: "ssrf", Status: agenttask.StatusPending},
				{ID: "l5", Detector: "php-detect", Status: agenttask.StatusPending},                                                                                // a template-tag match
				{ID: "l6", Detector: "misconfig", Status: agenttask.StatusPending, Rationale: "tech fact \"OpenResty\" matched registry capability \"misconfig\""}, // duplicate leaf+rationale, must not double-count either
				{ID: "l6b", Detector: "misconfig", Status: agenttask.StatusPending, Rationale: "tech fact \"nginx\" matched registry capability \"misconfig\""},    // distinct rationale for the same detector, must accumulate
				{ID: "l7", Status: agenttask.StatusUnresolved, Rationale: "unmatched tech fact"},
			},
		}},
	}}

	ready, needsInput, unsupported, rationales := bucketMatchedCapabilities(tree)
	assert.Equal(t, []string{"misconfig"}, ready)
	assert.ElementsMatch(t, []string{"idor", "authbypass"}, needsInput)
	assert.ElementsMatch(t, []string{"ssrf", "php-detect"}, unsupported)
	assert.Equal(t, []string{
		"tech fact \"OpenResty\" matched registry capability \"misconfig\"",
		"tech fact \"nginx\" matched registry capability \"misconfig\"",
	}, rationales["misconfig"], "must accumulate distinct rationales for one detector, deduplicated, without double-counting the repeated one")
	assert.Equal(t, []string{"tech fact \"OpenResty\" matched registry capability \"idor\""}, rationales["idor"])
	assert.Empty(t, rationales["authbypass"], "a leaf with no rationale set must not add an empty string")

	suggestions := suggestedDetectorNames(tree, nil)
	assert.ElementsMatch(t, []string{"misconfig", "idor", "authbypass", "ssrf", "php-detect"}, suggestions)

	excluded := suggestedDetectorNames(tree, map[string]bool{"misconfig": true})
	assert.NotContains(t, excluded, "misconfig", "a detector already selected to run this scan must not also appear as a suggestion")
	assert.ElementsMatch(t, []string{"idor", "authbypass", "ssrf", "php-detect"}, excluded)
}

// TestScanStatus_RendersReconResultTablesFromFixture covers the results
// page's recon tables (hosts/endpoints/tech-stack/out-of-scope/warnings) —
// coverage the now-retired recon_status.html's own tests used to give,
// preserved here since ScanStatusData now renders the same tables from a
// Job's ReconResult.
func TestScanStatus_RendersReconResultTablesFromFixture(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newTestJobWithRecon("job1", fixtureReconResult())
	h.store.Add(job)

	resp, err := http.Get(ts.URL + "/scans/job1")
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
}

func TestLaunchForm_RendersDefaults(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, `name="run_recon"`)
	assert.Contains(t, html, `name="run_misconfig"`)
	assert.Contains(t, html, `name="run_idor"`)
	assert.Contains(t, html, `name="run_authbypass"`)
	assert.Contains(t, html, `name="target"`)
}

// TestStartLaunch_ReconOnly_PopulatesReconResultAndRendersTables runs the
// recon phase alone (no detector checked) against a real local target and
// confirms the results page shows the real hosts/tech-stack tables — the
// "recon-only" path the redesign is meant to still support (doc14 Step 6).
func TestStartLaunch_ReconOnly_PopulatesReconResultAndRendersTables(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(targetSrv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	form := url.Values{
		"csrf_token": {csrfVal},
		"target":     {targetSrv.URL},
		"run_recon":  {"on"},
		"depth":      {"passive"}, // no active binaries needed, fast and hermetic
		"authorized": {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	redirect := resp.Header.Get("HX-Push-Url")
	require.Regexp(t, `^/scans/[0-9a-f]+$`, redirect)

	require.Eventually(t, func() bool {
		r, err := client.Get(ts.URL + redirect)
		if err != nil {
			return false
		}
		b, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			return false
		}
		// Deliberately not "status-badge\">done" — a completed wave (e.g.
		// wave0) renders that exact same badge text long before the whole
		// job does; "recon complete:" is the log line runLaunchRecon emits
		// only once SetReconResult has actually landed.
		return strings.Contains(string(b), "recon complete:")
	}, 15*time.Second, 100*time.Millisecond, "expected the recon-only job's recon phase to finish")

	r, err := client.Get(ts.URL + redirect)
	require.NoError(t, err)
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, r.Body.Close())
	html := string(body)

	assert.Contains(t, html, "Recon Results")
	assert.Contains(t, html, "recon complete:")

	_ = h // silence unused-var if no direct use beyond newTestServerHandlers' construction
}

func TestStartLaunch_UncheckedDetectorTab_NotRunSilently(t *testing.T) {
	ts := newTestServer(t)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(targetSrv.Close)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)

	// authbypass left unchecked, with no protected_paths filled in — must
	// not produce a validation error, it's simply not run.
	form := url.Values{
		"csrf_token":    {csrfVal},
		"target":        {targetSrv.URL},
		"run_misconfig": {"on"},
		"authorized":    {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
}

func TestStartLaunch_CheckedButInvalidTab_RerendersWithErrorNotSilentSkip(t *testing.T) {
	ts := newTestServer(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)

	// authbypass checked, but protected_paths deliberately left empty.
	form := url.Values{
		"csrf_token":     {csrfVal},
		"target":         {"http://example.com"},
		"run_authbypass": {"on"},
		"auth_token":     {"tok"},
		"authorized":     {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	assert.Contains(t, string(body), "authbypass:", "a checked-but-invalid detector must produce a visible error, not a silent no-op")
}

func TestStartLaunch_NothingSelected_RerendersWithError(t *testing.T) {
	ts := newTestServer(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)

	form := url.Values{
		"csrf_token": {csrfVal},
		"target":     {"http://example.com"},
		"authorized": {"on"},
		// run_recon and every run_<detector> deliberately omitted
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	assert.Contains(t, string(body), "select recon and/or at least one detector")
}

func TestLaunchTargetScheme(t *testing.T) {
	assert.Equal(t, "https://example.com", launchTargetScheme("example.com"))
	assert.Equal(t, "http://example.com", launchTargetScheme("http://example.com"))
	assert.Equal(t, "https://127.0.0.1:8888", launchTargetScheme("127.0.0.1:8888"))
}

// TestSnapshotData_FindingsAndLogsRenderNewestFirst guards the "Scan
// Activity" newest-on-top redesign (doc14 Step 6): the initial render must
// already match the order live SSE appends (hx-swap="afterbegin") produce.
func TestSnapshotData_FindingsAndLogsRenderNewestFirst(t *testing.T) {
	_, h := newTestServerHandlers(t)

	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender)
	job.AppendFinding(detectors.Finding{ID: "first"})
	job.AppendFinding(detectors.Finding{ID: "second"})
	job.AppendLog("info", "first-log")
	job.AppendLog("info", "second-log")

	data := h.snapshotData(job)

	findingsHTML := string(data.FindingRowsHTML)
	assert.Less(t, strings.Index(findingsHTML, "second"), strings.Index(findingsHTML, "first"), "the most recently appended finding must render first")

	logsHTML := string(data.LogLinesHTML)
	assert.Less(t, strings.Index(logsHTML, "second-log"), strings.Index(logsHTML, "first-log"), "the most recently appended log line must render first")
}
