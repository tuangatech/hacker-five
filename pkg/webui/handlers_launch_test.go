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
	"github.com/tuangatech/hacker-five/pkg/scanner"
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
	j := newJob(id, "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
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

	assert.Contains(t, html, `name="run_misconfig"`)
	assert.Contains(t, html, `name="run_idor"`)
	assert.Contains(t, html, `name="run_authbypass"`)
	assert.Contains(t, html, `name="run_ssrf"`)
	assert.Contains(t, html, `name="run_businesslogic"`)
	assert.Contains(t, html, `name="allow_writes"`)
	assert.Contains(t, html, `name="target"`)
	assert.NotContains(t, html, `name="run_recon"`, "recon always runs — no opt-out control shown")
	assert.NotContains(t, html, `name="depth"`, "recon depth is always full — no picker shown")
	assert.NotContains(t, html, "Recent Scans", "Recent Scans was dropped from the launch page — Scan History nav link covers it")

	// misconfig/idor/authbypass/ssrf default checked — "run whatever recon
	// can support without any input" (2026-09-01); businesslogic stays off,
	// it hard-requires a real token and its AllowWrites checkbox is a
	// deliberate, explicit opt-in (CLAUDE.md).
	assert.Contains(t, html, `name="run_misconfig" checked`)
	assert.Contains(t, html, `name="run_idor" checked`)
	assert.Contains(t, html, `name="run_authbypass" checked`)
	assert.Contains(t, html, `name="run_ssrf" checked`)
	assert.NotContains(t, html, `name="run_businesslogic" checked`)
	assert.NotContains(t, html, `name="allow_writes" checked`)

	assert.NotContains(t, html, "thetavernhouse.com", "the default Target must never point at a real external site")

	// OOB servers default to 2 public ProjectDiscovery servers (2026-09-02,
	// user's explicit choice — docs/discussions.md), not blank — but stay a
	// plain, clearable text field so an operator can opt out for a real
	// third-party engagement.
	assert.Contains(t, html, `value="https://oast.pro,https://oast.live"`)
}

// TestParseLaunchSubmission_SSRFOOBServers_DefaultAndClearable locks in the
// escape hatch for the new non-empty OOB default (2026-09-02): a blank
// oob_servers submission must produce zero OOBServers, never silently fall
// back to the default — the Web UI's only way to opt out is clearing the
// field, unlike the CLI's dedicated --no-oob flag.
func TestParseLaunchSubmission_SSRFOOBServers_DefaultAndClearable(t *testing.T) {
	form := url.Values{
		"target":      {"https://example.com"},
		"authorized":  {"on"},
		"run_ssrf":    {"on"},
		"oob_servers": {""},
		"ssrf_params": {"url"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())

	_, cfgs, errs := parseLaunchSubmission(req)
	require.Empty(t, errs)
	require.Len(t, cfgs, 1)
	assert.Empty(t, cfgs[0].OOBServers, "a blank oob_servers submission must clear OOB, never fall back to a default")
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

// TestParseLaunchSubmission_MultipleDetectorsChecked_TemplatesAttachedOnce
// guards a real bug found live, 2026-09-01: baseCfg used to attach the full
// nuclei/native template corpus to every checked detector's scanner.Config
// identically. Engine.Run fires every loaded template additively alongside
// whichever --detector was selected (by design, for the CLI's one-config-
// per-invocation model) — but runLaunchJob calls scanner.New(cfg).Run()
// once per checked checkbox, so with misconfig+idor+ssrf all checked (now
// the Launch page's own default), the same ~3190 templates fired three
// times against the same target, tripling every template-based Finding and
// every real request sent to the target. Exactly one config must carry
// TemplatePaths.
func TestParseLaunchSubmission_MultipleDetectorsChecked_TemplatesAttachedOnce(t *testing.T) {
	form := url.Values{
		"target":        {"https://example.com"},
		"run_misconfig": {"on"},
		"run_idor":      {"on"},
		"run_ssrf":      {"on"},
		"authorized":    {"on"},
	}
	req := httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, cfgs, errs := parseLaunchSubmission(req)
	require.Empty(t, errs)
	require.Len(t, cfgs, 3)

	withTemplates := 0
	for _, cfg := range cfgs {
		if len(cfg.TemplatePaths) > 0 {
			withTemplates++
		}
	}
	assert.Equal(t, 1, withTemplates, "the template corpus must be attached to exactly one config, never once per checked detector")
	assert.NotEmpty(t, cfgs[0].TemplatePaths, "misconfig is checked first and built first, so it should be the one carrying the templates")
	assert.Equal(t, "misconfig", cfgs[0].Detector)
}

// TestStartLaunch_CheckedButInvalidTab_RerendersWithErrorNotSilentSkip checks
// a field that is NOT recon-fillable (AuthToken — a session token can never
// be recon-derived, per doc14 Step 7's named credential-fields limit) still
// fails immediately at submission time. ProtectedPaths left blank, by
// contrast, is deferred rather than immediately rejected as of Step 7 — see
// TestFillReconFields_Authbypass_ZeroCandidates_SkipsWithLogLine below for
// that case.
// TestStartLaunch_CheckedButInvalidTab_RerendersWithErrorNotSilentSkip checks
// a field that's still genuinely unconditional for authbypass — a malformed
// auth_header_format missing the required "{token}" placeholder. AuthToken
// and ProtectedPaths no longer qualify: AuthToken is skippable (authbypass
// can run its two token-independent checks unauthenticated) and
// ProtectedPaths is deferred to recon, both per doc14 Step 7.
func TestStartLaunch_CheckedButInvalidTab_RerendersWithErrorNotSilentSkip(t *testing.T) {
	ts := newTestServer(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)

	form := url.Values{
		"csrf_token":         {csrfVal},
		"target":             {"http://example.com"},
		"run_authbypass":     {"on"},
		"protected_paths":    {"/admin"},
		"auth_header_format": {"Bearer notoken"},
		"authorized":         {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	assert.Contains(t, string(body), "authbypass:", "a checked-but-invalid detector must produce a visible error, not a silent no-op")
}

// TestStartLaunch_Authbypass_NoToken_DeferredNotRejected confirms authbypass
// can now start with zero token given at all — it narrows to
// checkMissingAuth/checkRateLimitSignal internally (see ValidateOptions'
// SkipAuthTokenRequired doc comment), it doesn't fail outright.
func TestStartLaunch_Authbypass_NoToken_DeferredNotRejected(t *testing.T) {
	ts := newTestServer(t)

	// A real local target, not a real external site: the job this submission
	// spawns runs recon + authbypass's real HTTP checks in the background,
	// outliving this test function — pointing that at a live host (as this
	// test used to, via a literal http://example.com) fires uncontrolled
	// real network requests from the test suite, which is both against this
	// project's "never scan real external hosts" rule and the root cause of
	// CI flakiness traced 2026-09-03 (see TestEndToEnd_StartScan_ProducesRealFindings's
	// comment).
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	form := url.Values{
		"csrf_token":      {csrfVal},
		"target":          {targetSrv.URL},
		"run_authbypass":  {"on"},
		"protected_paths": {"/admin"},
		"authorized":      {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
}

// TestStartLaunch_IDOR_NoToken_DeferredNotRejected is idor's counterpart —
// heuristic mode's signature comparison is still meaningful with no token.
func TestStartLaunch_IDOR_NoToken_DeferredNotRejected(t *testing.T) {
	ts := newTestServer(t)

	// Local target, not a real external site — see the comment on
	// TestStartLaunch_Authbypass_NoToken_DeferredNotRejected above; this one
	// is the specific test that was firing the "idor preview:
	// http://example.com/api/report?id=1" request seen in CI logs.
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

	form := url.Values{
		"csrf_token": {csrfVal},
		"target":     {targetSrv.URL},
		"run_idor":   {"on"},
		"endpoint":   {"/api/report?id={{id}}"},
		"authorized": {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
}

// TestStartLaunch_Businesslogic_MissingAuthToken_FailsImmediately confirms
// businesslogic's AuthToken requirement is never deferred to recon — a
// credential can't be recon-derived, the same permanent limit named for
// idor/authbypass in doc14 Step 7's Design section.
func TestStartLaunch_Businesslogic_MissingAuthToken_FailsImmediately(t *testing.T) {
	ts := newTestServer(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)

	form := url.Values{
		"csrf_token":        {csrfVal},
		"target":            {"http://example.com"},
		"run_businesslogic": {"on"},
		"authorized":        {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	assert.Contains(t, string(body), "businesslogic:")
}

// TestStartLaunch_SSRF_BlankParams_DeferredNotRejected confirms a checked
// ssrf tab with no --ssrf-param typed in succeeds at submission time —
// recon (which always runs) gets a chance to fill SSRFParams before the
// detector actually runs, same deferred-validation shape as idor/authbypass.
func TestStartLaunch_SSRF_BlankParams_DeferredNotRejected(t *testing.T) {
	ts := newTestServer(t)

	// Local target, not a real external site — see the comment on
	// TestStartLaunch_Authbypass_NoToken_DeferredNotRejected above.
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	form := url.Values{
		"csrf_token": {csrfVal},
		"target":     {targetSrv.URL},
		"run_ssrf":   {"on"},
		"authorized": {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
}

// TestStartLaunch_NoDetectorsChecked_StillSucceeds confirms omitting every
// run_<detector> is no longer an error case: recon always runs regardless,
// so there's always something for the job to do (doc14 Step 6 follow-up,
// 2026-09-01 — recon opt-out/depth picker removed from the launch page).
func TestStartLaunch_NoDetectorsChecked_StillSucceeds(t *testing.T) {
	ts := newTestServer(t)

	// Local target, not a real external site — see the comment on
	// TestStartLaunch_Authbypass_NoToken_DeferredNotRejected above; this
	// submission runs recon (always-on) with no detector attached.
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	form := url.Values{
		"csrf_token": {csrfVal},
		"target":     {targetSrv.URL},
		"authorized": {"on"},
		// every run_<detector> deliberately omitted
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode, string(body))
}

func TestLaunchTargetScheme(t *testing.T) {
	assert.Equal(t, "https://example.com", launchTargetScheme("example.com"))
	assert.Equal(t, "http://example.com", launchTargetScheme("http://example.com"))
	assert.Equal(t, "https://127.0.0.1:8888", launchTargetScheme("127.0.0.1:8888"))
}

// TestSnapshotData_FindingsRenderNewestFirst guards the "Scan Activity"
// newest-on-top redesign (doc14 Step 6): the initial render must already
// match the order live SSE appends (hx-swap="afterbegin") produce.
func TestSnapshotData_FindingsRenderNewestFirst(t *testing.T) {
	_, h := newTestServerHandlers(t)

	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.AppendFinding(detectors.Finding{ID: "first"})
	job.AppendFinding(detectors.Finding{ID: "second"})

	data := h.snapshotData(job)

	findingsHTML := string(data.FindingRowsHTML)
	assert.Less(t, strings.Index(findingsHTML, "second"), strings.Index(findingsHTML, "first"), "the most recently appended finding must render first")
}

// TestSnapshotData_LogsRenderOldestFirst guards the Logs panel's
// chronological order (old on top, new at bottom, auto-scrolled to the
// bottom by scan_status.html's own script): the initial render must
// already match the order live SSE appends (hx-swap="beforeend") produce,
// so a page load and a live update never disagree.
func TestSnapshotData_LogsRenderOldestFirst(t *testing.T) {
	_, h := newTestServerHandlers(t)

	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.AppendLog("info", "first-log")
	job.AppendLog("info", "second-log")

	data := h.snapshotData(job)

	logsHTML := string(data.LogLinesHTML)
	assert.Less(t, strings.Index(logsHTML, "first-log"), strings.Index(logsHTML, "second-log"), `the earliest log line must render first, matching hx-swap="beforeend"`)
}

// TestScanStatus_LogsPanel_HasCopyButtonAndAppendsAtBottom confirms the
// full-page render actually wires the copy-to-clipboard button and the
// bottom-appending SSE swap, not just snapshotData's own ordering (covered
// separately above) — a real GET /scans/{id} render, same as
// TestScanStatus_RendersReconResultTablesFromFixture's pattern.
func TestScanStatus_LogsPanel_HasCopyButtonAndAppendsAtBottom(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.AppendLog("info", "first-log")
	job.AppendLog("info", "second-log")
	h.store.Add(job)

	resp, err := http.Get(ts.URL + "/scans/job1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, `id="copy-logs-btn"`, "the copy-to-clipboard button must be present")
	assert.Contains(t, html, `sse-swap="log" hx-swap="beforeend"`, "live log lines must append at the bottom, not the top")
	assert.Less(t, strings.Index(html, "first-log"), strings.Index(html, "second-log"), "the initial render must already be oldest-first, matching the live beforeend order")
}

// logMessages flattens job's logs into "level: msg" strings for substring
// assertions below.
func logMessages(job *Job) []string {
	logs := job.Snapshot().Logs
	msgs := make([]string, len(logs))
	for i, l := range logs {
		msgs[i] = l.Level + ": " + l.Msg
	}
	return msgs
}

func containsSubstring(msgs []string, substr string) bool {
	for _, m := range msgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

// TestFillReconFields_IDOR_ZeroCandidates_SkipsWithLogLine and its siblings
// below cover doc14 Step 7's recon-derived-fill design directly against
// fillReconFields — no HTTP submission or real recon.Run needed, since the
// function only reads job.Snapshot().ReconResult (set here via
// SetReconResult, mirroring what runLaunchRecon does for a real job).
func TestFillReconFields_IDOR_ZeroCandidates_SkipsWithLogLine(t *testing.T) {
	forceNoLLMTier(t)
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "idor",
		AuthToken:   "tok",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	assert.Empty(t, got)
	assert.True(t, containsSubstring(logMessages(job), "idor: skipped"), "logs: %v", logMessages(job))
}

// TestFillReconFields_IDOR_ZeroCandidates_LLMFallbackSuggestsEndpoint_LoggedNotApplied
// confirms I4's field-suggestion resolution actually fires on a genuine
// zero-candidate miss when a local tier is configured, and — the invariant
// this whole feature hinges on, matching pkg/mcpserver's own
// resolveFieldSuggestions posture — that the suggestion is logged only,
// never applied to cfg: the detector still skips, EndpointTemplate stays
// blank, and the operator has to copy the value into the form themselves.
func TestFillReconFields_IDOR_ZeroCandidates_LLMFallbackSuggestsEndpoint_LoggedNotApplied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"suggested_value\":\"/api/orders/{{id}}\",\"rationale\":\"common REST pattern\"}"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HACKERFIVE_LOCAL_MODEL_URL", srv.URL)
	t.Setenv("OPENROUTER_API_KEY", "")

	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "idor",
		AuthToken:   "tok",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	assert.Empty(t, got, "an LLM-suggested endpoint must never be auto-applied — the detector still skips")
	logs := logMessages(job)
	assert.True(t, containsSubstring(logs, "idor: skipped"), "logs: %v", logs)
	assert.True(t, containsSubstring(logs, "LLM fallback suggests"), "logs: %v", logs)
	assert.True(t, containsSubstring(logs, "/api/orders/{{id}}"), "logs: %v", logs)
	assert.True(t, containsSubstring(logs, "not applied automatically"), "logs: %v", logs)
}

func TestFillReconFields_IDOR_OneCandidate_AutoFills(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{{URL: "https://example.com/orders/123"}},
	})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "idor",
		AuthToken:   "tok",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1)
	assert.Equal(t, "/orders/{{id}}", got[0].EndpointTemplate)
	assert.True(t, containsSubstring(logMessages(job), "idor: using recon-derived endpoint"), "logs: %v", logMessages(job))
}

// TestFillReconFields_IDOR_OneCandidate_AutoFills_NoToken is a regression
// test for a real bug caught live 2026-09-01: fillReconFields's own trailing
// cfg.Validate() call didn't carry SkipAuthTokenRequired through, so a
// successfully auto-filled idor config with no token was still dropped with
// a misleading "requires --auth-token" error — the exact thing
// SkipAuthTokenRequired was added to allow.
func TestFillReconFields_IDOR_OneCandidate_AutoFills_NoToken(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{{URL: "https://example.com/orders/123"}},
	})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "idor",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1, "logs: %v", logMessages(job))
	assert.Equal(t, "/orders/{{id}}", got[0].EndpointTemplate)
}

func TestFillReconFields_IDOR_MultipleCandidates_SkipsWithoutAutoPick(t *testing.T) {
	forceNoLLMTier(t)
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{
			{URL: "https://example.com/orders/123"},
			{URL: "https://example.com/invoices?invoice_id=456"},
		},
	})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "idor",
		AuthToken:   "tok",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	assert.Empty(t, got)
	assert.True(t, containsSubstring(logMessages(job), "recon-derived candidates found, none auto-selected"), "logs: %v", logMessages(job))
}

func TestFillReconFields_IDOR_UserTypedEndpoint_NeverOverwritten(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{{URL: "https://example.com/orders/123"}},
	})

	cfg := scanner.Config{
		Targets:          []string{"https://example.com"},
		Concurrency:      10,
		RateLimit:        10,
		Detector:         "idor",
		AuthToken:        "tok",
		EndpointTemplate: "/manual/{{id}}",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1)
	assert.Equal(t, "/manual/{{id}}", got[0].EndpointTemplate, "a user-typed value must never be overwritten even when a recon candidate also exists")
	assert.False(t, containsSubstring(logMessages(job), "idor: using recon-derived"), "logs: %v", logMessages(job))
}

func TestFillReconFields_Authbypass_ZeroCandidates_SkipsWithLogLine(t *testing.T) {
	forceNoLLMTier(t)
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "authbypass",
		AuthToken:   "tok",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	assert.Empty(t, got)
	assert.True(t, containsSubstring(logMessages(job), "authbypass: skipped"), "logs: %v", logMessages(job))
}

func TestFillReconFields_Authbypass_FillsProtectedLoginLogoutIndependently(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{
			{URL: "https://example.com/admin", StatusCode: http.StatusForbidden},
			{URL: "https://example.com/login"},
			{URL: "https://example.com/logout"},
		},
	})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "authbypass",
		AuthToken:   "tok",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1)
	assert.Equal(t, []string{"/admin"}, got[0].ProtectedPaths)
	assert.Equal(t, []string{"/login"}, got[0].LoginPaths)
	assert.Equal(t, []string{"/logout"}, got[0].LogoutPaths)
}

// TestFillReconFields_Authbypass_FillsProtectedPaths_NoToken is authbypass's
// counterpart to the idor regression test above — same real bug, same fix.
func TestFillReconFields_Authbypass_FillsProtectedPaths_NoToken(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{{URL: "https://example.com/admin", StatusCode: http.StatusForbidden}},
	})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "authbypass",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1, "logs: %v", logMessages(job))
	assert.Equal(t, []string{"/admin"}, got[0].ProtectedPaths)
}

func TestFillReconFields_Authbypass_UserTypedProtectedPaths_StillFillsBlankLoginPaths(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{{URL: "https://example.com/login"}},
	})

	cfg := scanner.Config{
		Targets:        []string{"https://example.com"},
		Concurrency:    10,
		RateLimit:      10,
		Detector:       "authbypass",
		AuthToken:      "tok",
		ProtectedPaths: []string{"/secret"},
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1)
	assert.Equal(t, []string{"/secret"}, got[0].ProtectedPaths, "a user-typed value must never be overwritten")
	assert.Equal(t, []string{"/login"}, got[0].LoginPaths)
}

func TestFillReconFields_SSRF_ZeroCandidates_SkipsWithLogLine(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "ssrf",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	assert.Empty(t, got)
	assert.True(t, containsSubstring(logMessages(job), "ssrf: skipped"), "logs: %v", logMessages(job))
}

func TestFillReconFields_SSRF_CandidatesFillEveryMatch_NoAmbiguity(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{
			{URL: "https://example.com/fetch?url=https://internal.example/health"},
			{URL: "https://example.com/avatar?webhook=https://cb.example"},
		},
	})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "ssrf",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1)
	assert.ElementsMatch(t, []string{"url", "webhook"}, got[0].SSRFParams, "unlike idor's single-endpoint choice, every recon-derived candidate is directly usable — no ambiguity to resolve")
	assert.True(t, containsSubstring(logMessages(job), "ssrf: using recon-derived params"), "logs: %v", logMessages(job))
}

func TestFillReconFields_SSRF_UserTypedParams_NeverOverwritten(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{
		Endpoints: []recon.EndpointFact{{URL: "https://example.com/fetch?url=https://internal.example/health"}},
	})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "ssrf",
		SSRFParams:  []string{"manual_param"},
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1)
	assert.Equal(t, []string{"manual_param"}, got[0].SSRFParams, "a user-typed value must never be overwritten even when a recon candidate also exists")
}

// TestStartLaunch_IDORBlankEndpoint_RealReconFindsNoCandidate_SkipsAndJobStillCompletes
// is the one end-to-end submission test doc14 Step 7 calls for: a real
// (non-fixture) recon.Run against a real httptest target, driven through a
// real POST /scans, confirming the zero-candidate skip path arises
// naturally — the target here serves no numeric/UUID-shaped paths, so recon
// genuinely finds nothing idor-fillable — and the job still reaches "done"
// rather than failing outright, same as
// TestStartLaunch_ReconOnly_PopulatesReconResultAndRendersTables's pattern.
func TestStartLaunch_IDORBlankEndpoint_RealReconFindsNoCandidate_SkipsAndJobStillCompletes(t *testing.T) {
	forceNoLLMTier(t)
	ts, _ := newTestServerHandlers(t)

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
		"run_idor":   {"on"},
		"auth_token": {"tok"},
		"authorized": {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode, "a blank --endpoint must not be rejected at submission time — recon gets a chance to fill it first")

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
		return strings.Contains(string(b), "idor: skipped")
	}, 15*time.Second, 100*time.Millisecond, "expected the idor phase to be skipped with a log line once recon found no candidate")

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
		return strings.Contains(string(b), `status-badge">done`)
	}, 15*time.Second, 100*time.Millisecond, "the job must still reach done — a skipped detector is not a job failure")
}

func TestFillReconFields_Misconfig_PassesThroughUnmodified(t *testing.T) {
	job := newTestJob("job1")
	job.SetReconResult(&recon.ReconResult{})

	cfg := scanner.Config{
		Targets:     []string{"https://example.com"},
		Concurrency: 10,
		RateLimit:   10,
		Detector:    "misconfig",
	}

	got := fillReconFields(context.Background(), job, []scanner.Config{cfg})

	require.Len(t, got, 1)
	assert.Equal(t, cfg, got[0])
}

func TestNoTokenNote(t *testing.T) {
	cases := []struct {
		name string
		cfg  scanner.Config
		want string
	}{
		{
			name: "idor with no token",
			cfg:  scanner.Config{Detector: "idor"},
			want: "unauthenticated",
		},
		{
			name: "idor with a token",
			cfg:  scanner.Config{Detector: "idor", AuthToken: "tok"},
			want: "",
		},
		{
			name: "authbypass with no token",
			cfg:  scanner.Config{Detector: "authbypass"},
			want: "missing-auth probe",
		},
		{
			name: "authbypass with an other-token only",
			cfg:  scanner.Config{Detector: "authbypass", OtherAuthToken: "tok"},
			want: "",
		},
		{
			name: "misconfig never gets a note",
			cfg:  scanner.Config{Detector: "misconfig"},
			want: "",
		},
		{
			name: "businesslogic never gets a note (it can't run without a token at all)",
			cfg:  scanner.Config{Detector: "businesslogic"},
			want: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := noTokenNote(tc.cfg)
			if tc.want == "" {
				assert.Empty(t, got)
			} else {
				assert.Contains(t, got, tc.want)
			}
		})
	}
}
