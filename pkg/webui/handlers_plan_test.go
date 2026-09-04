package webui

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
)

// fixtureReconResultForPlan carries TechFacts chosen to exercise every
// PlanTree.Confidence band through the real registry.Resolve, plus one
// unmatched tech name to produce a genuine StatusUnresolved leaf — same
// "real decision engine, fixture input" approach fixtureReconResult takes.
// Each surviving leaf must have a distinct (detector, confidence) — the
// decision engine now dedups leaves that would run the identical check
// (doc15 Step 2 addendum, P0-4), so PHP+nginx+mysql (all -> misconfig) no
// longer yield three separate misconfig leaves in three bands. Instead:
// PHP -> misconfig @ high; swagger -> idor @ medium (its misconfig leaf
// dedups against PHP's); the unmatched fact @ low -> unresolved leaf.
func fixtureReconResultForPlan() *recon.ReconResult {
	return &recon.ReconResult{
		Target: "https://example.com",
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "example.com", Source: "httpx-tech-detect", Confidence: recon.ConfidenceHigh},       // techRules match -> misconfig pending, high
			{Name: "swagger", Host: "example.com", Source: "httpx-tech-detect", Confidence: recon.ConfidenceMedium}, // techRules match -> idor pending, medium (misconfig leaf dedups away)
			{Name: "SomeUnknownFramework", Host: "example.com", Source: "httpx-tech-detect", Confidence: recon.ConfidenceLow}, // no match -> unresolved, low
		},
		GeneratedAt: time.Now(),
	}
}

func TestPlanPreview_RendersNestedLeavesEveryConfidenceBandAndUnresolvedBadge(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	resp, err := http.Get(ts.URL + "/plan-preview?job=job1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, "misconfig") // PHP's techRules match
	assert.Contains(t, html, "confidence: high")
	assert.Contains(t, html, "confidence: medium")
	assert.Contains(t, html, "confidence: low")
	assert.Contains(t, html, "unresolved")
	assert.Contains(t, html, "badge-unresolved")
	assert.Contains(t, html, "Read-only")
}

func TestPlanPreview_JobNotDone_Returns409(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.SetRunning() // never runs a recon phase, so ReconResult stays nil
	h.store.Add(job)

	resp, err := http.Get(ts.URL + "/plan-preview?job=job1")
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestPlanPreview_MissingTemplateIndex_DegradesToWarningBanner(t *testing.T) {
	// No templates/index.json exists relative to the test binary's working
	// directory in CI — loadTemplateIndex must degrade gracefully, not 500.
	ts, h := newTestServerHandlers(t)

	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	resp, err := http.Get(ts.URL + "/plan-preview?job=job1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(body), "template-tag matching skipped")
}

func TestPlanPreview_UnknownJob_404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)

	resp, err := http.Get(ts.URL + "/plan-preview?job=does-not-exist")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

// forceNoLLMTier makes llmfallback.New() deterministically fail (fb == nil,
// ErrNoTierAvailable) regardless of what's actually running on the test
// machine — same technique pkg/mcpserver/tools_triage_test.go already uses.
func forceNoLLMTier(t *testing.T) {
	t.Helper()
	t.Setenv("HACKERFIVE_LOCAL_MODEL_URL", "http://127.0.0.1:1/unreachable")
	t.Setenv("OPENROUTER_API_KEY", "")
}

func postWithCSRF(t *testing.T, ts *httptest.Server, path string) *http.Response {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/plan-preview?job=job1")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	resp, err := client.PostForm(ts.URL+path, url.Values{"csrf_token": {csrfVal}})
	require.NoError(t, err)
	return resp
}

// TestResolvePlanLeaves_NoLLMConfigured_EscalatesAndCachesTree confirms the
// fb == nil path renders an escalation (rather than erroring) and still
// caches the tree on the Job — a resolve pass that couldn't reach any LLM
// tier is still a completed, cacheable pass, matching handlePlan's own
// fb == nil posture.
func TestResolvePlanLeaves_NoLLMConfigured_EscalatesAndCachesTree(t *testing.T) {
	forceNoLLMTier(t)
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	resp := postWithCSRF(t, ts, "/plan-preview/resolve?job=job1")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Contains(t, string(body), "LLM fallback unavailable")

	tree, escalations := job.PlanTree()
	require.NotNil(t, tree, "a resolve pass must cache its tree on the Job even when every leaf just escalates")
	assert.NotEmpty(t, escalations)
}

func TestResolvePlanLeaves_JobNotDone_Returns409(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.SetRunning() // never runs a recon phase, so ReconResult stays nil
	h.store.Add(job)

	resp := postWithCSRFAgainstAnyJob(t, ts, "/plan-preview/resolve?job=job1")
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestResolvePlanLeaves_UnknownJob_404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)
	resp := postWithCSRFAgainstAnyJob(t, ts, "/plan-preview/resolve?job=does-not-exist")
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestResolvePlanLeaves_MissingCSRFCookie_Rejected(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	resp, err := http.PostForm(ts.URL+"/plan-preview/resolve?job=job1", url.Values{"csrf_token": {"whatever"}})
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// postWithCSRFAgainstAnyJob is postWithCSRF's variant for a case where
// job1 (postWithCSRF's own GET target for seeding the CSRF cookie) doesn't
// exist — seeds the cookie against the templates page instead, which every
// test server always has.
func postWithCSRFAgainstAnyJob(t *testing.T, ts *httptest.Server, path string) *http.Response {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/templates")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	resp, err := client.PostForm(ts.URL+path, url.Values{"csrf_token": {csrfVal}})
	require.NoError(t, err)
	return resp
}

// TestPlanPreview_PrefersCachedResolvedTreeOverFreshResolve confirms GET
// /plan-preview uses a Job's cached PlanTree (set by a prior resolve pass)
// rather than recomputing via registry.Resolve — re-resolving would
// silently discard the LLM's work and revert leaves back to unresolved. The
// cached tree here carries content a fresh registry.Resolve against the
// same fixture could never produce (a StatusDone leaf with a synthetic
// rationale, and an escalation banner), so if the response reflects it, GET
// must be using the cached tree.
func TestPlanPreview_PrefersCachedResolvedTreeOverFreshResolve(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	cached, _ := registry.Resolve(fixtureReconResultForPlan(), nil)
	for _, leaf := range agenttask.Leaves(cached.Root) {
		if leaf.Status == agenttask.StatusUnresolved {
			status := agenttask.StatusDone
			rationale := "synthetic-marker-from-cached-tree"
			require.NoError(t, cached.ApplyLeafUpdate(leaf.ID, agenttask.PlanNodePatch{Status: &status, Rationale: &rationale}))
		}
	}
	job.SetPlanTree(cached, []string{"synthetic-escalation-marker"})

	resp, err := http.Get(ts.URL + "/plan-preview?job=job1")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	html := string(body)
	assert.Contains(t, html, "synthetic-marker-from-cached-tree")
	assert.Contains(t, html, "synthetic-escalation-marker")
	assert.NotContains(t, html, "badge-unresolved", "the cached tree has no unresolved leaf left, so a fresh registry.Resolve's unresolved badge must not reappear")
}
