package webui

import (
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
	"github.com/tuangatech/hacker-five/pkg/recon"
)

func TestBucketMatchedCapabilities(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{
		ID: "root",
		Children: []*agenttask.PlanNode{{
			ID: "host:example.com",
			Children: []*agenttask.PlanNode{
				{ID: "l1", Detector: "misconfig", Status: agenttask.StatusPending},
				{ID: "l2", Detector: "idor", Status: agenttask.StatusPending},
				{ID: "l3", Detector: "authbypass", Status: agenttask.StatusPending},
				{ID: "l4", Detector: "ssrf", Status: agenttask.StatusPending},
				{ID: "l5", Detector: "php-detect", Status: agenttask.StatusPending}, // a template-tag match
				{ID: "l6", Detector: "misconfig", Status: agenttask.StatusPending},  // duplicate, must not double-count
				{ID: "l7", Status: agenttask.StatusUnresolved, Rationale: "unmatched tech fact"},
			},
		}},
	}}

	ready, needsInput, unsupported := bucketMatchedCapabilities(tree)
	assert.Equal(t, []string{"misconfig"}, ready)
	assert.ElementsMatch(t, []string{"idor", "authbypass"}, needsInput)
	assert.ElementsMatch(t, []string{"ssrf", "php-detect"}, unsupported)

	unresolved := unresolvedRationales(tree)
	assert.Equal(t, []string{"unmatched tech fact"}, unresolved)
}

// fixtureReconResultForGuidedScan uses OpenResty, whose techRules entry
// (pkg/registry/decisionengine.go) maps to all three of misconfig/idor/
// authbypass at once — real coverage of Guided Scan's Ready and NeedsInput
// buckets through the actual registry.Resolve, not a hand-built tree.
func fixtureReconResultForGuidedScan() *recon.ReconResult {
	return &recon.ReconResult{
		Target: "https://example.com",
		TechStack: []recon.TechFact{
			{Name: "OpenResty", Host: "example.com", Source: "httpx-tech-detect", Confidence: recon.ConfidenceHigh},
		},
		GeneratedAt: time.Now(),
	}
}

func TestGuidedScanPlan_RendersReadyAndNeedsInputBuckets(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newReconJob("job1", "https://example.com", "active", "guided", noopReconProgressRender)
	job.MarkDone(fixtureReconResultForGuidedScan(), nil)
	h.reconStore.Add(job)

	resp, err := http.Get(ts.URL + "/guided-scan/plan?job=job1")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, `name="run_misconfig"`)
	assert.Contains(t, html, `name="run_idor"`)
	assert.Contains(t, html, `name="run_authbypass"`)
	assert.Contains(t, html, `name="endpoint"`, "idor's own required field must render inline")
	assert.Contains(t, html, `name="protected_paths"`, "authbypass's own required field must render inline")
	assert.Contains(t, html, "Start Scan")
}

func TestGuidedScanPlan_JobNotDone_Returns409(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newReconJob("job1", "https://example.com", "active", "guided", noopReconProgressRender)
	job.SetRunning()
	h.reconStore.Add(job)

	resp, err := http.Get(ts.URL + "/guided-scan/plan?job=job1")
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestGuidedScanPlan_UnknownJob_404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)

	resp, err := http.Get(ts.URL + "/guided-scan/plan?job=does-not-exist")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

// TestStartGuidedScan_MisconfigOnly_RunsRealScanAndRedirects is a real
// end-to-end run needing no credentials at all: misconfig is the one
// detector Guided Scan can run fully automatically. Confirms the produced
// Job lands real findings from a real scanner.Engine run against a real
// local httptest target, reachable via the existing, unmodified /scans/{id}.
func TestStartGuidedScan_MisconfigOnly_RunsRealScanAndRedirects(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // no security headers -> a real misconfig finding
	}))
	t.Cleanup(targetSrv.Close)
	target := targetSrv.URL
	job := newReconJob("job1", target, "active", "guided", noopReconProgressRender)
	job.MarkDone(&recon.ReconResult{
		Target:      target,
		TechStack:   []recon.TechFact{{Name: "PHP", Host: target, Source: "httpx-tech-detect", Confidence: recon.ConfidenceHigh}},
		GeneratedAt: time.Now(),
	}, nil)
	h.reconStore.Add(job)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow HX-Redirect-triggered navigation automatically; it's a header, not a real 3xx anyway
		},
	}

	getResp, err := client.Get(ts.URL + "/guided-scan/plan?job=job1")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	form := url.Values{"csrf_token": {csrfVal}, "job": {"job1"}, "run_misconfig": {"on"}}
	resp, err := client.PostForm(ts.URL+"/guided-scan/run", form)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	redirect := resp.Header.Get("HX-Redirect")
	require.NotEmpty(t, redirect)
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
		return strings.Contains(string(b), "misconfig") && strings.Contains(string(b), StatusDone)
	}, 5*time.Second, 50*time.Millisecond, "expected a real misconfig finding and a done status once the guided scan finishes")
}
