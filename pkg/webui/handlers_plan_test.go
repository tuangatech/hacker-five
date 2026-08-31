package webui

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/recon"
)

// fixtureReconResultForPlan carries three TechFacts chosen to exercise every
// PlanTree.Confidence band through the real registry.Resolve, plus one
// unmatched tech name to produce a genuine StatusUnresolved leaf — same
// "real decision engine, fixture input" approach fixtureReconResult takes.
func fixtureReconResultForPlan() *recon.ReconResult {
	return &recon.ReconResult{
		Target: "https://example.com",
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "example.com", Source: "httpx-tech-detect", Confidence: recon.ConfidenceHigh},                  // techRules match -> pending, high
			{Name: "nginx", Host: "example.com", Source: "fingerprint-header", Confidence: recon.ConfidenceMedium},             // techRules match -> pending, medium
			{Name: "mysql", Host: "example.com", Source: "fingerprint-port", Confidence: recon.ConfidenceLow},                  // techRules match -> pending, low
			{Name: "SomeUnknownFramework", Host: "example.com", Source: "httpx-tech-detect", Confidence: recon.ConfidenceHigh}, // no match -> unresolved
		},
		GeneratedAt: time.Now(),
	}
}

func TestPlanPreview_RendersNestedLeavesEveryConfidenceBandAndUnresolvedBadge(t *testing.T) {
	ts, h := newTestServerHandlers(t)

	job := newReconJob("job1", "https://example.com", "active", noopProgressRender)
	job.MarkDone(fixtureReconResultForPlan(), nil)
	h.reconStore.Add(job)

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

	job := newReconJob("job1", "https://example.com", "active", noopProgressRender)
	job.SetRunning() // never MarkDone
	h.reconStore.Add(job)

	resp, err := http.Get(ts.URL + "/plan-preview?job=job1")
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}

func TestPlanPreview_MissingTemplateIndex_DegradesToWarningBanner(t *testing.T) {
	// No templates/index.json exists relative to the test binary's working
	// directory in CI — loadTemplateIndex must degrade gracefully, not 500.
	ts, h := newTestServerHandlers(t)

	job := newReconJob("job1", "https://example.com", "active", noopProgressRender)
	job.MarkDone(fixtureReconResultForPlan(), nil)
	h.reconStore.Add(job)

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
