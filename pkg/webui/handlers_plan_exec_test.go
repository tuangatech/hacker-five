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
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// dispatchableLeafIDs returns the IDs of tree's leaves that
// planexec.RunPlan could ever consider dispatching (has a Detector, no
// Children) — used to build a real "include" form submission the same way
// fragment_plan_node.html's checkboxes would, without needing to parse
// rendered HTML.
func dispatchableLeafIDs(tree *agenttask.PlanTree) []string {
	var ids []string
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Detector != "" && len(leaf.Children) == 0 {
			ids = append(ids, leaf.ID)
		}
	}
	return ids
}

// TestExecutePlan_Reject_LogsAndExecutesNothing confirms the reject action
// never dispatches anything — no finding, no dispatch log line, just the
// "rejected by operator" audit entry — and redirects back to the job's own
// status page.
func TestExecutePlan_Reject_LogsAndExecutesNothing(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", url.Values{"action": {"reject"}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "/scans/job1", resp.Request.URL.Path)

	snap := job.Snapshot()
	found := false
	for _, l := range snap.Logs {
		if l.Msg == "plan-preview: plan rejected by operator — not executed" {
			found = true
		}
		assert.NotContains(t, l.Msg, "operator approved", "reject must never dispatch")
	}
	assert.True(t, found, "expected the rejection audit log line")
	assert.Empty(t, snap.Findings)
}

// TestExecutePlan_Approve_DispatchesIncludedLeaves confirms approve
// dispatches exactly the leaves whose checkbox was included, reopens the
// job's terminal status (it was already StatusDone from
// newTestJobWithRecon's own MarkDone) back to running, and eventually
// returns to a terminal state once the background dispatch finishes.
func TestExecutePlan_Approve_DispatchesIncludedLeaves(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	job.SetExecConfig(scanner.Config{}) // no EndpointTemplate/ProtectedPaths/SSRFParams — idor leaf still dispatches (misconfig has no field requirement; idor's own requirement is gated inside runLeaf via cfg.Validate, not RunPlan's own eligibility loop)
	h.store.Add(job)
	require.Equal(t, StatusDone, job.Snapshot().Status, "precondition: the job must already be terminal before approving, to prove approve reopens it")

	tree, _ := registry.Resolve(fixtureReconResultForPlan(), nil)
	ids := dispatchableLeafIDs(tree)
	require.Len(t, ids, 2, "fixtureReconResultForPlan is documented to produce exactly 2 dispatchable leaves (misconfig, idor)")
	job.SetPlanTree(tree, nil)

	form := url.Values{"action": {"approve"}}
	for _, id := range ids {
		form.Add("include", id)
	}
	resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", form)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, "/scans/job1", resp.Request.URL.Path)

	// The dispatch log line is appended synchronously, before the redirect
	// — no need to poll for it.
	snap := job.Snapshot()
	assert.True(t, containsLogMsg(snap, "plan-preview: operator approved — dispatching 2 leaf/leaves (0 excluded)"))

	// The background goroutine's own scanner.Engine run against
	// https://example.com will fail fast (DNS/connect error in most CI
	// sandboxes) and call MarkDone — wait for it rather than asserting an
	// exact timing.
	require.Eventually(t, func() bool {
		s := job.Snapshot().Status
		return s == StatusDone || s == StatusFailed
	}, 10*time.Second, 50*time.Millisecond, "expected the plan-execution goroutine to reach a terminal state")
}

// TestExecutePlan_NoIncludeValues_AllLeavesExcluded confirms a bare approve
// with no "include" values (nothing in fragment_plan_node.html's checked-
// by-default set survived submission — e.g. every box was manually
// unchecked) reports every dispatchable leaf as excluded, not silently run.
func TestExecutePlan_NoIncludeValues_AllLeavesExcluded(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	tree, _ := registry.Resolve(fixtureReconResultForPlan(), nil)
	job.SetPlanTree(tree, nil)

	resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", url.Values{"action": {"approve"}})
	require.NoError(t, resp.Body.Close())

	snap := job.Snapshot()
	assert.True(t, containsLogMsg(snap, "plan-preview: operator approved — dispatching 0 leaf/leaves (2 excluded)"))
}

func containsLogMsg(snap Snapshot, msg string) bool {
	for _, l := range snap.Logs {
		if l.Msg == msg {
			return true
		}
	}
	return false
}

func TestExecutePlan_JobNotDone_Returns409(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.SetRunning() // never runs a recon phase, so ReconResult stays nil
	h.store.Add(job)

	resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", url.Values{"action": {"approve"}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

func TestExecutePlan_UnknownJob_404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)
	resp := postWithCSRFAgainstAnyJob(t, ts, "/plan-preview/execute?job=does-not-exist")
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestCancelScan_CancelsJobContextAndLogs confirms POST /scans/{id}/cancel
// reaches Job.Cancel — the doc15 Step 4 kill switch — and appends the audit
// log line, regardless of whether anything is actually still listening on
// the context (a directly-constructed test job has no background goroutine
// to react to it, which is fine: this test is about the handler reaching
// Cancel, not about a specific goroutine's reaction).
func TestCancelScan_CancelsJobContextAndLogs(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	job.SetRunning()
	h.store.Add(job)
	ctx := job.Ctx()

	resp := postWithCSRFForm(t, ts, "/scans/job1/cancel", url.Values{})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("POST /scans/{id}/cancel must cancel the job's own context")
	}

	assert.True(t, containsLogMsg(job.Snapshot(), "cancel requested by operator"))
}

func TestCancelScan_UnknownJob_404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)
	resp := postWithCSRFAgainstAnyJob(t, ts, "/scans/does-not-exist/cancel")
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestFragmentProgress_CancelButton_OnlyWhileRunningOrQueued confirms the
// kill switch only renders while there is actually something to cancel —
// no dead "Cancel" button on an already-terminal job's status page.
func TestFragmentProgress_CancelButton_OnlyWhileRunningOrQueued(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newJob("job1", "https://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
	h.store.Add(job)

	resp, err := http.Get(ts.URL + "/scans/job1")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Contains(t, string(body), "/scans/job1/cancel", "a queued job must show the Cancel control")

	job.MarkDone(nil)
	resp, err = http.Get(ts.URL + "/scans/job1")
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.NotContains(t, string(body), "/scans/job1/cancel", "a done job must not show the Cancel control")
}

// postWithCSRFForm is postWithCSRF's variant that submits extra form values
// alongside csrf_token — seeds the CSRF cookie against /templates (always
// present, unlike a specific job) rather than postWithCSRF's own
// job1-specific seed page.
func postWithCSRFForm(t *testing.T, ts *httptest.Server, path string, form url.Values) *http.Response {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/templates")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", csrfVal)

	resp, err := client.PostForm(ts.URL+path, form)
	require.NoError(t, err)
	return resp
}
