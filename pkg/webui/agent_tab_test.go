package webui

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// TestExecutePlan_Reject_RecordsAgentActivity confirms C1 (doc16 Phase 7
// Step 3): a plan rejection is recorded as a structured agent-activity
// entry on the job's Agent log — the same agenttask.SessionLogEntry shape
// pkg/mcpserver's session.log uses — not only as a free-text job-log line.
func TestExecutePlan_Reject_RecordsAgentActivity(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", url.Values{"action": {"reject"}})
	require.NoError(t, resp.Body.Close())

	entries := job.Snapshot().AgentEntries
	require.Len(t, entries, 1)
	assert.Equal(t, "plan.reject", entries[0].Tool)
	assert.Contains(t, entries[0].Result, "rejected by operator")
	assert.NotZero(t, entries[0].Seq, "an agent entry must carry a sequence for C5 catchup gating")
}

// TestExecutePlan_Approve_RecordsAgentActivityWithStructuredParams confirms
// C1 + C2: the approval is one agent-activity entry whose params capture
// the approved leaf count, the allow_writes posture, and the out-of-scope
// count — the agent-specific audit facts C2 asks for — and its Result is
// filled in only once the background dispatch reaches a terminal state.
func TestExecutePlan_Approve_RecordsAgentActivityWithStructuredParams(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	recResult := fixtureReconResultForPlan()
	recResult.OutOfScope = []string{"cdn.vendor.example"}
	job := newTestJobWithRecon("job1", recResult)
	job.SetExecConfig(scanner.Config{})
	h.store.Add(job)

	tree, _ := registry.Resolve(recResult, nil)
	job.SetPlanTree(tree, nil)

	form := url.Values{"action": {"approve"}}
	for _, id := range dispatchableLeafIDs(tree) {
		form.Add("include", id)
	}
	resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", form)
	require.NoError(t, resp.Body.Close())

	// The entry is appended synchronously at approval time (BeginAgentActivity).
	entries := job.Snapshot().AgentEntries
	require.Len(t, entries, 1)
	exec := entries[0]
	assert.Equal(t, "plan.execute", exec.Tool)
	params := string(exec.Params)
	assert.Contains(t, params, `"approved_leaves":2`)
	assert.Contains(t, params, `"allow_writes":false`)
	assert.Contains(t, params, `"out_of_scope_count":1`)

	// Result is filled in by the dispatch goroutine once it finishes.
	require.Eventually(t, func() bool {
		for _, e := range job.Snapshot().AgentEntries {
			if e.Tool == "plan.execute" && e.Result != "" {
				return true
			}
		}
		return false
	}, 10*time.Second, 50*time.Millisecond, "the plan.execute agent entry must get a Result once dispatch terminates")
}

// TestScanStatus_RendersAgentSection confirms the Scan Activity page paints
// the live Agent section (C1) — the sse-swap channel plus any entries
// already recorded — so a reconnecting client sees prior agent activity on
// first paint, exactly as it does for logs and findings.
func TestScanStatus_RendersAgentSection(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", url.Values{"action": {"reject"}})
	require.NoError(t, resp.Body.Close())

	page, err := http.Get(ts.URL + "/scans/job1")
	require.NoError(t, err)
	body, err := io.ReadAll(page.Body)
	require.NoError(t, err)
	require.NoError(t, page.Body.Close())
	html := string(body)

	assert.Contains(t, html, `id="agent"`)
	assert.Contains(t, html, `sse-swap="agent-event"`)
	assert.Contains(t, html, "plan.reject", "an already-recorded agent entry must be in the first paint")
}

// TestScanCatchup_ReplaysMissedAgentEntries confirms agent entries are
// sequence-gated by the same C5 mechanism as logs/findings.
func TestScanCatchup_ReplaysMissedAgentEntries(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJobWithRecon("job1", fixtureReconResultForPlan())
	h.store.Add(job)

	// Two agent activities: reject, then reject again (cheap, synchronous).
	for i := 0; i < 2; i++ {
		resp := postWithCSRFForm(t, ts, "/plan-preview/execute?job=job1", url.Values{"action": {"reject"}})
		require.NoError(t, resp.Body.Close())
	}
	entries := job.Snapshot().AgentEntries
	require.Len(t, entries, 2)
	firstSeq := entries[0].Seq

	resp, err := http.Get(ts.URL + "/scans/job1/catchup?since_agent=" + strconv.FormatInt(firstSeq, 10))
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, `hx-swap-oob="beforeend:#agent"`)
	assert.Contains(t, html, `data-seq="`+strconv.FormatInt(entries[1].Seq, 10)+`"`, "the missed agent entry is replayed")
}
