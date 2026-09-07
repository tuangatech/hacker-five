package webui

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAgentNote_RecordsOperatorNoteEntry is C4's core: an operator note
// POSTed to /scans/{id}/agent/note lands on the job's agent log as a
// structured `operator.note` entry (same agenttask.SessionLogEntry shape
// as every other agent-activity row), carrying a sequence for C5 catchup.
func TestAgentNote_RecordsOperatorNoteEntry(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJob("job1")
	h.store.Add(job)

	resp := postWithCSRFForm(t, ts, "/scans/job1/agent/note", url.Values{
		"note": {"skip the CVE sweep, dig into the /admin 401"},
	})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	entries := job.Snapshot().AgentEntries
	require.Len(t, entries, 1)
	assert.Equal(t, "operator.note", entries[0].Tool)
	assert.Contains(t, entries[0].Reason, "/admin 401")
	assert.NotZero(t, entries[0].Seq, "an agent entry must carry a sequence for C5 catchup gating")
}

// TestAgentNote_BlankNoteIsIgnored: an empty submission must not append a
// row.
func TestAgentNote_BlankNoteIsIgnored(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJob("job1")
	h.store.Add(job)

	resp := postWithCSRFForm(t, ts, "/scans/job1/agent/note", url.Values{"note": {"   "}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	assert.Empty(t, job.Snapshot().AgentEntries)
}

// TestAgentNote_UnknownJob404s
func TestAgentNote_UnknownJob404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)
	resp := postWithCSRFForm(t, ts, "/scans/nope/agent/note", url.Values{"note": {"hi"}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestScanStatus_RendersAgentNoteForm confirms the Scan Activity page
// paints the C4 injection textbox wired to the note route.
func TestScanStatus_RendersAgentNoteForm(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	h.store.Add(newTestJob("job1"))

	resp, err := http.Get(ts.URL + "/scans/job1")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	html := string(body)

	assert.Contains(t, html, `hx-post="/scans/job1/agent/note"`)
	assert.True(t, strings.Contains(html, `name="note"`), "the note input must be present")
}
