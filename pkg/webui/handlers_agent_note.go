package webui

import (
	"net/http"
	"strings"
)

// maxOperatorNoteLen bounds one C4 operator note — long enough for a
// real redirect instruction ("stop the CVE sweep, focus on the /admin
// 401"), short enough that the Agent log stays readable and a stuck key
// can't flood it.
const maxOperatorNoteLen = 2000

// agentNote is POST /scans/{id}/agent/note — C4's live log injection (doc16
// Phase 7 Step 4). An operator types a note on the Scan Activity page's
// Agent section; it's appended to the job's agent log as a structured
// `operator.note` entry (the same agenttask.SessionLogEntry shape every
// other agent-activity row uses) and streamed to every connected client
// over the existing agent-event SSE channel. A coordinator loop reading
// that log surfaces the note on its next reasoning turn — the "it got
// distracted, nudge it" path doc90 §2 cites. The response is deliberately
// empty (the form swaps nothing); the new row arrives via SSE like any
// other agent entry.
func (h *handlers) agentNote(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if note == "" {
		// Nothing to record — ack without touching the log.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(note) > maxOperatorNoteLen {
		note = note[:maxOperatorNoteLen]
	}

	finish := job.BeginAgentActivity("operator.note", note, map[string]any{"source": "webui-agent-tab"})
	finish("operator note recorded — will be surfaced to the coordinator on its next turn", nil)

	// The row is delivered over SSE (agent-event); the form asked for no
	// swap. 204 keeps htmx from trying to render an empty body.
	w.WriteHeader(http.StatusNoContent)
}
