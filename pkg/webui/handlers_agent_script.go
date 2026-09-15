package webui

import "net/http"

// agentScriptApproval is POST /scans/{id}/agent-script — docs/93-
// implementation-plan-agent-orchestrator.md M4's Web UI approve/reject for a
// pending script.explore action: Job.RequestScriptApproval (running on the
// job's own background goroutine, inside scriptexec.Execute's
// Precheck -> ApprovalGate -> sandbox call chain) blocks on exactly this
// decision. No batch/blanket approval — every proposed script gets its own
// pending state and its own POST, mirroring cmd/hackerfive/agent.go's stdin
// y/N prompt's "every time" requirement. The response is deliberately empty
// (204): the resolved/cleared card arrives over SSE (EventScriptApproval)
// like any other live job update, not as this request's own response body.
func (h *handlers) agentScriptApproval(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	// ResolveScriptApproval's bool return (nothing was pending — a duplicate
	// submit, e.g. a doubled click, or the request already timed out/was
	// canceled) isn't an error either way: the operator's intent is already
	// satisfied, or there's nothing left to satisfy it against.
	_ = job.ResolveScriptApproval(r.PostFormValue("action") == "approve")
	w.WriteHeader(http.StatusNoContent)
}
