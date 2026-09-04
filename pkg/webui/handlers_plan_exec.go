// handlers_plan_exec.go implements doc15 Phase 6 Step 4's "make the Plan
// Preview actionable" gap: POST /plan-preview/execute dispatches the exact
// tree GET /plan-preview showed, via the shared pkg/planexec dispatcher
// (the same one an MCP client's elicitation-approved `plan` tool call
// uses) — closing docs/follow-up.md's LT-1 ("Web UI Launch never dispatches
// the decision engine's own template-ranked leaves").
package webui

import (
	"fmt"
	"net/http"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/planexec"
	"github.com/tuangatech/hacker-five/pkg/registry"
)

// executePlan is POST /plan-preview/execute?job={id}. Two actions share this
// one route (a "action" form field, mirroring resolvePlanLeaves' own single-
// route convention): "reject" logs the decision and executes nothing;
// "approve" (the default/only other value) dispatches every included leaf
// in the background, into the same Job the operator already has open — its
// SSE stream and findings/logs table pick the results up live, exactly as
// they do for a native detector run.
//
// Deliberately does not implement the elicitation round trip an MCP client's
// `plan` tool call resolves (doc15 Step 2): pkg/mcpserver and pkg/webui are
// two separate, unconnected processes in this codebase (`hackerfive mcpserve`
// vs. `hackerfive serve`) with no shared pending-approval store between
// them, so "approve from either surface interchangeably" would need new
// cross-process infrastructure this step doesn't build. What this route
// does provide — real Approve/Reject, per-leaf inclusion, a spend gauge
// (plan_preview.html), and a kill switch reachable from the resulting run
// (fragment_progress.html's Cancel button, POST /scans/{id}/cancel) — is
// the Web UI's own, self-contained approval surface for a human driving a
// session through the Web UI directly.
func (h *handlers) executePlan(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.URL.Query().Get("job"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	snap := job.Snapshot()
	if snap.ReconResult == nil {
		http.Error(w, "this job has no completed recon phase to execute a plan against", http.StatusConflict)
		return
	}

	if r.PostFormValue("action") == "reject" {
		job.AppendLog("info", "plan-preview: plan rejected by operator — not executed")
		http.Redirect(w, r, "/scans/"+job.ID, http.StatusSeeOther)
		return
	}

	tree, _ := job.PlanTree()
	if tree == nil {
		index, _ := loadTemplateIndexOrWarn()
		tree, _ = registry.Resolve(snap.ReconResult, index)
	}

	// Every dispatchable leaf (has a Detector, no Children) runs unless its
	// ID was explicitly unchecked — fragment_plan_node.html's "run this
	// leaf" checkboxes default checked, name="include".
	included := make(map[string]bool, len(r.PostForm["include"]))
	for _, id := range r.PostForm["include"] {
		included[id] = true
	}
	leaves := agenttask.Leaves(tree.Root)
	excluded := make(map[string]bool, len(leaves))
	dispatchCount := 0
	for _, leaf := range leaves {
		if leaf.Detector == "" || len(leaf.Children) > 0 {
			continue // not a dispatchable leaf to begin with — never counted either way
		}
		if included[leaf.ID] {
			dispatchCount++
		} else {
			excluded[leaf.ID] = true
		}
	}

	index, _ := loadTemplateIndex(defaultTemplateIndexPath)
	execCfg := job.ExecConfig()

	job.AppendLog("info", fmt.Sprintf("plan-preview: operator approved — dispatching %d leaf/leaves (%d excluded)", dispatchCount, len(excluded)))
	// Reopens the job's own progress/SSE lifecycle: this job may already be
	// StatusDone from its native-detector phase by the time a plan is
	// approved, and scanEvents refuses to open a live stream for an
	// already-terminal job — SetRunning flips status back before the
	// browser's redirect-triggered GET /scans/{id} has a chance to race it.
	job.SetRunning()
	job.SetPhase("plan-execution")

	go func() {
		_, _, skipped, err := planexec.RunPlan(job.Ctx(), tree, execCfg, index, planexec.ExecOptions{
			Notify:         func(target, message string) { job.AppendLog("info", target+": "+message) },
			OnFinding:      func(_ *agenttask.PlanNode, f detectors.Finding) { job.AppendFinding(f) },
			OnLog:          func(_ *agenttask.PlanNode, level, msg string) { job.AppendLog(level, msg) },
			Excluded:       excluded,
			DetConcurrency: defaultConcurrency,
			LLMConcurrency: llmAssistedExecConcurrency,
		})
		for _, s := range skipped {
			job.AppendLog("info", "plan-execution: "+s)
		}
		job.MarkDone(err)
	}()

	http.Redirect(w, r, "/scans/"+job.ID, http.StatusSeeOther)
}
