package webui

import (
	"net/http"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// defaultTemplateIndexPath mirrors cmd/hackerfive/templates.go's `templates
// index` default output path — the file `hackerfive templates index`
// produces and this page reads.
const defaultTemplateIndexPath = "templates/index.json"

// planPreview is GET /plan-preview?job={id} — renders a completed job's
// PlanTree. Prefers the job's cached, I4-resolved tree (set by a prior
// POST /plan-preview/resolve) when one exists; only builds a fresh one via
// registry.Resolve when no resolve action has run yet. Re-running
// registry.Resolve after a resolve pass would silently discard the LLM's
// work and revert leaves back to unresolved, so this order matters. Only
// makes sense against a Job whose recon phase actually finished: a
// queued/running/failed job, or one that never ran recon at all, has no
// ReconResult to resolve yet. Reads from the same unified JobStore every
// other route uses (doc14 Step 6) — recon is a phase of Job, not a separate
// ReconJob/ReconJobStore anymore.
func (h *handlers) planPreview(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.URL.Query().Get("job"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	snap := job.Snapshot()
	if snap.ReconResult == nil {
		http.Error(w, "this job has no completed recon phase to preview a plan against", http.StatusConflict)
		return
	}

	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tree, escalations := job.PlanTree()
	var indexWarn string
	if tree == nil {
		var index []templatesync.Entry
		index, indexWarn = loadTemplateIndexOrWarn()
		tree, _ = registry.Resolve(snap.ReconResult, index)
	}

	executeTemplate(w, h.tmpl, "plan_preview.html", PlanPreviewData{
		JobID:         job.ID,
		Target:        snap.ReconResult.Target, // the scheme-normalized target recon actually ran against, not job.Target's raw form input
		Tree:          tree,
		IndexWarn:     indexWarn,
		Escalations:   escalations,
		SpendUSD:      tree.SpendSoFar(),
		HasUnresolved: hasUnresolvedLeaf(tree),
		CSRFToken:     token,
	})
}

// resolvePlanLeaves is POST /plan-preview/resolve?job={id} — runs I4
// (llmfallback.ResolveTreeLeaves) over the job's current PlanTree's
// unresolved leaves and caches the mutated tree on the Job, so a page
// reload (or a second click) doesn't lose the work or re-spend on an
// already-resolved leaf. Deliberately synchronous, mirroring
// pkg/mcpserver's own handlePlan resolution pass — this only classifies or
// drafts a template (a draft lands in templates-proposed/, pending human
// promotion), it never runs a detector or template against the live
// target; that stays Step 4's job (the approval UI). Always responds 200
// with the updated fragment, same "operational result, not a malformed
// request" posture as syncTemplates/setupTools.
func (h *handlers) resolvePlanLeaves(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.URL.Query().Get("job"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	snap := job.Snapshot()
	if snap.ReconResult == nil {
		http.Error(w, "this job has no completed recon phase to resolve a plan against", http.StatusConflict)
		return
	}

	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	index, indexWarn := loadTemplateIndexOrWarn()

	// leafContexts (P2-2) only exists for a freshly-built tree — a tree
	// pulled from the job cache (a second resolve pass, or one already
	// partially resolved) has no cached context alongside it, so
	// ResolveTreeLeaves falls back to its rationale-regex path for those
	// leaves. Not a regression: that fallback is exactly this project's
	// pre-P2-2 behavior for every leaf, not just cached ones.
	var leafContexts map[string]registry.LeafContext
	tree, _ := job.PlanTree()
	if tree == nil {
		tree, leafContexts = registry.Resolve(snap.ReconResult, index)
		tree.SpendCeilingUSD = llmfallback.PerCallDefaultSpendCeilingUSD()
	}

	fb, fbErr := llmfallback.New()
	escalations := llmfallback.ResolveTreeLeaves(r.Context(), fb, fbErr, tree, registry.Capabilities, index, leafContexts)
	job.SetPlanTree(tree, escalations)

	executeTemplate(w, h.tmpl, "fragment_plan_tree", PlanPreviewData{
		JobID:         job.ID,
		Target:        snap.ReconResult.Target,
		Tree:          tree,
		IndexWarn:     indexWarn,
		Escalations:   escalations,
		SpendUSD:      tree.SpendSoFar(),
		HasUnresolved: hasUnresolvedLeaf(tree),
		CSRFToken:     token,
	})
}

// loadTemplateIndexOrWarn wraps loadTemplateIndex with plan_preview.html's
// existing degrade-gracefully wording — a missing/unreadable index
// degrades to skipping template-tag matching, same posture as
// cmd/hackerfive/plan.go, shared by both planPreview and resolvePlanLeaves.
func loadTemplateIndexOrWarn() ([]templatesync.Entry, string) {
	index, err := loadTemplateIndex(defaultTemplateIndexPath)
	if err != nil {
		return nil, "could not load " + defaultTemplateIndexPath + " (" + err.Error() + ") — template-tag matching skipped; run 'hackerfive templates index' first"
	}
	return index, ""
}

// loadTemplateIndex reads templates/index.json via templatesync.LoadIndex.
func loadTemplateIndex(path string) ([]templatesync.Entry, error) {
	return templatesync.LoadIndex(path)
}

// hasUnresolvedLeaf reports whether tree has any StatusUnresolved leaf —
// drives whether plan_preview.html's "Resolve via LLM fallback" button
// renders at all.
func hasUnresolvedLeaf(tree *agenttask.PlanTree) bool {
	if tree == nil {
		return false
	}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Status == agenttask.StatusUnresolved {
			return true
		}
	}
	return false
}
