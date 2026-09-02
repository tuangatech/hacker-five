package webui

import (
	"net/http"

	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// defaultTemplateIndexPath mirrors cmd/hackerfive/templates.go's `templates
// index` default output path — the file `hackerfive templates index`
// produces and this page reads.
const defaultTemplateIndexPath = "templates/index.json"

// planPreview is GET /plan-preview?job={id} — renders the PlanTree
// registry.Resolve builds from a completed job's recon-phase ReconResult.
// Only makes sense against a Job whose recon phase actually finished: a
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

	var indexWarn string
	index, err := loadTemplateIndex(defaultTemplateIndexPath)
	if err != nil {
		// A missing/unreadable index degrades to skipping template-tag
		// matching, same graceful-degrade posture as cmd/hackerfive/plan.go.
		indexWarn = "could not load " + defaultTemplateIndexPath + " (" + err.Error() + ") — template-tag matching skipped; run 'hackerfive templates index' first"
		index = nil
	}

	tree := registry.Resolve(snap.ReconResult, index)

	executeTemplate(w, h.tmpl, "plan_preview.html", PlanPreviewData{
		JobID:     job.ID,
		Target:    snap.ReconResult.Target, // the scheme-normalized target recon actually ran against, not job.Target's raw form input
		Tree:      tree,
		IndexWarn: indexWarn,
	})
}

// loadTemplateIndex reads templates/index.json via templatesync.LoadIndex.
func loadTemplateIndex(path string) ([]templatesync.Entry, error) {
	return templatesync.LoadIndex(path)
}
