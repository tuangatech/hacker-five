package webui

import (
	"errors"
	"net/http"
	"os"

	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func (h *handlers) templatesPage(w http.ResponseWriter, r *http.Request) {
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	tags := r.URL.Query().Get("tags")
	data := TemplatesPageData{
		CSRFToken: token,
		Table:     buildTemplateTableData(tags),
		Sync:      buildSyncPanelData(false, ""),
	}
	executeTemplate(w, h.tmpl, "templates_page.html", data)
}

// templateTable is GET /templates/table — the tag filter's hx-get target
// (doc12: "the tag filter does hx-get=... hx-target=#template-table"),
// a dedicated fragment route rather than sniffing the request type inside
// templatesPage, matching the same pattern GET /scans/new/detector-fields
// already establishes.
func (h *handlers) templateTable(w http.ResponseWriter, r *http.Request) {
	tags := r.URL.Query().Get("tags")
	executeTemplate(w, h.tmpl, "fragment_template_table", buildTemplateTableData(tags))
}

// syncTemplates is POST /templates/sync. csrfMiddleware has already
// validated the CSRF cookie/field and called r.ParseForm() by the time this
// runs. Always responds 200 (design decision 5) — a failed sync is a valid,
// successfully-processed operational result, not a malformed request.
func (h *handlers) syncTemplates(w http.ResponseWriter, r *http.Request) {
	syncedDir, dirErr := templatesync.DefaultSyncDir()
	if dirErr != nil {
		executeTemplate(w, h.tmpl, "fragment_sync_status", buildSyncPanelData(false, "resolving the sync directory failed: "+dirErr.Error()))
		return
	}

	_, syncErr := templatesync.Sync(r.Context(), syncedDir)
	if syncErr != nil {
		msg := syncErr.Error()
		if errors.Is(syncErr, templatesync.ErrGitNotFound) {
			msg = "git is not installed (or not on PATH) on this machine — template sync shells out to it. Install git, make sure it is on PATH, then try again."
		}
		executeTemplate(w, h.tmpl, "fragment_sync_status", buildSyncPanelData(false, msg))
		return
	}

	executeTemplate(w, h.tmpl, "fragment_sync_status", buildSyncPanelData(true, ""))
}

// buildTemplateTableData loads every template under the default web
// directories (bundled + synced, if present), labeled the same way
// cmd/hackerfive/templates.go's `templates list` labels them, and filters by
// tags when non-empty — the GET /templates?tags=... behavior doc12 specifies.
func buildTemplateTableData(tags string) TemplateTableData {
	dirs, labels := defaultWebTemplateDirsWithLabels()
	entries, rejected, err := templatesync.List(dirs, labels, splitCSV(tags))
	if err != nil {
		return TemplateTableData{Tags: tags}
	}
	return TemplateTableData{Entries: entries, Rejected: rejected, Tags: tags}
}

// buildSyncPanelData reads the synced directory's on-disk state — its mtime
// stands in for "last synced" (design decision 3: templatesync.Sync always
// recreates that exact directory, so its mtime is the real last-sync time)
// and templatesync.CategoryCounts recomputes the per-category numbers
// without requiring an in-process Sync call to have just happened.
func buildSyncPanelData(justSynced bool, errMsg string) SyncPanelData {
	data := SyncPanelData{
		PinnedCommit: templatesync.PinnedCommit,
		Categories:   templatesync.Categories,
		Error:        errMsg,
		JustSynced:   justSynced,
	}

	syncedDir, err := templatesync.DefaultSyncDir()
	if err != nil {
		return data
	}
	data.SyncedDir = syncedDir

	info, statErr := os.Stat(syncedDir)
	if statErr != nil {
		return data
	}
	modTime := info.ModTime()
	data.LastSynced = &modTime

	if counts, err := templatesync.CategoryCounts(syncedDir); err == nil {
		data.CategoryCounts = counts
	}
	return data
}

// defaultWebTemplateDirsWithLabels mirrors cmd/hackerfive/templates.go's
// defaultTemplateDirsWithLabels — same "bundled always, synced if present"
// logic, reimplemented locally since sharing one function across the cmd/
// and pkg/webui package boundary isn't worth it for a handful of lines (same
// reasoning already applied to splitCSV and pkg/templatesync/list.go's
// tag-filter helpers).
func defaultWebTemplateDirsWithLabels() (dirs, labels []string) {
	dirs = []string{templatesync.DefaultBundledDir}
	labels = []string{"bundled"}

	if syncedDir, err := templatesync.DefaultSyncDir(); err == nil {
		if _, statErr := os.Stat(syncedDir); statErr == nil {
			dirs = append(dirs, syncedDir)
			labels = append(labels, "synced")
		}
	}
	return dirs, labels
}
