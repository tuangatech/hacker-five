package webui

import (
	"net/http"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/toolsync"
)

// buildToolSetupData mirrors buildSyncPanelData (handlers_templates.go)
// exactly, for the same kind of concern: the current on-disk state of the
// 6 recon binaries, no network call — Status is file-existence-based, safe
// to call on every page render.
func buildToolSetupData(justInstalled bool, errMsg string) ToolSetupData {
	data := ToolSetupData{Error: errMsg, JustInstalled: justInstalled}

	dir, err := toolsync.DefaultInstallDir()
	if err != nil {
		return data
	}
	data.Dir = dir

	for _, s := range toolsync.Status(dir) {
		data.Rows = append(data.Rows, ToolStatusRow{Name: s.Name, Installed: s.Installed, Version: s.Version})
	}
	return data
}

// setupTools is POST /recon/setup. csrfMiddleware has already validated the
// CSRF cookie/field by the time this runs. Always responds 200 (same design
// decision syncTemplates already established, handlers_templates.go) — a
// failed or partial install is a valid, successfully-processed operational
// result, not a malformed request; per-tool failures are summarized in the
// rendered panel, not swallowed.
func (h *handlers) setupTools(w http.ResponseWriter, r *http.Request) {
	dir, err := toolsync.DefaultInstallDir()
	if err != nil {
		executeTemplate(w, h.tmpl, "fragment_tool_setup_status", buildToolSetupData(true, "resolving the install directory failed: "+err.Error()))
		return
	}

	result := toolsync.Install(r.Context(), dir, nil)

	var failures []string
	for _, tr := range result.Tools {
		if !tr.OK {
			failures = append(failures, tr.Name+": "+tr.Err)
		}
	}

	errMsg := ""
	if len(failures) > 0 {
		errMsg = strings.Join(failures, "; ")
	}
	executeTemplate(w, h.tmpl, "fragment_tool_setup_status", buildToolSetupData(true, errMsg))
}
