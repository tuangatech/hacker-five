package webui

import (
	"html/template"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// NewScanData is what new_scan.html renders — form defaults/echoed values
// plus any validation errors, so a rejected submission re-renders with the
// operator's input intact rather than losing it.
type NewScanData struct {
	CSRFToken string
	Errors    []string

	Detector    string
	Targets     string
	Tags        string
	RateLimit   int
	Concurrency int
	Proxy       string
	Timeout     string
	Insecure    bool
	ScopeFile   string

	AuthToken        string
	OtherAuthToken   string
	AuthHeaderName   string
	AuthHeaderFormat string
	Headers          string // one "Name: Value" per line, mirrors repeatable --header

	Endpoint       string // idor only
	ProtectedPaths string // authbypass only
	LoginPaths     string
	LogoutPaths    string

	DetectorFieldsHTML template.HTML // pre-rendered detector_fields_* fragment for the initially-selected detector
}

// ProgressData is fragment_progress.html's input — the status badge shown
// both on initial render and pushed live via SSE (progress/done events).
type ProgressData struct {
	Status string
	Err    error
}

// ScanStatusData is what scan_status.html renders — the job's snapshot at
// page-load/reload time, per doc12's reconnect design (render this first,
// SSE only streams what happens after).
type ScanStatusData struct {
	JobID    string
	Target   string
	Snapshot Snapshot

	FindingRowsHTML template.HTML
	LogLinesHTML    template.HTML
	ProgressHTML    template.HTML
}

// DashboardData is dashboard.html's input.
type DashboardData struct {
	RecentJobs []JobSummary
	HasMore    bool
}

// ScanHistoryData is scan_history.html's input.
type ScanHistoryData struct {
	Jobs []JobSummary
}

// SyncPanelData is the sync-panel half of the Templates page — both its
// initial render (embedded in TemplatesPageData) and POST /templates/sync's
// fragment_sync_status response (design decision 5: always 200, success or a
// friendly failure message).
type SyncPanelData struct {
	PinnedCommit   string
	SyncedDir      string
	LastSynced     *time.Time // nil = never synced
	Categories     []string   // stable display order, mirrors templatesync.Categories
	CategoryCounts map[string]int
	Error          string // friendly message when a sync attempt failed; empty otherwise
	JustSynced     bool   // true only on POST /templates/sync's own response — drives "synced just now" wording
}

// TemplateTableData is fragment_template_table's input — the active-template
// list plus the tag filter's current value, so the filter input keeps
// showing what's actually applied after an hx-get swap.
type TemplateTableData struct {
	Entries  []templatesync.Entry
	Rejected int
	Tags     string
}

// TemplatesPageData is templates_page.html's full-page input.
type TemplatesPageData struct {
	CSRFToken string
	Table     TemplateTableData
	Sync      SyncPanelData
}

// ReconFormData is new_recon.html's input — form defaults/echoed values plus
// any validation errors, same "re-render with input intact" shape as
// NewScanData.
type ReconFormData struct {
	CSRFToken string
	Errors    []string

	Target      string
	Depth       string
	ScopeFile   string
	RateLimit   int
	Concurrency int
	Insecure    bool

	Tools ToolSetupData
}

// ReconStatusData is what recon_status.html (and startRecon's response
// fragment) renders — the job's snapshot at page-load/reload time, same
// reconnect-safety shape as ScanStatusData.
type ReconStatusData struct {
	CSRFToken string
	JobID     string
	Target    string
	Depth     string

	Snapshot ReconSnapshot

	ProgressHTML template.HTML

	Tools ToolSetupData
}

// ToolStatusRow is one recon binary's row in the tool-setup panel.
type ToolStatusRow struct {
	Name      string
	Installed bool
	Version   string
}

// ToolSetupData is fragment_tool_setup_status.html's input — mirrors
// SyncPanelData's own shape (Error/JustInstalled play the same role as
// Error/JustSynced there) for the same kind of concern, different payload.
type ToolSetupData struct {
	Dir           string
	Rows          []ToolStatusRow
	Error         string // friendly message when an install attempt failed; empty otherwise
	JustInstalled bool   // true only on POST /recon/setup's own response
}

// PlanPreviewData is plan_preview.html's input.
type PlanPreviewData struct {
	JobID     string
	Target    string
	Tree      *agenttask.PlanTree
	IndexWarn string // non-empty when templates/index.json couldn't be loaded — degraded, not fatal
}
