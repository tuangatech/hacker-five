package webui

import (
	"html/template"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// LaunchFormData is launch.html's input — the single unified entry point
// (doc14 Step 6) replacing New Scan/Recon/Guided Scan's three separate
// forms. Same "re-render with input intact on a validation error" shape
// those pages already used.
type LaunchFormData struct {
	CSRFToken string
	Errors    []string

	Target string

	RunMisconfig bool

	RunIdor  bool
	Endpoint string // idor's own field, rendered via detector_fields_idor

	RunAuthbypass  bool
	ProtectedPaths string // authbypass's own fields, rendered via detector_fields_authbypass
	LoginPaths     string
	LogoutPaths    string

	RunSsrf    bool
	SSRFParams string // ssrf's own fields, rendered via detector_fields_ssrf
	OOBServers string

	RunBusinesslogic bool
	AllowWrites      bool   // businesslogic's own fields, rendered via detector_fields_businesslogic — AllowWrites defaults false and is never recon-derived (CLAUDE.md's mutating-checks gate)
	CouponMintPath   string
	CouponApplyPath  string
	RaceConcurrency  int

	Tags string

	AuthToken        string
	OtherAuthToken   string
	AuthHeaderName   string
	AuthHeaderFormat string
	Headers          string // one "Name: Value" per line, mirrors repeatable --header

	RateLimit   int
	Concurrency int
	Insecure    bool
	ScopeFile   string
	Authorized  bool

	Tools ToolSetupData
}

// ProgressData is fragment_progress.html's input — the status badge shown
// both on initial render and pushed live via SSE (progress/done events).
// Waves is only non-empty when this Job ran an optional recon phase first.
type ProgressData struct {
	Status        string
	Phase         string // "" | "recon" | a detector name — which main step is currently running
	Err           error
	Waves         []WaveStatus
	DetectorSteps []WaveStatus
	Target        string // this job's target — only used to build the "New scan" link once Status is terminal
}

// CatchupData is fragment_catchup.html's input — an out-of-band re-sync of
// the progress badge and Recon Results against the job's *current* snapshot,
// fetched once the SSE connection actually opens. Closes a real gap: the
// browser's EventSource only receives events published after its own
// Subscribe() call registers, so anything published between job-start and
// connection-open (SetRunning, early wave transitions, a fast recon
// finishing before the connection opens) is silently missed — the page
// could sit on "queued" indefinitely even though the job had already
// finished. Deliberately narrow: only the two idempotent, last-value-wins
// fragments (progress badge, Recon Results) are re-synced this way, not
// Findings/Logs — those use hx-swap="afterbegin" (an append list), and
// blindly overwriting them here would risk duplicating rows already
// delivered live; a finding/log missed in the same narrow window still
// recovers via reload, same as before this fix.
type CatchupData struct {
	ProgressHTML template.HTML
	ReconHTML    template.HTML
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
	AllInstalled  bool   // true when every row is present — collapses the panel to a version summary, no "Setup now" button
	Error         string // friendly message when an install attempt failed; empty otherwise
	JustInstalled bool   // true only on POST /recon/setup's own response
}

// PlanPreviewData is plan_preview.html's (and fragment_plan_tree's) input.
type PlanPreviewData struct {
	JobID     string
	Target    string
	Tree      *agenttask.PlanTree
	IndexWarn string // non-empty when templates/index.json couldn't be loaded — degraded, not fatal

	Escalations   []string // leaves an LLM-fallback resolve pass couldn't resolve — see llmfallback.ResolveTreeLeaves
	SpendUSD      float64  // Tree.SpendSoFar() — zero until a resolve pass has run
	HasUnresolved bool     // drives whether the "Resolve via LLM fallback" button renders
	CSRFToken     string
}
