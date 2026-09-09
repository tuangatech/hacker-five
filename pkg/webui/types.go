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

	// ExtraTargets is the raw content of the "additional targets" textarea
	// (LT-115): zero or more hosts, one per line (blank lines and "#"
	// comments ignored), each scanned in the same Job alongside Target via
	// the engine's own per-target loop. Empty — the common case — is an
	// ordinary single-target launch, byte-identical to before. Recon still
	// runs once, against Target only; see runLaunchJob's multi-target note.
	ExtraTargets string

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
	// NarrowByTech opts into LT-16's (docs/follow-up.md) tech-stack-driven
	// template narrowing: when checked and recon detects at least one
	// actionable technology, each detector's loaded template corpus is
	// narrowed to tags registry.TechStackTags ranks relevant to that tech
	// stack, instead of running the full synced corpus regardless of what
	// recon found. Off by default — narrowing trades scan speed for
	// detection breadth, a tradeoff this project's default posture leaves
	// to the operator rather than silently applying to every scan (see
	// CLAUDE.md's detection philosophy: push for coverage by default).
	NarrowByTech bool

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
	JobID         string // this job's ID — the Cancel button's POST target (doc15 Step 4 kill switch)
	CSRFToken     string // the Cancel button's hidden csrf_token field
}

// CatchupData is fragment_catchup.html's input — an out-of-band re-sync of
// the job's *current* snapshot against a client whose SSE connection just
// opened. Closes a real gap: the browser's EventSource only receives events
// published after its own Subscribe() call registers, so anything published
// between job-start and connection-open (SetRunning, early wave transitions,
// a fast recon finishing before the connection opens) is silently missed —
// the page could sit on "queued" indefinitely even though the job had
// already finished.
//
// ProgressHTML/ReconHTML are the two idempotent, last-value-wins fragments —
// re-synced unconditionally as innerHTML swaps.
//
// LogsHTML/FindingsHTML (C5, follow-up.md LT-5) carry only the #logs/#findings
// rows this client actually missed: the catchup fetch reports the highest
// Seq already present in each list (scan_status.html's hfMaxSeq, reading the
// data-seq every row carries whether it arrived via the initial render or
// the live stream), and the handler replays only rows past that point.
// Append-list rows already delivered live are therefore never duplicated,
// and a row missed in the connect gap is no longer lost until a manual
// reload. Empty when the client missed nothing.
type CatchupData struct {
	ProgressHTML template.HTML
	ReconHTML    template.HTML
	LogsHTML     template.HTML
	FindingsHTML template.HTML
	AgentHTML    template.HTML
	// PlanPreviewLink re-syncs the header's Plan Preview link (LT-116): it's
	// part of scan_status.html's static header, not an sse-swap region, so a
	// client that connected before recon finished would otherwise never see
	// it appear without a manual reload. OOB is always true here.
	PlanPreviewLink PlanPreviewLinkData
}

// PlanPreviewLinkData drives fragment_plan_preview_link — the header's
// "Plan Preview" link, shown only once recon has produced a result (GET
// /plan-preview 409s before that). Rendered inline in scan_status.html's
// first paint and, live, as an hx-swap-oob update riding the recon SSE
// event and the catchup re-sync, so the link appears the moment recon
// finishes instead of only after a reload (LT-116).
type PlanPreviewLinkData struct {
	JobID     string
	ReconDone bool // snap.ReconResult != nil
	OOB       bool // render the wrapper <span> with hx-swap-oob (SSE/catchup); false for the inline first paint
}

// PlanPreviewLink is the header link state for scan_status.html's inline
// first render — OOB stays false; the live updates set it true themselves.
func (d ScanStatusData) PlanPreviewLink() PlanPreviewLinkData {
	return PlanPreviewLinkData{JobID: d.JobID, ReconDone: d.Snapshot.ReconResult != nil}
}

// ScanStatusData is what scan_status.html renders — the job's snapshot at
// page-load/reload time, per doc12's reconnect design (render this first,
// SSE only streams what happens after).
type ScanStatusData struct {
	JobID     string
	Target    string
	Snapshot  Snapshot
	CSRFToken string // scan_status.html's own hidden forms (e.g. a Plan Preview link needs none, but ProgressHTML's embedded Cancel form does — kept here too for any future direct use)

	FindingRowsHTML template.HTML
	LogLinesHTML    template.HTML
	AgentRowsHTML   template.HTML // this job's agent-activity log so far (C1), oldest-first
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

	Escalations     []string // leaves an LLM-fallback resolve pass couldn't resolve — see llmfallback.ResolveTreeLeaves
	SpendUSD        float64  // Tree.SpendSoFar() — zero until a resolve pass has run
	SpendCeilingUSD float64  // Tree.SpendCeilingUSD — the budget gauge's max (doc15 Step 4); zero means unset/no ceiling, gauge hidden
	HasUnresolved   bool     // drives whether the "Resolve via LLM fallback" button renders
	CSRFToken       string
}
