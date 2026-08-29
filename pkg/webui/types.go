package webui

import "html/template"

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
