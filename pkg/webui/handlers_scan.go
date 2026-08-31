package webui

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// defaultRateLimit/defaultConcurrency/defaultTimeout mirror
// cmd/hackerfive/scan.go's own CLI flag defaults, so the web form pre-fills
// with the same values a CLI user gets without passing any flags.
const (
	defaultRateLimit   = 50
	defaultConcurrency = 25
	defaultTimeout     = 30 * time.Second
)

// sseKeepAlive is how often a comment-only ping is sent on an idle SSE
// connection — standard SSE practice to prevent some proxies/browsers from
// treating a quiet connection as dead.
const sseKeepAlive = 15 * time.Second

// handlers holds what every scan-related route needs. baseCtx is the
// server's own lifecycle context (from Server.ListenAndServe), not any one
// request's context — a scan must keep running after the HTTP request that
// started it returns, and should only be cancelled on server shutdown.
type handlers struct {
	tmpl       *template.Template
	store      *JobStore
	reconStore *ReconJobStore
	baseCtx    context.Context
}

func (h *handlers) newScanForm(w http.ResponseWriter, r *http.Request) {
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := NewScanData{
		CSRFToken:   token,
		Detector:    "misconfig",
		Tags:        r.URL.Query().Get("tags"), // prefilled via the Templates page's tag links (docs/12-implementation-plan-ph3.md design decision 1)
		RateLimit:   defaultRateLimit,
		Concurrency: defaultConcurrency,
		Timeout:     defaultTimeout.String(),
	}
	data.DetectorFieldsHTML = renderFragment(h.tmpl, "detector_fields_misconfig", data)
	executeTemplate(w, h.tmpl, "new_scan.html", data)
}

func (h *handlers) detectorFields(w http.ResponseWriter, r *http.Request) {
	detector := r.URL.Query().Get("detector")
	switch detector {
	case "idor", "authbypass", "misconfig":
	default:
		http.Error(w, "unknown detector", http.StatusBadRequest)
		return
	}
	executeTemplate(w, h.tmpl, "detector_fields_"+detector, NewScanData{})
}

// startScan is POST /scans. r.Form/r.PostForm are already populated —
// csrfMiddleware calls r.ParseForm() for every non-GET request before its
// own check, so by the time this handler runs the form is parsed.
func (h *handlers) startScan(w http.ResponseWriter, r *http.Request) {
	cfg, errs := buildScanConfig(r)

	if r.PostFormValue("authorized") != "on" {
		errs = append(errs, "you must confirm you are authorized to scan this target")
	}

	if len(errs) == 0 {
		if err := cfg.Validate(); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		h.rerenderFormWithErrors(w, r, errs)
		return
	}

	id, err := randomHex(8)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	job := newJob(id, strings.Join(cfg.Targets, ", "),
		func(f detectors.Finding) template.HTML { return renderFragment(h.tmpl, "fragment_finding_row", f) },
		func(entry LogEntry) template.HTML { return renderFragment(h.tmpl, "fragment_log_line", entry) },
		func(status string, err error) template.HTML {
			return renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: status, Err: err})
		},
	)
	// The authorization checkbox becomes the job's first log entry — the
	// "audit trail" doc12 calls for; no separate audit mechanism exists or
	// is being built here, this reuses the one logging surface that already
	// does (see docs/12-implementation-plan-ph3.md's design decision #7).
	job.AppendLog("info", "authorized: target(s) confirmed by operator acknowledgment")
	h.store.Add(job)

	go h.runJob(job, cfg)

	w.Header().Set("HX-Push-Url", "/scans/"+job.ID)
	executeTemplate(w, h.tmpl, "fragment_scan_status_body", h.snapshotData(job))
}

func (h *handlers) rerenderFormWithErrors(w http.ResponseWriter, r *http.Request, errs []string) {
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := formDataFromRequest(r, token, errs)
	data.DetectorFieldsHTML = renderFragment(h.tmpl, "detector_fields_"+data.Detector, data)
	w.WriteHeader(http.StatusUnprocessableEntity)
	executeTemplate(w, h.tmpl, "new_scan.html", data)
}

// runJob runs the scan in the background, on the server's lifecycle
// context — not the HTTP request's, which ends when startScan returns,
// long before a real scan finishes.
func (h *handlers) runJob(job *Job, cfg scanner.Config) {
	job.SetRunning()
	_, err := scanner.New(cfg).
		WithFindingCallback(job.AppendFinding).
		WithLogCallback(job.AppendLog).
		Run(h.baseCtx)
	job.MarkDone(err)
}

func (h *handlers) scanStatus(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	executeTemplate(w, h.tmpl, "scan_status.html", h.snapshotData(job))
}

func (h *handlers) exportJSON(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	snap := job.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-findings.json"`, job.ID))
	if err := reporter.WriteJSON(w, snap.Findings); err != nil {
		log.Printf("webui: exporting job %s: %v", job.ID, err)
	}
}

// scanEvents is GET /scans/{id}/events, the SSE stream. Per doc12's
// reconnect design, GET /scans/{id} already renders the current snapshot —
// this only needs to stream what happens after that point.
func (h *handlers) scanEvents(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// A job that's already finished by the time a client connects (or
	// reconnects) needs no live stream — send the final state once and
	// close, rather than holding a connection open for nothing.
	if snap := job.Snapshot(); snap.Status == StatusDone || snap.Status == StatusFailed {
		if err := writeSSEEvent(w, Event{Type: EventDone, HTML: renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Err: snap.Err})}); err == nil {
			flusher.Flush()
		}
		return
	}

	ch, unsubscribe := job.Subscribe()
	defer unsubscribe()

	ticker := time.NewTicker(sseKeepAlive)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSEEvent(w, ev); err != nil {
				return
			}
			flusher.Flush()
			if ev.Type == EventDone {
				return
			}
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeSSEEvent writes ev in the SSE wire format. HTML may itself contain
// newlines (every template file here does) — the SSE spec requires one
// "data: " line per line of payload, which htmx's SSE extension correctly
// rejoins with \n before swapping; a single "data:" line with embedded
// newlines would truncate at the first line instead.
func writeSSEEvent(w http.ResponseWriter, ev Event) error {
	if _, err := fmt.Fprintf(w, "event: %s\n", ev.Type); err != nil {
		return err
	}
	for _, line := range strings.Split(string(ev.HTML), "\n") {
		if _, err := fmt.Fprintf(w, "data: %s\n", line); err != nil {
			return err
		}
	}
	_, err := fmt.Fprint(w, "\n")
	return err
}

// snapshotData builds the initial-render data for both scan_status.html
// (full page) and startScan's response fragment — one job snapshot, two
// callers, so a page load and a form-submit response always agree.
func (h *handlers) snapshotData(job *Job) ScanStatusData {
	snap := job.Snapshot()

	var findingsHTML strings.Builder
	for _, f := range snap.Findings {
		findingsHTML.WriteString(string(renderFragment(h.tmpl, "fragment_finding_row", f)))
	}
	var logsHTML strings.Builder
	for _, l := range snap.Logs {
		logsHTML.WriteString(string(renderFragment(h.tmpl, "fragment_log_line", l)))
	}

	return ScanStatusData{
		JobID:           job.ID,
		Target:          job.Target,
		Snapshot:        snap,
		FindingRowsHTML: template.HTML(findingsHTML.String()), //nolint:gosec // built only from our own already-escaped fragment renders, not raw input
		LogLinesHTML:    template.HTML(logsHTML.String()),     //nolint:gosec // same
		ProgressHTML:    renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Err: snap.Err}),
	}
}

// buildScanConfig maps POST /scans' form values onto scanner.Config —
// the web-form counterpart to cmd/hackerfive/scan.go's flag-to-Config
// mapping, reading r.PostFormValue instead of cobra flags since the input
// source differs; the resulting Config fields are identical either way, and
// cfg.Validate() (called by the caller once errs is empty) is the single
// shared source of truth for per-detector required fields either path
// takes.
func buildScanConfig(r *http.Request) (scanner.Config, []string) {
	var errs []string

	targets := parseTargetsFromTextarea(r.PostFormValue("targets"))
	if len(targets) == 0 {
		errs = append(errs, "at least one target is required")
	}

	rateLimit, err := parsePositiveInt(r.PostFormValue("rate_limit"), defaultRateLimit)
	if err != nil {
		errs = append(errs, "rate limit must be a positive integer")
	}
	concurrency, err := parsePositiveInt(r.PostFormValue("concurrency"), defaultConcurrency)
	if err != nil {
		errs = append(errs, "concurrency must be a positive integer")
	}

	timeout := defaultTimeout
	if raw := r.PostFormValue("timeout"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			timeout = d
		} else {
			errs = append(errs, "timeout must be a duration like 30s")
		}
	}

	extraHeaders, err := parseHeaderLines(r.PostFormValue("headers"))
	if err != nil {
		errs = append(errs, err.Error())
	}

	cfg := scanner.Config{
		Targets:          targets,
		TemplatePaths:    defaultWebTemplateDirs(),
		Tags:             splitCSV(r.PostFormValue("tags")),
		Concurrency:      concurrency,
		RateLimit:        rateLimit,
		ProxyURL:         r.PostFormValue("proxy"),
		Timeout:          timeout,
		OutputFormat:     "json",
		Detector:         r.PostFormValue("detector"),
		EndpointTemplate: r.PostFormValue("endpoint"),
		Insecure:         r.PostFormValue("insecure") == "on",
		AuthToken:        r.PostFormValue("auth_token"),
		OtherAuthToken:   r.PostFormValue("other_auth_token"),
		AuthHeaderName:   r.PostFormValue("auth_header_name"),
		AuthHeaderFormat: r.PostFormValue("auth_header_format"),
		ScopeFile:        r.PostFormValue("scope_file"),
		ProtectedPaths:   splitCSV(r.PostFormValue("protected_paths")),
		LoginPaths:       splitCSV(r.PostFormValue("login_paths")),
		LogoutPaths:      splitCSV(r.PostFormValue("logout_paths")),
		ExtraHeaders:     extraHeaders,
	}
	return cfg, errs
}

// defaultWebTemplateDirs mirrors cmd/hackerfive/scan.go's --templates
// default-plus-auto-append behavior: the bundled directory, plus the synced
// directory if 'hackerfive templates sync' has ever been run — so a scan
// started from the web UI sees the same template corpus a default CLI scan
// would, without a template-selection field the form doesn't have (Week 23
// adds the Templates page).
func defaultWebTemplateDirs() []string {
	dirs := []string{templatesync.DefaultBundledDir}
	if syncedDir, err := templatesync.DefaultSyncDir(); err == nil {
		if _, statErr := os.Stat(syncedDir); statErr == nil {
			dirs = append(dirs, syncedDir)
		}
	}
	return dirs
}

func formDataFromRequest(r *http.Request, token string, errs []string) NewScanData {
	rateLimit, _ := strconv.Atoi(r.PostFormValue("rate_limit"))
	if rateLimit <= 0 {
		rateLimit = defaultRateLimit
	}
	concurrency, _ := strconv.Atoi(r.PostFormValue("concurrency"))
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	detector := r.PostFormValue("detector")
	if detector == "" {
		detector = "misconfig"
	}

	return NewScanData{
		CSRFToken:        token,
		Errors:           errs,
		Detector:         detector,
		Targets:          r.PostFormValue("targets"),
		Tags:             r.PostFormValue("tags"),
		RateLimit:        rateLimit,
		Concurrency:      concurrency,
		Proxy:            r.PostFormValue("proxy"),
		Timeout:          r.PostFormValue("timeout"),
		Insecure:         r.PostFormValue("insecure") == "on",
		ScopeFile:        r.PostFormValue("scope_file"),
		AuthToken:        r.PostFormValue("auth_token"),
		OtherAuthToken:   r.PostFormValue("other_auth_token"),
		AuthHeaderName:   r.PostFormValue("auth_header_name"),
		AuthHeaderFormat: r.PostFormValue("auth_header_format"),
		Headers:          r.PostFormValue("headers"),
		Endpoint:         r.PostFormValue("endpoint"),
		ProtectedPaths:   r.PostFormValue("protected_paths"),
		LoginPaths:       r.PostFormValue("login_paths"),
		LogoutPaths:      r.PostFormValue("logout_paths"),
	}
}

func parsePositiveInt(raw string, def int) (int, error) {
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("must be a positive integer, got %q", raw)
	}
	return n, nil
}

// parseTargetsFromTextarea splits a browser textarea's one-target-per-line
// value. Unlike cmd/hackerfive/scan.go's resolveTargets, this never treats
// a value as a filesystem path — a browser form has no meaningful "path on
// the server" concept for this field, so it's a small, deliberately
// separate parser (see docs/12-implementation-plan-ph3.md's design
// decision #5).
func parseTargetsFromTextarea(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// splitCSV is the shared comma-separated-value parser for --tags/
// --protected-paths/--login-paths/--logout-paths' form equivalents — same
// trim-and-drop-empty semantics as cmd/hackerfive/scan.go's parseTags,
// reimplemented locally rather than shared across the package boundary
// (small, proportionate duplication, same reasoning as
// pkg/templatesync/list.go's tag-filter helpers).
func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// parseHeaderLines is --header's web-form equivalent: one "Name: Value" per
// textarea line instead of a repeatable CLI flag, same first-colon-splits
// semantics as cmd/hackerfive/scan.go's parseHeaders.
func parseHeaderLines(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	headers := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			return nil, fmt.Errorf("header line %q must be in \"Name: Value\" form", line)
		}
		headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return headers, nil
}
