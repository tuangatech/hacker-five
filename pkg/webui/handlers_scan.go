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

	"github.com/tuangatech/hacker-five/pkg/detectors/ssrf"
	"github.com/tuangatech/hacker-five/pkg/reporter"
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

// llmAssistedExecConcurrency mirrors pkg/mcpserver's own constant of the
// same name — caps how many use_existing_tag/LLM-resolved plan leaves
// planexec.RunPlan dispatches in parallel (doc15 Step 2's Done note: this
// tier split is about resolution provenance, not "deterministic vs.
// currently-costing-LLM" — execution itself never calls an LLM either way).
const llmAssistedExecConcurrency = 3

// defaultOOBServers mirrors cmd/hackerfive/scan.go's --oob-server default
// (ssrf.DefaultOOBServers) — same source of truth, joined for the form's
// plain-text field. A user who wants no OOB check just clears the field
// before submitting (a plain <input>, unlike the CLI's StringArray flag,
// naturally supports "explicitly empty").
var defaultOOBServers = strings.Join(ssrf.DefaultOOBServers, ",")

// sseKeepAlive is how often a comment-only ping is sent on an idle SSE
// connection — standard SSE practice to prevent some proxies/browsers from
// treating a quiet connection as dead.
const sseKeepAlive = 15 * time.Second

// handlers holds what every scan-related route needs. baseCtx is the
// server's own lifecycle context (from Server.ListenAndServe), not any one
// request's context — a scan must keep running after the HTTP request that
// started it returns, and should only be cancelled on server shutdown.
type handlers struct {
	tmpl    *template.Template
	store   *JobStore
	baseCtx context.Context
}

func (h *handlers) scanStatus(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	executeTemplate(w, h.tmpl, "scan_status.html", h.snapshotData(job, token))
}

// cancelScan is POST /scans/{id}/cancel — the doc15 Step 4 kill switch,
// reachable from every running job's own progress fragment (New Scan,
// Guided Scan, and a plan-execution run alike, since all three render
// fragment_progress). Cancels the job's own context and appends an
// explanatory log line; the job's own goroutine observes ctx.Done() on its
// next blocking call and calls MarkDone itself (StatusCanceled — see
// Job.MarkDone), which is what actually stops the SSE stream and finalizes
// the badge. This handler just acks the click with the current snapshot;
// it does not wait for the job to actually finish unwinding.
func (h *handlers) cancelScan(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	job.AppendLog("info", "cancel requested by operator")
	job.Cancel()

	snap := job.Snapshot()
	executeTemplate(w, h.tmpl, "fragment_progress", ProgressData{
		Status: snap.Status, Phase: snap.Phase, Err: snap.Err,
		Waves: snap.Waves, DetectorSteps: snap.DetectorSteps,
		Target: job.Target, JobID: job.ID, CSRFToken: readCSRFCookie(r),
	})
}

// scanCatchup is GET /scans/{id}/catchup — fired once by the browser's own
// htmx:sseOpen event (see scan_status.html), right after its SSE connection
// actually opens. Re-syncs the progress badge and Recon Results against the
// job's *current* snapshot via an out-of-band swap (CatchupData), closing
// the gap where anything published between job-start and connection-open
// (a fast recon/scan racing ahead of the browser's own connection setup)
// would otherwise never reach this client. Deliberately excludes
// Findings/Logs — see CatchupData's own doc comment for why.
func (h *handlers) scanCatchup(w http.ResponseWriter, r *http.Request) {
	job, ok := h.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	snap := job.Snapshot()
	executeTemplate(w, h.tmpl, "fragment_catchup", CatchupData{
		ProgressHTML: renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Phase: snap.Phase, Err: snap.Err, Waves: snap.Waves, DetectorSteps: snap.DetectorSteps, Target: job.Target, JobID: job.ID, CSRFToken: readCSRFCookie(r)}),
		ReconHTML:    renderFragment(h.tmpl, "fragment_recon_results", newReconView(snap.ReconResult)),
	})
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
	if snap := job.Snapshot(); snap.Status == StatusDone || snap.Status == StatusFailed || snap.Status == StatusCanceled {
		if err := writeSSEEvent(w, Event{Type: EventDone, HTML: renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Phase: snap.Phase, Err: snap.Err, Waves: snap.Waves, DetectorSteps: snap.DetectorSteps, Target: job.Target, JobID: job.ID, CSRFToken: readCSRFCookie(r)})}); err == nil {
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
// (full page) and startLaunch's response fragment — one job snapshot, two
// callers, so a page load and a form-submit response always agree. Findings
// are rendered newest-first: the live SSE stream appends new ones via
// hx-swap="afterbegin" (doc14 Step 6's "Scan Activity" redesign), so the
// very first paint must already match that order. Log lines are the
// opposite — rendered oldest-first (chronological, matching snap.Logs'
// own append order) since the live SSE stream appends new ones via
// hx-swap="beforeend" on #logs; the page auto-scrolls #logs to its bottom
// on load and on every new line so the newest entry stays visible without
// the reversed order findings needs.
func (h *handlers) snapshotData(job *Job, csrfTok string) ScanStatusData {
	snap := job.Snapshot()

	var findingsHTML strings.Builder
	for i := len(snap.Findings) - 1; i >= 0; i-- {
		findingsHTML.WriteString(string(renderFragment(h.tmpl, "fragment_finding_row", snap.Findings[i])))
	}
	var logsHTML strings.Builder
	for _, entry := range snap.Logs {
		logsHTML.WriteString(string(renderFragment(h.tmpl, "fragment_log_line", entry)))
	}

	return ScanStatusData{
		JobID:           job.ID,
		Target:          job.Target,
		Snapshot:        snap,
		CSRFToken:       csrfTok,
		FindingRowsHTML: template.HTML(findingsHTML.String()), //nolint:gosec // built only from our own already-escaped fragment renders, not raw input
		LogLinesHTML:    template.HTML(logsHTML.String()),     //nolint:gosec // same
		ProgressHTML:    renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Phase: snap.Phase, Err: snap.Err, Waves: snap.Waves, DetectorSteps: snap.DetectorSteps, Target: job.Target, JobID: job.ID, CSRFToken: csrfTok}),
	}
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
