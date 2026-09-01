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
		if err := writeSSEEvent(w, Event{Type: EventDone, HTML: renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Err: snap.Err, Waves: snap.Waves})}); err == nil {
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
// and log lines are rendered newest-first: the live SSE stream appends new
// ones via hx-swap="afterbegin" (doc14 Step 6's "Scan Activity" redesign),
// so the very first paint must already match that order, not the other way
// around (oldest-first, matching the old "beforeend" behavior).
func (h *handlers) snapshotData(job *Job) ScanStatusData {
	snap := job.Snapshot()

	var findingsHTML strings.Builder
	for i := len(snap.Findings) - 1; i >= 0; i-- {
		findingsHTML.WriteString(string(renderFragment(h.tmpl, "fragment_finding_row", snap.Findings[i])))
	}
	var logsHTML strings.Builder
	for i := len(snap.Logs) - 1; i >= 0; i-- {
		logsHTML.WriteString(string(renderFragment(h.tmpl, "fragment_log_line", snap.Logs[i])))
	}

	return ScanStatusData{
		JobID:           job.ID,
		Target:          job.Target,
		Snapshot:        snap,
		FindingRowsHTML: template.HTML(findingsHTML.String()), //nolint:gosec // built only from our own already-escaped fragment renders, not raw input
		LogLinesHTML:    template.HTML(logsHTML.String()),     //nolint:gosec // same
		ProgressHTML:    renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Err: snap.Err, Waves: snap.Waves}),
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
