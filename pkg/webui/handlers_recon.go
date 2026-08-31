package webui

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// reconRunTimeout mirrors cmd/hackerfive/recon.go's own constant — bounds
// the whole multi-wave Run so a hung external binary can't stall a
// background job forever.
const reconRunTimeout = 10 * time.Minute

func (h *handlers) newReconForm(w http.ResponseWriter, r *http.Request) {
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	executeTemplate(w, h.tmpl, "new_recon.html", ReconFormData{
		CSRFToken:   token,
		Depth:       string(recon.DepthActive), // matches cmd/hackerfive/plan.go's own default/rationale: Wave 2's httpx tech signals are what the decision engine matches against
		RateLimit:   recon.DefaultRateLimit,
		Concurrency: recon.DefaultConcurrency,
	})
}

// startRecon is POST /recon. r.Form/r.PostForm are already populated by
// csrfMiddleware, same precondition startScan documents.
func (h *handlers) startRecon(w http.ResponseWriter, r *http.Request) {
	form, errs := reconFormFromRequest(r)

	if len(errs) > 0 {
		h.rerenderReconFormWithErrors(w, r, form, errs)
		return
	}

	id, err := randomHex(8)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	job := newReconJob(id, form.Target, form.Depth, func(status string, err error) template.HTML {
		return renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: status, Err: err})
	})
	h.reconStore.Add(job)

	go h.runReconJob(job, form)

	w.Header().Set("HX-Push-Url", "/recon/"+job.ID)
	executeTemplate(w, h.tmpl, "fragment_recon_status_body", h.reconSnapshotData(job))
}

func (h *handlers) rerenderReconFormWithErrors(w http.ResponseWriter, r *http.Request, form ReconFormData, errs []string) {
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	form.CSRFToken = token
	form.Errors = errs
	w.WriteHeader(http.StatusUnprocessableEntity)
	executeTemplate(w, h.tmpl, "new_recon.html", form)
}

// runReconJob runs recon in the background, on the server's lifecycle
// context — same reasoning as runJob (handlers_scan.go): a recon run must
// outlive the HTTP request that started it.
func (h *handlers) runReconJob(job *ReconJob, form ReconFormData) {
	job.SetRunning()

	var s *scope.Scope
	if form.ScopeFile != "" {
		parsed, err := scope.Parse(form.ScopeFile)
		if err != nil {
			job.MarkDone(nil, fmt.Errorf("parsing scope file: %w", err))
			return
		}
		s = parsed
	}

	client := httpclient.New(httpclient.Config{
		Timeout:             defaultTimeout,
		MaxRedirects:        5,
		InsecureSkipVerify:  form.Insecure,
		MaxIdleConnsPerHost: form.Concurrency,
	}, httpclient.WithRateLimit(ratelimit.New(form.RateLimit)))

	opts := []recon.Option{recon.WithRateLimit(form.RateLimit), recon.WithConcurrency(form.Concurrency)}
	if s != nil {
		opts = append(opts, recon.WithScope(s))
	}
	r := recon.New(client, opts...)

	ctx, cancel := context.WithTimeout(h.baseCtx, reconRunTimeout)
	defer cancel()

	result, err := r.Run(ctx, form.Target, recon.Depth(form.Depth))
	job.MarkDone(result, err)
}

func (h *handlers) reconStatus(w http.ResponseWriter, r *http.Request) {
	job, ok := h.reconStore.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	executeTemplate(w, h.tmpl, "recon_status.html", h.reconSnapshotData(job))
}

// reconEvents is GET /recon/{id}/events, the SSE stream. Structurally
// mirrors scanEvents (handlers_scan.go) but only ever has one terminal
// event to send — recon.Run has no incremental callback to stream.
func (h *handlers) reconEvents(w http.ResponseWriter, r *http.Request) {
	job, ok := h.reconStore.Get(r.PathValue("id"))
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

// reconSnapshotData builds the initial-render data for both recon_status.html
// and startRecon's response fragment — one job snapshot, two callers, same
// reasoning as snapshotData (handlers_scan.go).
func (h *handlers) reconSnapshotData(job *ReconJob) ReconStatusData {
	snap := job.Snapshot()
	return ReconStatusData{
		JobID:        job.ID,
		Target:       job.Target,
		Depth:        job.Depth,
		Snapshot:     snap,
		ProgressHTML: renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: snap.Status, Err: snap.Err}),
	}
}

// reconFormFromRequest maps POST /recon's form values onto ReconFormData —
// same errs-list validation style as buildScanConfig (handlers_scan.go).
func reconFormFromRequest(r *http.Request) (ReconFormData, []string) {
	var errs []string

	target := strings.TrimSpace(r.PostFormValue("target"))
	if target == "" {
		errs = append(errs, "target is required")
	}

	depth := r.PostFormValue("depth")
	switch recon.Depth(depth) {
	case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
	default:
		errs = append(errs, `depth must be "passive", "active", or "full"`)
	}

	rateLimit, err := parsePositiveInt(r.PostFormValue("rate_limit"), recon.DefaultRateLimit)
	if err != nil {
		errs = append(errs, "rate limit must be a positive integer")
	}
	concurrency, err := parsePositiveInt(r.PostFormValue("concurrency"), recon.DefaultConcurrency)
	if err != nil {
		errs = append(errs, "concurrency must be a positive integer")
	}

	return ReconFormData{
		Target:      target,
		Depth:       depth,
		ScopeFile:   r.PostFormValue("scope_file"),
		RateLimit:   rateLimit,
		Concurrency: concurrency,
		Insecure:    r.PostFormValue("insecure") == "on",
	}, errs
}
