package webui

import (
	"context"
	"errors"
	"html/template"
	"sync"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// Job statuses.
const (
	StatusQueued   = "queued"
	StatusRunning  = "running"
	StatusDone     = "done"
	StatusFailed   = "failed"
	StatusCanceled = "canceled" // set by Cancel — the kill switch (doc15 Step 4), distinct from an ordinary failure
)

// SSE event types — must match the sse-swap values doc12's htmx design uses.
const (
	EventProgress = "progress"
	EventFinding  = "finding"
	EventLog      = "log"
	EventDone     = "done"
	EventRecon    = "recon"
)

// subscriberBuffer is each SSE subscriber's channel depth — a small buffer
// so a quick burst of events doesn't immediately drop, while the publish
// path stays non-blocking regardless (see Job.publish): a full buffer just
// drops that one live update, it never blocks the scan.
const subscriberBuffer = 16

// WaveStatus is one recon wave's current progress ("wave0".."wave3",
// "running"/"done") — pkg/recon.WithProgressCallback's payload. Originally
// ReconJob-only; moved onto Job when the unified launch page (doc14 Step 6)
// made recon an optional phase of the same Job a detector scan uses, instead
// of a separate job type.
type WaveStatus struct {
	Name   string
	Status string
}

// LogEntry is one warning/error line, as scanner.Engine's WithLogCallback
// delivers it. Time is pre-formatted (server-local, 24h "HH:MM") at
// AppendLog time rather than stored as time.Time — this codebase's existing
// convention for display-only values (see pkg/webui/recon_view.go's
// EndpointRow.DisplayURL): the Logs panel is the only consumer, and matching
// two long log lists side by side is much easier with a visible time on
// each line than by position alone.
type LogEntry struct {
	Level string
	Msg   string
	Time  string
}

// Event is one live update pushed to an SSE subscriber — HTML is
// pre-rendered (see Job's render funcs) so a finding/log looks identical
// whether it arrived via the initial page render or a live push, per
// docs/12-implementation-plan-ph3.md's design decision #3.
type Event struct {
	Type string
	HTML template.HTML
}

// Job is the durable source of truth for one scan run — both what
// GET /scans/{id} renders on initial load/reload and what
// GET /scans/{id}/events streams live, per doc12's "Backpressure and
// reconnect: one job store, not two buffers" design.
type Job struct {
	ID        string
	Target    string    // display only — the raw target list the form submitted, joined
	CreatedAt time.Time // set once at creation — drives Dashboard/Scan History ordering and display

	mu            sync.Mutex
	status        string
	phase         string // "" | "recon" | a detector name — which main step is currently running, doc14/15's "which step are we in" gap
	err           error
	findings      []detectors.Finding
	logs          []LogEntry
	waves         []WaveStatus       // set only when this Job runs an optional recon phase first
	detectorSteps []WaveStatus       // the planned detector pipeline, same update-or-append shape as waves — see SetDetectorStatus
	reconResult   *recon.ReconResult // nil until a recon phase (if any) completes
	subs          []chan Event

	// planTree/planEscalations cache a plan-preview "Resolve via LLM
	// fallback" pass's result (doc15 Step 2's 2026-09-03 addendum item 2) —
	// nil/empty until POST /plan-preview/resolve runs once for this job.
	// GET /plan-preview must prefer this over a fresh registry.Resolve once
	// set: re-resolving would silently discard the LLM's work and revert
	// leaves back to unresolved.
	planTree        *agenttask.PlanTree
	planEscalations []string

	// execCfg is the shared scanner.Config template (Scope, AuthToken,
	// RateLimit/Concurrency, ExtraHeaders, AllowWrites, TemplatePaths — see
	// SetExecConfig's caller) this job's own detector run started from,
	// cached so POST /plan-preview/execute (doc15 Step 4) can dispatch a
	// decision-engine-ranked leaf against the same target with the same
	// scope/credentials the operator already approved at launch time,
	// without asking them to re-enter anything on the Plan Preview page.
	execCfg scanner.Config

	// ctx/cancel are this job's own lifecycle context, derived from the
	// server's baseCtx (see bindParentContext) — every long-running call a
	// background job goroutine makes (recon, a detector run, a plan-
	// execution dispatch) should use ctx, not baseCtx directly, so Cancel
	// (the doc15 Step 4 kill switch) actually stops it rather than only
	// hiding it in the UI.
	ctx    context.Context
	cancel context.CancelFunc

	renderFinding  func(detectors.Finding) template.HTML
	renderLog      func(LogEntry) template.HTML
	renderProgress func(status string, err error, waves []WaveStatus, detectorSteps []WaveStatus, phase string) template.HTML
	renderRecon    func(*recon.ReconResult) template.HTML
}

func newJob(id, target string, renderFinding func(detectors.Finding) template.HTML, renderLog func(LogEntry) template.HTML, renderProgress func(status string, err error, waves []WaveStatus, detectorSteps []WaveStatus, phase string) template.HTML, renderRecon func(*recon.ReconResult) template.HTML) *Job {
	// A placeholder context.Background()-rooted context, immediately
	// replaced by bindParentContext once a real caller (startLaunch) has
	// h.baseCtx to derive from — kept here rather than making ctx/cancel
	// required constructor args so the many existing test call sites that
	// only care about rendering (newJob(id, target, ...)) don't all need
	// updating for a concern (server-shutdown/kill-switch propagation)
	// they don't exercise.
	ctx, cancel := context.WithCancel(context.Background())
	return &Job{
		ID:             id,
		Target:         target,
		CreatedAt:      time.Now(),
		status:         StatusQueued,
		ctx:            ctx,
		cancel:         cancel,
		renderFinding:  renderFinding,
		renderLog:      renderLog,
		renderProgress: renderProgress,
		renderRecon:    renderRecon,
	}
}

// bindParentContext replaces j's placeholder context with one derived from
// parent (the server's own baseCtx) — called once, right after newJob, by
// any caller that starts a real background job (startLaunch). The
// placeholder's cancel is invoked first purely for bookkeeping (it has no
// goroutines waiting on it yet); this is not itself a cancellation of j.
func (j *Job) bindParentContext(parent context.Context) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cancel()
	j.ctx, j.cancel = context.WithCancel(parent)
}

// Ctx is this job's own lifecycle context — every long-running call a
// background job goroutine makes should use this, not the server's baseCtx
// directly, so Cancel actually stops it.
func (j *Job) Ctx() context.Context {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.ctx
}

// Cancel is the doc15 Step 4 kill switch: cancels this job's own context.
// Any in-flight recon/scanner.Engine/planexec.RunPlan call reading Ctx()
// observes ctx.Done() on its next blocking operation and returns promptly;
// MarkDone then records StatusCanceled rather than StatusFailed once the
// job's own goroutine unwinds and calls it. Safe to call on an
// already-finished job (a no-op past that point — nothing is still reading
// ctx.Done() to react to it).
func (j *Job) Cancel() {
	j.mu.Lock()
	cancel := j.cancel
	j.mu.Unlock()
	cancel()
}

// SetExecConfig caches cfg as this job's shared scanner.Config template —
// see execCfg's own doc comment.
func (j *Job) SetExecConfig(cfg scanner.Config) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.execCfg = cfg
}

// ExecConfig returns this job's cached shared scanner.Config template, the
// zero value if SetExecConfig was never called (a job created outside the
// normal startLaunch path, e.g. in a test) — planexec.RunPlan's own
// per-leaf field gating (missingRequiredField) degrades a zero-value config
// to "every recon-derived-field leaf skipped, with a clear reason," not a
// crash.
func (j *Job) ExecConfig() scanner.Config {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.execCfg
}

// Snapshot is everything GET /scans/{id} needs to render the job's current
// state before attaching SSE — the reconnect-safety mechanism doc12 calls
// for: render this first, then SSE only needs to stream what happens after.
type Snapshot struct {
	Status        string
	Phase         string
	Err           error
	Findings      []detectors.Finding
	Logs          []LogEntry
	Waves         []WaveStatus
	DetectorSteps []WaveStatus
	ReconResult   *recon.ReconResult // nil unless this Job ran a recon phase that completed
}

func (j *Job) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return Snapshot{
		Status:        j.status,
		Phase:         j.phase,
		Err:           j.err,
		Findings:      append([]detectors.Finding(nil), j.findings...),
		Logs:          append([]LogEntry(nil), j.logs...),
		Waves:         append([]WaveStatus(nil), j.waves...),
		DetectorSteps: append([]WaveStatus(nil), j.detectorSteps...),
		ReconResult:   j.reconResult,
	}
}

// Subscribe registers a new live SSE subscriber and returns the channel to
// read events from plus an unsubscribe func the caller must invoke exactly
// once (typically via defer) when it stops listening — e.g. on client
// disconnect (r.Context().Done()). Without this, subs would only ever grow
// as htmx's SSE extension auto-reconnects over a scan's lifetime — see
// docs/12-implementation-plan-ph3.md's corrected "Backpressure and
// reconnect" design.
func (j *Job) Subscribe() (ch chan Event, unsubscribe func()) {
	ch = make(chan Event, subscriberBuffer)

	j.mu.Lock()
	j.subs = append(j.subs, ch)
	j.mu.Unlock()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			j.mu.Lock()
			for i, s := range j.subs {
				if s == ch {
					j.subs = append(j.subs[:i], j.subs[i+1:]...)
					break
				}
			}
			j.mu.Unlock()
			close(ch)
		})
	}
	return ch, unsubscribe
}

// publish sends ev to every current subscriber with a non-blocking send —
// a slow/dead subscriber never holds up the scan (see doc12's Backpressure
// note); it just misses that one live update, which the next Snapshot
// (or a page reload) already carries since AppendFinding/AppendLog append
// before ever publishing.
func (j *Job) publish(ev Event) {
	j.mu.Lock()
	subs := append([]chan Event(nil), j.subs...)
	j.mu.Unlock()

	for _, sub := range subs {
		select {
		case sub <- ev:
		default:
		}
	}
}

// AppendFinding records f (making it visible to any future Snapshot/page
// load immediately) then publishes it live — append-before-publish, so a
// dropped live push never loses the finding itself.
func (j *Job) AppendFinding(f detectors.Finding) {
	j.mu.Lock()
	j.findings = append(j.findings, f)
	j.mu.Unlock()

	j.publish(Event{Type: EventFinding, HTML: j.renderFinding(f)})
}

// AppendLog is AppendFinding's counterpart for scanner.Engine's
// WithLogCallback.
func (j *Job) AppendLog(level, msg string) {
	entry := LogEntry{Level: level, Msg: msg, Time: time.Now().Format("15:04")}
	j.mu.Lock()
	j.logs = append(j.logs, entry)
	j.mu.Unlock()

	j.publish(Event{Type: EventLog, HTML: j.renderLog(entry)})
}

// SetRunning transitions a queued job to running and publishes a progress
// event — called once, right before the scan actually starts.
func (j *Job) SetRunning() {
	j.mu.Lock()
	j.status = StatusRunning
	waves := append([]WaveStatus(nil), j.waves...)
	detectorSteps := append([]WaveStatus(nil), j.detectorSteps...)
	phase := j.phase
	j.mu.Unlock()
	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(StatusRunning, nil, waves, detectorSteps, phase)})
}

// SetPhase records which main step is currently running — recon, or one
// detector name — and publishes the same EventProgress event wave updates
// do. Distinct from Waves: this covers the coarser "what stage is the whole
// job in" question, including the detector-scan stage recon's own wave list
// says nothing about. A real gap found live 2026-09-01: once recon finished,
// nothing on the page indicated which detector (if any) was currently
// running — only the scrolling Logs panel had any signal, and only once
// that detector's own log lines started arriving.
func (j *Job) SetPhase(phase string) {
	j.mu.Lock()
	j.phase = phase
	waves := append([]WaveStatus(nil), j.waves...)
	detectorSteps := append([]WaveStatus(nil), j.detectorSteps...)
	curStatus, curErr := j.status, j.err
	j.mu.Unlock()
	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(curStatus, curErr, waves, detectorSteps, phase)})
}

// SetWaveStatus is pkg/recon.WithProgressCallback's target when a Job runs
// an optional recon phase first — updates (or appends) one wave's status and
// publishes the same EventProgress event SetRunning/MarkDone already do, so
// the wave list re-renders as part of the existing progress fragment rather
// than needing a new SSE event type. Moved here from the now-retired
// ReconJob (doc14 Step 6's unified launch page).
func (j *Job) SetWaveStatus(wave, waveStatus string) {
	j.mu.Lock()
	updated := false
	for i := range j.waves {
		if j.waves[i].Name == wave {
			j.waves[i].Status = waveStatus
			updated = true
			break
		}
	}
	if !updated {
		j.waves = append(j.waves, WaveStatus{Name: wave, Status: waveStatus})
	}
	waves := append([]WaveStatus(nil), j.waves...)
	detectorSteps := append([]WaveStatus(nil), j.detectorSteps...)
	curStatus, curErr, curPhase := j.status, j.err, j.phase
	j.mu.Unlock()

	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(curStatus, curErr, waves, detectorSteps, curPhase)})
}

// SetDetectorStatus is SetWaveStatus's counterpart for the detector
// pipeline — same update-or-append-by-name shape, so the same call both
// seeds a detector as "pending" (before the loop in runLaunchJob starts)
// and later transitions it to "running"/"done". A distinct method from
// SetWaveStatus (not a shared helper parameterized on which slice) because
// the two pipelines are conceptually distinct steps of a job, matching this
// package's existing preference for small, direct methods over an early
// generic abstraction.
func (j *Job) SetDetectorStatus(name, status string) {
	j.mu.Lock()
	updated := false
	for i := range j.detectorSteps {
		if j.detectorSteps[i].Name == name {
			j.detectorSteps[i].Status = status
			updated = true
			break
		}
	}
	if !updated {
		j.detectorSteps = append(j.detectorSteps, WaveStatus{Name: name, Status: status})
	}
	waves := append([]WaveStatus(nil), j.waves...)
	detectorSteps := append([]WaveStatus(nil), j.detectorSteps...)
	curStatus, curErr, curPhase := j.status, j.err, j.phase
	j.mu.Unlock()

	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(curStatus, curErr, waves, detectorSteps, curPhase)})
}

// SetReconResult records a completed recon phase's result — read by the
// results page's hosts/tech/endpoints tables and the "recon also suggests"
// callout. Distinct from MarkDone: a Job that runs recon then detectors
// isn't done just because recon finished. Publishes EventRecon so a client
// already watching the SSE stream sees the Recon Results tables appear live,
// rather than only after a manual reload of /scans/{id} — a real gap found
// live 2026-09-01: SetWaveStatus already published wave progress, but this
// method originally didn't publish anything at all.
func (j *Job) SetReconResult(result *recon.ReconResult) {
	j.mu.Lock()
	j.reconResult = result
	j.mu.Unlock()
	j.publish(Event{Type: EventRecon, HTML: j.renderRecon(result)})
}

// PlanTree returns this job's cached, I4-resolved PlanTree from a prior
// POST /plan-preview/resolve call, or nil if no resolve action has run yet
// for this job — the caller falls back to a fresh registry.Resolve in that
// case. escalations is a defensive copy, matching Snapshot's convention.
func (j *Job) PlanTree() (tree *agenttask.PlanTree, escalations []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.planTree, append([]string(nil), j.planEscalations...)
}

// SetPlanTree stores tree/escalations as this job's current resolved plan
// state, overwriting any previous resolve pass's result — tree is a full
// snapshot of the current best-known resolution (already mutated in place
// by llmfallback.ResolveTreeLeaves), not a delta to merge.
func (j *Job) SetPlanTree(tree *agenttask.PlanTree, escalations []string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.planTree = tree
	j.planEscalations = escalations
}

// MarkDone transitions the job to its terminal state (done or failed) and
// publishes an EventDone — the SSE handler's own signal to stop streaming
// and close the connection, since a reload of /scans/{id} at that point
// renders the final state directly with no SSE needed.
func (j *Job) MarkDone(err error) {
	j.mu.Lock()
	switch {
	case err != nil && errors.Is(err, context.Canceled):
		// The operator's own kill switch (Cancel), not a real failure —
		// StatusCanceled reads correctly in the UI instead of showing a
		// raw "context canceled" error. j.err deliberately stays nil: the
		// "cancel requested by operator" log line already explains why,
		// same info without an alarming error badge.
		j.status = StatusCanceled
	case err != nil:
		j.status = StatusFailed
		j.err = err
	default:
		j.status = StatusDone
	}
	j.phase = ""
	status := j.status
	waves := append([]WaveStatus(nil), j.waves...)
	detectorSteps := append([]WaveStatus(nil), j.detectorSteps...)
	j.mu.Unlock()

	j.publish(Event{Type: EventDone, HTML: j.renderProgress(status, err, waves, detectorSteps, "")})
}

// maxJobs caps the in-memory job store per doc12's corrected eviction
// policy — a fixed, stated starting number, not left unbounded.
const maxJobs = 50

// JobStore is the in-memory map every handler shares, keyed by job ID.
// Acceptable to lose on restart for the same reason hackerfive scan's
// output already is — see docs/12-implementation-plan-ph3.md's
// "Async job model."
type JobStore struct {
	mu    sync.Mutex
	jobs  map[string]*Job
	order []string // insertion order, oldest first — drives eviction
}

func newJobStore() *JobStore {
	return &JobStore{jobs: make(map[string]*Job)}
}

// Add stores j, evicting the oldest job past maxJobs.
func (s *JobStore) Add(j *Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = j
	s.order = append(s.order, j.ID)
	for len(s.order) > maxJobs {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.jobs, oldest)
	}
}

func (s *JobStore) Get(id string) (*Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	return j, ok
}

// JobSummary is the row shape Dashboard and Scan History both render — see
// fragment_job_row.html.
type JobSummary struct {
	ID           string
	Target       string
	Status       string
	FindingCount int
	CreatedAt    time.Time
}

// List returns every stored job's summary, most-recent-first. Each job's own
// mu is locked briefly per entry (matching Snapshot's per-job locking
// discipline) rather than holding the store lock for the whole walk.
func (s *JobStore) List() []JobSummary {
	s.mu.Lock()
	order := append([]string(nil), s.order...)
	s.mu.Unlock()

	summaries := make([]JobSummary, 0, len(order))
	for i := len(order) - 1; i >= 0; i-- {
		s.mu.Lock()
		j, ok := s.jobs[order[i]]
		s.mu.Unlock()
		if !ok {
			continue
		}
		j.mu.Lock()
		summaries = append(summaries, JobSummary{
			ID:           j.ID,
			Target:       j.Target,
			Status:       j.status,
			FindingCount: len(j.findings),
			CreatedAt:    j.CreatedAt,
		})
		j.mu.Unlock()
	}
	return summaries
}
