package webui

import (
	"html/template"
	"sync"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// Job statuses.
const (
	StatusQueued  = "queued"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// SSE event types — must match the sse-swap values doc12's htmx design uses.
const (
	EventProgress = "progress"
	EventFinding  = "finding"
	EventLog      = "log"
	EventDone     = "done"
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
// delivers it.
type LogEntry struct {
	Level string
	Msg   string
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

	mu          sync.Mutex
	status      string
	err         error
	findings    []detectors.Finding
	logs        []LogEntry
	waves       []WaveStatus       // set only when this Job runs an optional recon phase first
	reconResult *recon.ReconResult // nil until a recon phase (if any) completes
	subs        []chan Event

	renderFinding  func(detectors.Finding) template.HTML
	renderLog      func(LogEntry) template.HTML
	renderProgress func(status string, err error, waves []WaveStatus) template.HTML
}

func newJob(id, target string, renderFinding func(detectors.Finding) template.HTML, renderLog func(LogEntry) template.HTML, renderProgress func(status string, err error, waves []WaveStatus) template.HTML) *Job {
	return &Job{
		ID:             id,
		Target:         target,
		CreatedAt:      time.Now(),
		status:         StatusQueued,
		renderFinding:  renderFinding,
		renderLog:      renderLog,
		renderProgress: renderProgress,
	}
}

// Snapshot is everything GET /scans/{id} needs to render the job's current
// state before attaching SSE — the reconnect-safety mechanism doc12 calls
// for: render this first, then SSE only needs to stream what happens after.
type Snapshot struct {
	Status      string
	Err         error
	Findings    []detectors.Finding
	Logs        []LogEntry
	Waves       []WaveStatus
	ReconResult *recon.ReconResult // nil unless this Job ran a recon phase that completed
}

func (j *Job) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return Snapshot{
		Status:      j.status,
		Err:         j.err,
		Findings:    append([]detectors.Finding(nil), j.findings...),
		Logs:        append([]LogEntry(nil), j.logs...),
		Waves:       append([]WaveStatus(nil), j.waves...),
		ReconResult: j.reconResult,
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
	entry := LogEntry{Level: level, Msg: msg}
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
	j.mu.Unlock()
	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(StatusRunning, nil, waves)})
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
	curStatus, curErr := j.status, j.err
	j.mu.Unlock()

	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(curStatus, curErr, waves)})
}

// SetReconResult records a completed recon phase's result — read by the
// results page's hosts/tech/endpoints tables and the "recon also suggests"
// callout. Distinct from MarkDone: a Job that runs recon then detectors
// isn't done just because recon finished.
func (j *Job) SetReconResult(result *recon.ReconResult) {
	j.mu.Lock()
	j.reconResult = result
	j.mu.Unlock()
}

// MarkDone transitions the job to its terminal state (done or failed) and
// publishes an EventDone — the SSE handler's own signal to stop streaming
// and close the connection, since a reload of /scans/{id} at that point
// renders the final state directly with no SSE needed.
func (j *Job) MarkDone(err error) {
	j.mu.Lock()
	if err != nil {
		j.status = StatusFailed
		j.err = err
	} else {
		j.status = StatusDone
	}
	status := j.status
	waves := append([]WaveStatus(nil), j.waves...)
	j.mu.Unlock()

	j.publish(Event{Type: EventDone, HTML: j.renderProgress(status, err, waves)})
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
