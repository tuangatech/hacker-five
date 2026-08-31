package webui

import (
	"html/template"
	"sync"
	"time"

	"github.com/tuangatech/hacker-five/pkg/recon"
)

// reconSubscriberBuffer mirrors subscriberBuffer (jobs.go) — small buffer,
// non-blocking publish, same reasoning.
const reconSubscriberBuffer = 4

// WaveStatus is one recon wave's current progress ("wave0".."wave3",
// "running"/"done") — pkg/recon.WithProgressCallback's payload, carried
// through to the rendered progress fragment so an operator watching the
// status page sees which wave is active, not just an opaque overall
// "running" badge.
type WaveStatus struct {
	Name   string
	Status string
}

// ReconJob is a background hackerfive recon run. Deliberately a separate,
// smaller type from Job rather than a generalization of it: recon.Run
// (pkg/recon/recon.go) has no per-finding/per-log incremental callback like
// scanner.Engine's WithFindingCallback/WithLogCallback, only the wave-level
// progress WithProgressCallback adds — not the finding/log stream Job
// exists to carry. Mode distinguishes a plain recon run ("") from a Guided
// Scan run ("guided"): the only thing it changes is which link the status
// page offers once the job is done (see fragment_recon_status_body.html) —
// immutable after construction, no mutex needed.
type ReconJob struct {
	ID        string
	Target    string
	Depth     string
	Mode      string
	CreatedAt time.Time

	mu     sync.Mutex
	status string
	err    error
	result *recon.ReconResult
	waves  []WaveStatus
	subs   []chan Event

	renderProgress func(status string, err error, waves []WaveStatus) template.HTML
}

func newReconJob(id, target, depth, mode string, renderProgress func(status string, err error, waves []WaveStatus) template.HTML) *ReconJob {
	return &ReconJob{
		ID:             id,
		Target:         target,
		Depth:          depth,
		Mode:           mode,
		CreatedAt:      time.Now(),
		status:         StatusQueued,
		renderProgress: renderProgress,
	}
}

// ReconSnapshot is everything GET /recon/{id} needs to render the job's
// current state before attaching SSE — same reconnect-safety shape as
// Job.Snapshot.
type ReconSnapshot struct {
	Status string
	Err    error
	Result *recon.ReconResult // nil until done
	Waves  []WaveStatus
}

func (j *ReconJob) Snapshot() ReconSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return ReconSnapshot{Status: j.status, Err: j.err, Result: j.result, Waves: append([]WaveStatus(nil), j.waves...)}
}

// SetWaveStatus is pkg/recon.WithProgressCallback's target — updates (or
// appends) one wave's status and publishes the same EventProgress event
// SetRunning/MarkDone already do, so the wave list re-renders as part of
// the existing progress fragment rather than needing a new SSE event type.
func (j *ReconJob) SetWaveStatus(wave, status string) {
	j.mu.Lock()
	updated := false
	for i := range j.waves {
		if j.waves[i].Name == wave {
			j.waves[i].Status = status
			updated = true
			break
		}
	}
	if !updated {
		j.waves = append(j.waves, WaveStatus{Name: wave, Status: status})
	}
	wavesCopy := append([]WaveStatus(nil), j.waves...)
	curStatus, curErr := j.status, j.err
	j.mu.Unlock()

	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(curStatus, curErr, wavesCopy)})
}

// Subscribe/publish mirror Job's own (jobs.go) — same non-blocking-send,
// unsubscribe-once discipline, only ever carrying EventProgress/EventDone.
func (j *ReconJob) Subscribe() (ch chan Event, unsubscribe func()) {
	ch = make(chan Event, reconSubscriberBuffer)

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

func (j *ReconJob) publish(ev Event) {
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

// SetRunning mirrors Job.SetRunning.
func (j *ReconJob) SetRunning() {
	j.mu.Lock()
	j.status = StatusRunning
	waves := append([]WaveStatus(nil), j.waves...)
	j.mu.Unlock()
	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(StatusRunning, nil, waves)})
}

// MarkDone transitions to a terminal state and records result — nil result
// on failure, matching ReconSnapshot.Result's "nil until done" contract.
func (j *ReconJob) MarkDone(result *recon.ReconResult, err error) {
	j.mu.Lock()
	if err != nil {
		j.status = StatusFailed
		j.err = err
	} else {
		j.status = StatusDone
		j.result = result
	}
	status := j.status
	waves := append([]WaveStatus(nil), j.waves...)
	j.mu.Unlock()

	j.publish(Event{Type: EventDone, HTML: j.renderProgress(status, err, waves)})
}

// maxReconJobs mirrors maxJobs (jobs.go) — same fixed, stated eviction cap.
const maxReconJobs = 50

// ReconJobStore mirrors JobStore (jobs.go) exactly, kept as a separate type
// since its payload (ReconJob, not Job) differs.
type ReconJobStore struct {
	mu    sync.Mutex
	jobs  map[string]*ReconJob
	order []string
}

func newReconJobStore() *ReconJobStore {
	return &ReconJobStore{jobs: make(map[string]*ReconJob)}
}

func (s *ReconJobStore) Add(j *ReconJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = j
	s.order = append(s.order, j.ID)
	for len(s.order) > maxReconJobs {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.jobs, oldest)
	}
}

func (s *ReconJobStore) Get(id string) (*ReconJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	return j, ok
}
