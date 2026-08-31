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

// ReconJob is a background hackerfive recon run. Deliberately a separate,
// smaller type from Job rather than a generalization of it: recon.Run
// (pkg/recon/recon.go) has no incremental callback like scanner.Engine's
// WithFindingCallback/WithLogCallback, so there is exactly one event ever
// worth publishing — the running -> done|failed transition — not the
// finding/log stream Job exists to carry.
type ReconJob struct {
	ID        string
	Target    string
	Depth     string
	CreatedAt time.Time

	mu     sync.Mutex
	status string
	err    error
	result *recon.ReconResult
	subs   []chan Event

	renderProgress func(status string, err error) template.HTML
}

func newReconJob(id, target, depth string, renderProgress func(status string, err error) template.HTML) *ReconJob {
	return &ReconJob{
		ID:             id,
		Target:         target,
		Depth:          depth,
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
}

func (j *ReconJob) Snapshot() ReconSnapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	return ReconSnapshot{Status: j.status, Err: j.err, Result: j.result}
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
	j.mu.Unlock()
	j.publish(Event{Type: EventProgress, HTML: j.renderProgress(StatusRunning, nil)})
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
	j.mu.Unlock()

	j.publish(Event{Type: EventDone, HTML: j.renderProgress(status, err)})
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
