// Package workerpool provides a fixed-size worker pool for concurrent job
// execution, with a bounded queue so a slow target can't OOM the scanner.
package workerpool

import (
	"context"
	"fmt"
	"sync"
)

// Job is a unit of work submitted to a Pool.
type Job func(ctx context.Context) error

// Pool runs submitted Jobs across a fixed number of worker goroutines.
type Pool struct {
	ctx  context.Context
	jobs chan Job
	wg   sync.WaitGroup

	mu   sync.Mutex
	errs []error
}

// New starts a Pool with size workers and a queue that can hold queueDepth
// pending jobs before Submit blocks. Cancelling ctx drains the pool: workers
// stop pulling new jobs and exit, and Submit starts returning ctx.Err().
func New(ctx context.Context, size, queueDepth int) *Pool {
	p := &Pool{
		ctx:  ctx,
		jobs: make(chan Job, queueDepth),
	}
	for i := 0; i < size; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			p.runJob(job)
		}
	}
}

func (p *Pool) runJob(job Job) {
	defer func() {
		if r := recover(); r != nil {
			p.recordErr(fmt.Errorf("job panicked: %v", r))
		}
	}()
	if err := job(p.ctx); err != nil {
		p.recordErr(err)
	}
}

func (p *Pool) recordErr(err error) {
	p.mu.Lock()
	p.errs = append(p.errs, err)
	p.mu.Unlock()
}

// Submit queues job, blocking until it's queued or ctx is done. It returns
// ctx.Err() rather than dropping the job or blocking forever once the pool
// has been cancelled.
func (p *Pool) Submit(job Job) error {
	select {
	case p.jobs <- job:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

// Wait closes the pool to further submissions, waits for every in-flight and
// queued job to finish, and returns every error recorded along the way
// (including recovered panics) — one bad job never crashes the whole scan.
func (p *Pool) Wait() []error {
	close(p.jobs)
	p.wg.Wait()
	return p.errs
}
