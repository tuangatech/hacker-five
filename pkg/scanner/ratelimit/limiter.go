// Package ratelimit provides a token-bucket limiter shared by every worker
// in a scan, bounding total requests/sec regardless of concurrency.
package ratelimit

import (
	"context"

	"golang.org/x/time/rate"
)

// Limiter wraps golang.org/x/time/rate for configurable QPS.
type Limiter struct {
	rl *rate.Limiter
}

// New creates a Limiter allowing qps requests/sec, with a burst equal to qps
// so a fresh scan can start at full rate rather than ramping up.
func New(qps int) *Limiter {
	if qps < 1 {
		qps = 1
	}
	return &Limiter{rl: rate.NewLimiter(rate.Limit(qps), qps)}
}

// Wait blocks until a request may proceed, or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	return l.rl.Wait(ctx)
}

// SetQPS changes the allowed rate at runtime — used by the adaptive
// throttle (docs/follow-up.md LT-74) to back off when the target starts
// returning sustained 429/503. Burst is kept equal to the rate. A value
// below 1 is clamped to 1.
func (l *Limiter) SetQPS(qps int) {
	if qps < 1 {
		qps = 1
	}
	l.rl.SetLimit(rate.Limit(qps))
	l.rl.SetBurst(qps)
}

// QPS reports the limiter's current allowed rate, rounded to the nearest
// whole request/sec.
func (l *Limiter) QPS() int {
	return int(float64(l.rl.Limit()) + 0.5)
}
