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
	return &Limiter{rl: rate.NewLimiter(rate.Limit(qps), qps)}
}

// Wait blocks until a request may proceed, or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	return l.rl.Wait(ctx)
}
