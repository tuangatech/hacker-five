package unit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
)

func TestLimiter_EnforcesQPS(t *testing.T) {
	limiter := ratelimit.New(10) // burst == qps == 10
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 15; i++ {
		require.NoError(t, limiter.Wait(ctx))
	}
	elapsed := time.Since(start)

	// 10 requests drain the burst immediately; the remaining 5 wait for
	// tokens to regenerate at 10/sec (~100ms apart) — at least ~400ms total.
	assert.GreaterOrEqual(t, elapsed, 400*time.Millisecond)
	assert.Less(t, elapsed, 2*time.Second)
}

func TestLimiter_RespectsContextCancellation(t *testing.T) {
	limiter := ratelimit.New(1)                            // burst == 1
	require.NoError(t, limiter.Wait(context.Background())) // consume the only token

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.Error(t, limiter.Wait(cancelledCtx))
}
