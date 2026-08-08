package unit

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/workerpool"
)

func TestPool_SubmitAndDrain(t *testing.T) {
	pool := workerpool.New(context.Background(), 4, 8)

	var completed int32
	for i := 0; i < 20; i++ {
		require.NoError(t, pool.Submit(func(_ context.Context) error {
			atomic.AddInt32(&completed, 1)
			return nil
		}))
	}

	errs := pool.Wait()
	assert.Empty(t, errs)
	assert.Equal(t, int32(20), atomic.LoadInt32(&completed))
}

func TestPool_Backpressure(t *testing.T) {
	pool := workerpool.New(context.Background(), 1, 1) // 1 worker, 1 queue slot

	release := make(chan struct{})
	require.NoError(t, pool.Submit(func(_ context.Context) error {
		<-release
		return nil
	}))
	require.NoError(t, pool.Submit(func(_ context.Context) error { return nil })) // fills the queue

	submitted := make(chan error, 1)
	go func() {
		submitted <- pool.Submit(func(_ context.Context) error { return nil })
	}()

	select {
	case <-submitted:
		t.Fatal("Submit should have blocked while the pool is full")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-submitted:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Submit did not unblock after the pool drained")
	}

	pool.Wait()
}

func TestPool_CancellationStopsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pool := workerpool.New(ctx, 2, 4)

	started := make(chan struct{})
	require.NoError(t, pool.Submit(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}))
	<-started
	cancel()

	done := make(chan []error, 1)
	go func() { done <- pool.Wait() }()

	select {
	case errs := <-done:
		require.Len(t, errs, 1)
		assert.ErrorIs(t, errs[0], context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Wait did not return promptly after cancellation")
	}
}

func TestPool_PanicIsolation(t *testing.T) {
	pool := workerpool.New(context.Background(), 2, 4)

	var normalRan int32
	require.NoError(t, pool.Submit(func(_ context.Context) error {
		panic("boom")
	}))
	require.NoError(t, pool.Submit(func(_ context.Context) error {
		atomic.AddInt32(&normalRan, 1)
		return nil
	}))

	errs := pool.Wait()
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "boom")
	assert.Equal(t, int32(1), atomic.LoadInt32(&normalRan))
}

func TestPool_JobErrorsPropagate(t *testing.T) {
	pool := workerpool.New(context.Background(), 1, 1)
	sentinel := errors.New("job failed")

	require.NoError(t, pool.Submit(func(_ context.Context) error {
		return sentinel
	}))

	errs := pool.Wait()
	require.Len(t, errs, 1)
	assert.ErrorIs(t, errs[0], sentinel)
}
