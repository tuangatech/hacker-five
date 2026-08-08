package workerpool

import (
	"context"
	"testing"
)

// BenchmarkWorkerPool hits a local no-op job, not a live network target, so
// the throughput bar is reproducible identically across machines and CI —
// no dependency on network conditions.
func BenchmarkWorkerPool(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool := New(context.Background(), 25, 50)
		for j := 0; j < 1000; j++ {
			_ = pool.Submit(func(_ context.Context) error { return nil })
		}
		pool.Wait()
	}
}
