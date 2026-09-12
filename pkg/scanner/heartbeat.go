package scanner

import (
	"sync"
	"sync/atomic"
	"time"
)

// dispatchHeartbeatInterval is how often startDispatchHeartbeat logs a
// "still working" progress line while a target's corpus dispatch is in
// flight (LT-149, docs/follow-up.md) — live-observed: a
// --max-target-duration scan against several targets gave zero output
// between the "loaded N templates" line and the final "scan finished"
// summary, however many minutes that spanned, indistinguishable from a
// hang. A var, not a const, so a test can shrink it rather than waiting out
// a real 30s tick.
var dispatchHeartbeatInterval = 30 * time.Second

// startDispatchHeartbeat launches a goroutine that logs one progress line
// via warnf every dispatchHeartbeatInterval, reporting how many of total
// templates have completed so far against target, until the returned stop
// func is called. A no-op (nil goroutine) when total is 0 — nothing to
// report progress on. Extracted out of runTemplates so its timing can be
// exercised directly in a test without a real template/executor set.
//
// stop blocks until the goroutine has actually exited (not just signaled to
// stop) — so a caller (runTemplates' deferred stopHeartbeat) is guaranteed
// no heartbeat line logs after stop returns, and no goroutine outlives the
// function that started it.
func startDispatchHeartbeat(target string, total int, completed *atomic.Int64, warnf func(level, format string, args ...any)) (stop func()) {
	if total <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(dispatchHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				warnf("info", "%s: %d/%d template(s) completed so far", target, completed.Load(), total)
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(done) })
		<-stopped
	}
}
