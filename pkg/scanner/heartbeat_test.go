package scanner

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestStartDispatchHeartbeat_LogsProgressUntilStopped locks in LT-149's fix:
// a periodic progress line fires while dispatch is in flight, reports the
// live completed/total count, and stops cleanly once stop() is called —
// no further lines after that, however long the test waits.
func TestStartDispatchHeartbeat_LogsProgressUntilStopped(t *testing.T) {
	orig := dispatchHeartbeatInterval
	dispatchHeartbeatInterval = 5 * time.Millisecond
	defer func() { dispatchHeartbeatInterval = orig }()

	var (
		mu   sync.Mutex
		msgs []string
	)
	warnf := func(level, format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, fmt.Sprintf(format, args...))
	}

	var completed atomic.Int64
	completed.Store(2)
	stop := startDispatchHeartbeat("https://example.com", 5, &completed, warnf)

	// Long enough for several ticks at the shrunk interval.
	time.Sleep(40 * time.Millisecond)
	stop()

	mu.Lock()
	got := len(msgs)
	last := ""
	if got > 0 {
		last = msgs[got-1]
	}
	mu.Unlock()

	if got == 0 {
		t.Fatalf("expected at least one heartbeat log line, got none")
	}
	want := "https://example.com: 2/5 template(s) completed so far"
	if last != want {
		t.Fatalf("heartbeat line = %q, want %q", last, want)
	}

	// Nothing further should be logged after stop(), even past another tick.
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	after := len(msgs)
	mu.Unlock()
	if after != got {
		t.Fatalf("stop() didn't stop the heartbeat: had %d line(s), now %d", got, after)
	}
}

// TestStartDispatchHeartbeat_ZeroTotal_NeverLogs confirms the no-op path
// (an empty template set — e.g. a fully-skipped tcp: leaf) starts no
// goroutine and stop() is still safe to call.
func TestStartDispatchHeartbeat_ZeroTotal_NeverLogs(t *testing.T) {
	orig := dispatchHeartbeatInterval
	dispatchHeartbeatInterval = 1 * time.Millisecond
	defer func() { dispatchHeartbeatInterval = orig }()

	var called atomic.Bool
	warnf := func(level, format string, args ...any) { called.Store(true) }

	var completed atomic.Int64
	stop := startDispatchHeartbeat("https://example.com", 0, &completed, warnf)
	time.Sleep(10 * time.Millisecond)
	stop()

	if called.Load() {
		t.Fatalf("expected no heartbeat log line for total == 0")
	}
}
