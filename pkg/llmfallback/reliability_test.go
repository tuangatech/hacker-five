package llmfallback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowThenFastServer responds to the first slowCount request(s) only after
// delay, then immediately (valid chat-completion JSON) to every request
// after that — lets a test make a real client-side timeout fire on an early
// attempt and a real success land on a later one, without a fake clock.
func slowThenFastServer(t *testing.T, slowCount int, delay time.Duration) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		n := calls.Add(1)
		if int(n) <= slowCount {
			time.Sleep(delay)
		}
		resp := chatResponse{}
		resp.Choices = []struct {
			Message chatMessage `json:"message"`
		}{{Message: chatMessage{Role: "assistant", Content: `{"ok":true}`}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return srv, &calls
}

// TestWithLogCallback_AppliedByNew confirms the public Option actually wires
// logCB through New(), not just via direct field assignment the other tests
// in this file use for brevity.
func TestWithLogCallback_AppliedByNew(t *testing.T) {
	srv, _ := slowThenFastServer(t, 0, 0)
	defer srv.Close()
	t.Setenv(envLocalModelURL, srv.URL)
	t.Setenv(envOpenRouterKey, "")

	var got string
	c, err := New(WithLogCallback(func(level, msg string) { got = msg }))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.logf("info", "hello %s", "world")
	if got != "hello world" {
		t.Fatalf("logCB got %q, want %q", got, "hello world")
	}
}

// TestCompleteLabeled_RetriesOnceOnOwnTimeout guards LT-146's bounded retry:
// a call whose own per-call deadline (not the caller's outer ctx) fires
// gets exactly one fresh attempt, which succeeds here.
func TestCompleteLabeled_RetriesOnceOnOwnTimeout(t *testing.T) {
	srv, calls := slowThenFastServer(t, 1, 150*time.Millisecond)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	text, _, err := c.completeLabeled(context.Background(), tierLocal, "sys", "user", "test-label", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("completeLabeled: %v", err)
	}
	if text == "" {
		t.Fatal("expected a non-empty response from the retried attempt")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("server saw %d call(s), want exactly 2 (one timeout, one retry)", got)
	}
}

// TestCompleteLabeled_CallerCtxAlreadyDone_NoRetry guards the other half of
// isOwnTimeout: when the *caller's* own ctx deadline is what actually fires
// (shorter than completeOnce's internal per-call timeout), that's not
// worth retrying — the whole operation is stopping regardless.
func TestCompleteLabeled_CallerCtxAlreadyDone_NoRetry(t *testing.T) {
	srv, calls := slowThenFastServer(t, 100, 150*time.Millisecond) // every call is slow
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, _, err := c.completeLabeled(ctx, tierLocal, "sys", "user", "test-label", 5*time.Second)
	if err == nil {
		t.Fatal("expected an error when the caller's own ctx deadline fires")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("server saw %d call(s), want exactly 1 (no retry on a caller-driven timeout)", got)
	}
}

// TestCompleteLabeled_RealError_NotRetried confirms a genuine, non-timeout
// failure (here: a bad status code) gets no retry — only a bare timeout
// does.
func TestCompleteLabeled_RealError_NotRetried(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	_, _, err := c.completeLabeled(context.Background(), tierLocal, "sys", "user", "test-label", 5*time.Second)
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("server saw %d call(s), want exactly 1 (a real error must not be retried)", got)
	}
}

// TestCompleteOnce_HeartbeatLogsWhileOutstanding guards LT-146's "still
// waiting" signal: a call outstanding past heartbeatInterval logs at least
// one progress line naming the call's label before it returns.
func TestCompleteOnce_HeartbeatLogsWhileOutstanding(t *testing.T) {
	orig := heartbeatInterval
	heartbeatInterval = 5 * time.Millisecond
	defer func() { heartbeatInterval = orig }()

	srv, _ := slowThenFastServer(t, 1, 50*time.Millisecond)
	defer srv.Close()

	var (
		mu   sync.Mutex
		msgs []string
	)
	c := newTestClient(t, srv.URL)
	c.logCB = func(level, msg string) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, msg)
	}

	_, _, err := c.completeOnce(context.Background(), tierLocal, "sys", "user", "heartbeat-label", time.Second)
	if err != nil {
		t.Fatalf("completeOnce: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(msgs) == 0 {
		t.Fatal("expected at least one heartbeat log line for a call outstanding past heartbeatInterval")
	}
	for _, m := range msgs {
		if !strings.Contains(m, "heartbeat-label") {
			t.Fatalf("heartbeat line %q doesn't name the call's label", m)
		}
	}
}

// TestCompleteLabeled_TimesOutLogsWarning guards the retry-warning line
// itself (separate from the periodic heartbeat): a timed-out attempt logs a
// "retrying once" line via logCB.
func TestCompleteLabeled_TimesOutLogsWarning(t *testing.T) {
	srv, _ := slowThenFastServer(t, 1, 150*time.Millisecond)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	var (
		mu   sync.Mutex
		msgs []string
	)
	c.logCB = func(level, msg string) {
		mu.Lock()
		defer mu.Unlock()
		msgs = append(msgs, msg)
	}

	if _, _, err := c.completeLabeled(context.Background(), tierLocal, "sys", "user", "retry-label", 20*time.Millisecond); err != nil {
		t.Fatalf("completeLabeled: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, m := range msgs {
		if strings.Contains(m, "retry-label") && strings.Contains(m, "retrying once") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a retrying-once log line naming retry-label, got %v", msgs)
	}
}
