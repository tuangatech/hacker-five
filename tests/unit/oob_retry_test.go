package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/oob"
)

// TestOOBClient_Register_RetriesOnTransientFailure proves the fix for a real
// finding (docs/discussions.md, 2026-09-02): public Interactsh servers
// individually drop/tarpit a meaningful fraction of requests, and a
// single-attempt client fails against them routinely even though the server
// is genuinely reachable. This mock server fails the first two /register
// attempts (connection reset, simulating the observed silent-drop symptom
// closely enough for retry-count purposes) and succeeds on the third —
// exactly the shape a real flaky public server produces.
func TestOOBClient_Register_RetriesOnTransientFailure(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			// Simulate a dropped connection — the same "client sees no
			// response at all" symptom observed against the real public
			// servers, not a clean HTTP error.
			hj, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, _, err := hj.Hijack()
			require.NoError(t, err)
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := oob.NewClient(ctx, &http.Client{Timeout: 2 * time.Second}, srv.URL)
	require.NoError(t, err, "client should succeed once the server accepts a request within retryAttempts")
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts), "expected exactly 2 failed attempts then 1 successful attempt")
}

// TestOOBClient_Register_GivesUpAfterRetriesExhausted proves the retry loop
// is bounded — a persistently unreachable server still fails the overall
// call rather than retrying forever.
func TestOOBClient_Register_GivesUpAfterRetriesExhausted(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		hj, ok := w.(http.Hijacker)
		require.True(t, ok)
		conn, _, err := hj.Hijack()
		require.NoError(t, err)
		_ = conn.Close()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, err := oob.NewClient(ctx, &http.Client{Timeout: 2 * time.Second}, srv.URL)
	require.Error(t, err, "a server that never succeeds must still surface an error, not retry forever")
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts), "expected exactly retryAttempts (3) tries before giving up")
}
