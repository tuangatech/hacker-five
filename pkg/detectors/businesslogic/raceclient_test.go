package businesslogic

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFireRace_RoundTrip proves the raw-connection mechanism itself
// completes a normal request/response cycle correctly (headers, body,
// status) across every connection it opens — independent of any timing
// assertion.
func TestFireRace_RoundTrip(t *testing.T) {
	var mu sync.Mutex
	var hitCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		hitCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("echo:" + string(body)))
	}))
	defer srv.Close()

	results, err := fireRace(context.Background(), srv.URL, "/probe", raceRequestOptions{
		Method:  http.MethodPost,
		Headers: map[string]string{"Content-Type": "text/plain"},
		Body:    []byte("hello"),
	}, 5)
	require.NoError(t, err)
	require.Len(t, results, 5)
	for _, r := range results {
		require.NoError(t, r.Err)
		assert.Equal(t, http.StatusOK, r.StatusCode)
		assert.Equal(t, "echo:hello", string(r.Body))
	}

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 5, hitCount)
}

// TestFireRace_ExploitsRealTOCTOUWindow proves the last-byte-sync mechanism
// itself lands concurrent requests inside a real, narrow check-then-act
// window over genuine TCP connections — not just asserted against an
// artificially-slept mock (which detector_businesslogic_test.go's
// higher-level tests use instead, for determinism independent of this
// mechanism). A handler with a short check-then-set window, mirroring
// crAPI's real coupon-apply race, should let more than one concurrent
// request through if the technique actually works.
func TestFireRace_ExploitsRealTOCTOUWindow(t *testing.T) {
	var mu sync.Mutex
	claimed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		alreadyClaimed := claimed
		mu.Unlock()
		if alreadyClaimed {
			w.WriteHeader(http.StatusConflict)
			return
		}
		time.Sleep(20 * time.Millisecond) // simulate a real check-then-act DB round trip
		mu.Lock()
		claimed = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	results, err := fireRace(context.Background(), srv.URL, "/claim", raceRequestOptions{Method: http.MethodPost}, 10)
	require.NoError(t, err)

	successCount := 0
	for _, r := range results {
		if r.Err == nil && r.StatusCode == http.StatusOK {
			successCount++
		}
	}
	assert.Greater(t, successCount, 1, "last-byte-sync should land multiple requests inside the check-then-act window")
}
