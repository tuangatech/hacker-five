package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithHeaders_AppliedToDirectProbes checks that every request this
// package issues itself (Wave 0 security.txt/robots.txt, Wave 3 common-path
// and auth-boundary probes) carries the configured static header (LT-36).
func TestWithHeaders_AppliedToDirectProbes(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{} // path -> X-Hackerone value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("X-Hackerone")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, fake := recordingRun(t, nil)
	r := New(newTestClient(), withRun(fake), WithHeaders(map[string]string{"X-Hackerone": "tonytran"}))
	_, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, seen, "expected the recon run to make at least one direct HTTP probe")
	for path, got := range seen {
		assert.Equalf(t, "tonytran", got, "path %s was probed without the X-Hackerone header", path)
	}
	assert.Contains(t, seen, "/.well-known/security.txt", "Wave 0 should have probed security.txt")
}

// TestWithHeaders_PassedToHTTPXAndKatana checks the header is forwarded to
// the two subprocess crawlers via their own -H flag.
func TestWithHeaders_PassedToHTTPXAndKatana(t *testing.T) {
	var mu sync.Mutex
	argsByTool := map[string][]string{}

	capture := func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
		mu.Lock()
		argsByTool[name] = args
		mu.Unlock()
		return nil, nil
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := New(newTestClient(), withRun(capture), WithHeaders(map[string]string{"X-Hackerone": "tonytran"}))
	_, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	for _, tool := range []string{"httpx", "katana"} {
		args, ok := argsByTool[tool]
		require.Truef(t, ok, "%s was never invoked", tool)
		assert.Containsf(t, args, "-H", "%s args missing -H flag: %v", tool, args)
		assert.Containsf(t, args, "X-Hackerone: tonytran", "%s args missing the header value: %v", tool, args)
	}

	// dnsx/naabu take no HTTP header — they must not be handed -H.
	for _, tool := range []string{"dnsx", "naabu"} {
		if args, ok := argsByTool[tool]; ok {
			assert.NotContainsf(t, args, "-H", "%s should not receive an HTTP header flag: %v", tool, args)
		}
	}
}

func TestHeaderArgs_SortedAndPaired(t *testing.T) {
	r := &Recon{headers: map[string]string{"X-Hackerone": "tonytran", "A-Header": "v"}}
	assert.Equal(t, []string{"-H", "A-Header: v", "-H", "X-Hackerone: tonytran"}, r.headerArgs())

	assert.Nil(t, (&Recon{}).headerArgs(), "no configured headers -> no args")
}

func TestWithHeaders_EmptyMapIsNoOp(t *testing.T) {
	r := New(newTestClient(), WithHeaders(nil))
	assert.Nil(t, r.headers)
	r = New(newTestClient(), WithHeaders(map[string]string{}))
	assert.Nil(t, r.headers)
}
