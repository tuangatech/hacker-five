package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
	// A default desktop-browser User-Agent is always included unless the
	// operator overrode it (LT-75 / LT-81), sorted in with the rest.
	r := &Recon{headers: map[string]string{"X-Hackerone": "tonytran", "A-Header": "v"}}
	assert.Equal(t, []string{
		"-H", "A-Header: v",
		"-H", "User-Agent: " + DefaultBrowserUserAgent,
		"-H", "X-Hackerone: tonytran",
	}, r.headerArgs())

	assert.Equal(t, []string{"-H", "User-Agent: " + DefaultBrowserUserAgent}, (&Recon{}).headerArgs(),
		"no configured headers -> just the default UA")
}

func TestHeaderArgs_UserAgentOverrideWins(t *testing.T) {
	r := &Recon{headers: map[string]string{"user-agent": "custom/1.0"}}
	assert.Equal(t, []string{"-H", "user-agent: custom/1.0"}, r.headerArgs(),
		"an operator-supplied User-Agent (any casing) replaces the default, not appended to")
}

func TestWithHeaders_EmptyMapIsNoOp(t *testing.T) {
	r := New(newTestClient(), WithHeaders(nil))
	assert.Nil(t, r.headers)
	r = New(newTestClient(), WithHeaders(map[string]string{}))
	assert.Nil(t, r.headers)
}

// LT-187: a credential given through WithCrawlHeaders reaches katana only when
// every seed is on its origin, pins the crawl to that exact hostname, and never
// reaches httpx (which probes many hosts).
func TestWithCrawlHeaders_KatanaOnlyOnTheCredentialsOrigin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()

	run := func(origin string) (map[string][]string, *ReconResult) {
		var mu sync.Mutex
		argsByTool := map[string][]string{}
		capture := func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
			mu.Lock()
			argsByTool[name] = args
			mu.Unlock()
			return nil, nil
		}
		r := New(newTestClient(), withRun(capture), WithCrawlHeaders(origin, map[string]string{"Authorization": "Bearer s3cret"}))
		res, err := r.Run(context.Background(), srv.URL, DepthFull)
		require.NoError(t, err)
		mu.Lock()
		defer mu.Unlock()
		return argsByTool, res
	}

	args, res := run(srv.URL)
	assert.Contains(t, args["katana"], "Authorization: Bearer s3cret")
	assert.Contains(t, args["katana"], "fqdn", "an authenticated crawl is pinned to the exact hostname")
	assert.Contains(t, args["katana"], StateChangingCrawlExclusion(), "an authenticated crawl skips state-changing URLs")
	assert.NotContains(t, args["httpx"], "Authorization: Bearer s3cret", "httpx probes many hosts and must never carry the credential")
	assert.NotContains(t, strings.Join(res.Warnings, "\n"), "crawl ran unauthenticated")

	args, res = run("http://another-host.invalid")
	assert.NotContains(t, args["katana"], "Authorization: Bearer s3cret", "a crawl seeded off the credential's origin must not carry it")
	assert.Contains(t, strings.Join(res.Warnings, "\n"), "crawl ran unauthenticated")
}

func TestSameOrigin(t *testing.T) {
	assert.True(t, sameOrigin("https://Example.com/a", "https://example.com:443"))
	assert.True(t, sameOrigin("http://example.com", "http://example.com:80/x"))
	assert.False(t, sameOrigin("https://example.com", "http://example.com"), "scheme changes the default port")
	assert.False(t, sameOrigin("https://example.com:8443", "https://example.com"))
	assert.False(t, sameOrigin("https://sub.example.com", "https://example.com"))
	assert.False(t, sameOrigin("", ""), "an unparseable origin matches nothing")
}

func TestStateChangingURL(t *testing.T) {
	match := []string{
		"https://x.test/logout", "https://x.test/api/auth/sign-out", "https://x.test/api/v2/user/signout",
		"https://x.test/api/videos/delete_video", "https://x.test/api/item/12/delete", "https://x.test/account/revoke",
		"https://x.test/api/order/cancel?id=1", "https://x.test/app?action=logout", "https://x.test/password/reset",
		"https://x.test/API/LogOut",
	}
	for _, raw := range match {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Truef(t, StateChangingURL(u), "%s should be treated as state-changing", raw)
	}
	keep := []string{
		"https://x.test/api/deleted-items", "https://x.test/api/removal-policy", "https://x.test/api/v2/user/videos",
		"https://x.test/api/resetting", "https://x.test/api/cancellations", "https://x.test/workshop/api/shop/orders/1",
	}
	for _, raw := range keep {
		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Falsef(t, StateChangingURL(u), "%s is not a state-changing action", raw)
	}
	assert.False(t, StateChangingURL(nil))
}
