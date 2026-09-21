package unit

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func TestClient_RetriesTransientErrors(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&attempts, 1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 10*time.Millisecond))

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(3), atomic.LoadInt32(&attempts))
}

// TestClient_DoNoRedirect_NeverFollows locks in LT-156: unlike Do (which
// follows up to MaxRedirects), DoNoRedirect must return the raw 3xx response
// itself — needed by a caller that inspects the redirect's own headers
// (e.g. checkHostHeaderRedirect) rather than wanting the final page.
func TestClient_DoNoRedirect_NeverFollows(t *testing.T) {
	var finalHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/final")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&finalHits, 1)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/redirect", nil)
	require.NoError(t, err)

	resp, err := client.DoNoRedirect(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, "/final", resp.Header.Get("Location"))
	assert.Equal(t, int32(0), atomic.LoadInt32(&finalHits), "DoNoRedirect must never actually follow the redirect")
}

func TestClient_DoesNotRetryClientErrors(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 10*time.Millisecond))

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts))
}

// TestClient_RetryAfter_HonoredOverBackoff: a 429 carrying Retry-After: 1
// makes the retry wait ~1s, not the 10ms exponential backoff (doc15 Step 3).
func TestClient_RetryAfter_HonoredOverBackoff(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 10*time.Millisecond))

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), atomic.LoadInt32(&attempts))
	assert.GreaterOrEqual(t, time.Since(start), 900*time.Millisecond,
		"the retry must wait the server-stated ~1s, not the 10ms exponential backoff")
}

// TestClient_RetryAfter_BeyondCeiling_ReturnsResponse: a Retry-After longer
// than retryAfterCeiling (30s) is treated as "give up" — the 503 is handed
// back as the answer without blocking a worker or burning further attempts.
func TestClient_RetryAfter_BeyondCeiling_ReturnsResponse(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 10*time.Millisecond))

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attempts), "must not retry past a beyond-ceiling Retry-After")
	assert.Less(t, time.Since(start), 5*time.Second, "must return immediately, not wait out the 120s")
}

// TestClient_RetryAfter_HTTPDateForm: the HTTP-date form of Retry-After is
// parsed and honored the same way as the delta-seconds form.
func TestClient_RetryAfter_HTTPDateForm(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			// now+2s, not now+1s: http.TimeFormat has one-second granularity,
			// so a now+1s value truncates to as little as ~1ms in the future
			// by the time the client parses it — which made the >=500ms
			// assertion below flaky (seen failing at ~90-490ms). now+2s keeps
			// the honored wait safely near a full second after truncation.
			w.Header().Set("Retry-After", time.Now().Add(2*time.Second).UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 10*time.Millisecond))

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(2), atomic.LoadInt32(&attempts))
	assert.GreaterOrEqual(t, time.Since(start), 500*time.Millisecond,
		"the HTTP-date Retry-After must delay the retry")
}

func TestClient_WithHeaders(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Test")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithHeaders(map[string]string{"X-Test": "value"}))

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, "value", gotHeader)
}

func TestClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             20 * time.Millisecond,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	assert.Error(t, err)
}

// TestClient_Proxy uses a local httptest-based proxy stub, not a live
// MitmProxy — manual smoke testing via MitmProxy is a nice-to-have, not a CI
// gate.
func TestClient_Proxy(t *testing.T) {
	var proxied int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&proxied, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
		ProxyURL:            proxy.URL,
	})

	req, err := http.NewRequest(http.MethodGet, "http://example.invalid/", nil)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, int32(1), atomic.LoadInt32(&proxied))
}

// LT-187: a credential header must reach only the origin it was configured
// for. Server B answers with what it received; server A redirects to B, so a
// leak through net/http's own redirect header copy would show up there.
func TestClient_WithHostHeaders_OnlyTheConfiguredOrigin(t *testing.T) {
	var gotOnB atomic.Value
	gotOnB.Store("")
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOnB.Store(r.Header.Get("X-Session"))
		w.WriteHeader(http.StatusOK)
	}))
	defer b.Close()
	var gotOnA atomic.Value
	gotOnA.Store("")
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, b.URL+"/landed", http.StatusFound)
			return
		}
		gotOnA.Store(r.Header.Get("X-Session"))
		w.WriteHeader(http.StatusOK)
	}))
	defer a.Close()

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, MaxRedirects: 5, MaxIdleConnsPerHost: 4},
		httpclient.WithHostHeaders(a.URL, map[string]string{"X-Session": "secret"}))
	do := func(u string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, u, nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Empty(t, req.Header.Get("X-Session"), "the caller's own request must not be mutated")
	}

	do(a.URL + "/plain")
	assert.Equal(t, "secret", gotOnA.Load(), "the configured origin gets the header")

	do(b.URL + "/direct")
	assert.Empty(t, gotOnB.Load(), "another origin (same host, other port) must not")

	gotOnB.Store("")
	do(a.URL + "/redirect")
	assert.Empty(t, gotOnB.Load(), "a redirect to another origin must not carry it")
}

func TestClient_WithHostHeaders_DefaultPortsAndCase(t *testing.T) {
	var got atomic.Value
	rt := httpclient.WithHostHeaders("https://Example.COM", map[string]string{"X-Session": "secret"})(roundTripFn(func(r *http.Request) (*http.Response, error) {
		got.Store(r.Header.Get("X-Session"))
		return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
	}))
	for url, want := range map[string]string{
		"https://example.com/x":     "secret",
		"https://example.com:443/x": "secret",
		"https://example.com:8443/": "",
		"http://example.com/":       "",
		"https://sub.example.com/":  "",
		"https://example.com.evil/": "",
	} {
		got.Store("")
		req, err := http.NewRequest(http.MethodGet, url, nil)
		require.NoError(t, err)
		resp, err := rt.RoundTrip(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, want, got.Load(), url)
	}
}

type roundTripFn func(*http.Request) (*http.Response, error)

func (f roundTripFn) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
