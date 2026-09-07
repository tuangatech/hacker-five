package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// TestRunKatana_OutOfScopeFetchedEndpoint_DivertedToOutOfScope guards LT-52
// (docs/follow-up.md): katana's default scope keeps it on the seed's root
// domain, but a cross-host link it actually fetched (no rec.Error) still
// reaches this output. When a --scope is set and that host is neither a seed
// nor in scope, it must be recorded in OutOfScope, never in Endpoints —
// mirroring the existing rec.Error branch.
func TestRunKatana_OutOfScopeFetchedEndpoint_DivertedToOutOfScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + srv.URL + `/app","method":"GET"},"response":{"status_code":200}}
{"request":{"endpoint":"https://images.out-of-scope.example/logo.png","method":"GET"},"response":{"status_code":200}}`,
	}
	_, fake := recordingRun(t, responses)

	s, err := scope.New([]string{hostOnly(srv.URL)}) // only the seed host is in scope
	require.NoError(t, err)
	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		assert.NotContains(t, ep.URL, "out-of-scope.example",
			"an out-of-scope host katana fetched must never reach Endpoints")
	}
	assert.Contains(t, result.OutOfScope, "images.out-of-scope.example",
		"the out-of-scope fetched host must be recorded in OutOfScope")
	found := false
	for _, ep := range result.Endpoints {
		if ep.Source == "katana-crawl" && ep.URL == srv.URL+"/app" {
			found = true
		}
	}
	assert.True(t, found, "the in-scope seed-host endpoint must still be kept")
}

func TestRunWave3_SwaggerJSONExposed_SetsAPISpec(t *testing.T) {
	_, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.0","paths":{"/pets":{"get":{}}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	require.NotNil(t, result.APISpec, "expected APISpec to be set once /swagger.json returns real JSON")
	assert.Equal(t, "openapi", result.APISpec.Kind)
	assert.Equal(t, srv.URL+"/swagger.json", result.APISpec.URL)

	// The generic EndpointFact must still be recorded too — APISpecFact is
	// additive, never a replacement for the raw fact.
	found := false
	for _, ep := range result.Endpoints {
		if ep.URL == srv.URL+"/swagger.json" {
			found = true
			assert.Equal(t, "application/json", ep.ContentType, "LT-30b: probeCommonPaths must record the observed Content-Type")
			assert.Positive(t, ep.BodyLen, "LT-30b: probeCommonPaths must record the observed body length")
		}
	}
	assert.True(t, found, "swagger.json must still appear as a plain EndpointFact")
}

func TestRunWave3_NoSpecPathReachable_APISpecStaysNil(t *testing.T) {
	_, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)
	assert.Nil(t, result.APISpec)
}

// TestRunWave3_SpecPathServesHTMLShell_NoAPISpec is LT-30's core regression
// guard: /swagger.json returns 200 but an HTML SPA shell (not JSON), and a
// random canary path returns that same shell. The shell is distinct enough
// from a bare 404 to still be a real endpoint, but it is NOT a machine-
// readable spec — no APISpecFact.
func TestRunWave3_SpecPathServesHTMLShell_NoAPISpec(t *testing.T) {
	_, fake := recordingRun(t, nil)
	const shell = `<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(shell)) // every path, including the canary and /swagger.json
	}))
	defer srv.Close()

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	assert.Nil(t, result.APISpec, "an HTML shell at /swagger.json is not a reachable API spec")
	for _, ep := range result.Endpoints {
		assert.NotEqual(t, "wave3-common-path-probe", ep.Source,
			"a uniform catch-all must suppress every common-path probe as a soft-404")
	}
	sawSuppressWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "uniform SPA/catch-all") {
			sawSuppressWarning = true
		}
	}
	assert.True(t, sawSuppressWarning, "a suppressed catch-all must leave one visible warning")
}

// TestRunWave3_UniformResponseWall covers D6 (docs/16-implementation-plan-ph7.md
// Step 4): Wave 3 records a UniformResponseFact when a host answers every
// probe with one generic page — "waf-block" for a 403-everything wall,
// "catchall" for a 200-everything shell.
func TestRunWave3_UniformResponseWall(t *testing.T) {
	t.Run("403 on every path -> waf-block", func(t *testing.T) {
		_, fake := recordingRun(t, nil)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Access Denied"))
		}))
		defer srv.Close()

		r := New(newTestClient(), withRun(fake))
		result, err := r.Run(context.Background(), srv.URL, DepthFull)
		require.NoError(t, err)
		require.NotNil(t, result.UniformResponse, "a 403-everything host must be recorded as a uniform wall")
		assert.Equal(t, "waf-block", result.UniformResponse.Kind)
		assert.Equal(t, http.StatusForbidden, result.UniformResponse.CanaryStatus)
	})

	t.Run("200 shell on every path -> catchall", func(t *testing.T) {
		_, fake := recordingRun(t, nil)
		const shell = `<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>`
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(shell))
		}))
		defer srv.Close()

		r := New(newTestClient(), withRun(fake))
		result, err := r.Run(context.Background(), srv.URL, DepthFull)
		require.NoError(t, err)
		require.NotNil(t, result.UniformResponse)
		assert.Equal(t, "catchall", result.UniformResponse.Kind)
	})

	t.Run("normal host (real 404 for nonexistent) -> no fact", func(t *testing.T) {
		_, fake := recordingRun(t, nil)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				_, _ = w.Write([]byte("<html>real homepage with lots of distinct content " + strings.Repeat("x", 4000) + "</html>"))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		r := New(newTestClient(), withRun(fake))
		result, err := r.Run(context.Background(), srv.URL, DepthFull)
		require.NoError(t, err)
		assert.Nil(t, result.UniformResponse, "a host with a real 404 for nonexistent paths is not a wall")
	})
}

func TestRunWave3_MultipleRealSpecPathsExposed_FirstOneWins(t *testing.T) {
	_, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/swagger.json", "/.well-known/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.0"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	require.NotNil(t, result.APISpec)
	assert.Equal(t, srv.URL+"/swagger.json", result.APISpec.URL, "commonPaths checks /swagger.json before /.well-known/openapi.json")
}

// TestRunKatana_401NotReproduced_EndpointDropped guards the false-positive
// fix found live 2026-09-04: a real target's "/giftcard/" got a single
// crawl-time 401 (most likely bot-protection reacting to katana, not real
// access control) that fed straight into authbypass's protected-path
// suggestion, producing a false "missing auth" finding once a direct
// unauthenticated request naturally succeeded. A katana-reported 401/403
// that a fresh, direct request doesn't reproduce must never reach
// ReconResult.Endpoints.
func TestRunKatana_401NotReproduced_EndpointDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // the real server has no auth wall at all
	}))
	defer srv.Close()

	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + srv.URL + `/giftcard/","method":"GET"},"response":{"status_code":401}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		if ep.Source == "katana-crawl" && ep.URL == srv.URL+"/giftcard/" {
			t.Fatalf("expected the unreproduced 401 to be dropped, got it kept: %+v", ep)
		}
	}
}

// TestRunKatana_401Reproduced_EndpointKeptAtHighConfidence is
// TestRunKatana_401NotReproduced_EndpointDropped's counterpart: a
// katana-observed 401 that a fresh, direct request also gets is a real,
// independently-reproduced signal — kept, and promoted to ConfidenceHigh
// (up from katana-crawl's own default ConfidenceMedium).
func TestRunKatana_401Reproduced_EndpointKeptAtHighConfidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // genuinely, consistently gated
	}))
	defer srv.Close()

	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + srv.URL + `/admin","method":"GET"},"response":{"status_code":401}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	found := false
	for _, ep := range result.Endpoints {
		if ep.Source == "katana-crawl" && ep.URL == srv.URL+"/admin" {
			found = true
			assert.Equal(t, 401, ep.StatusCode)
			assert.Equal(t, ConfidenceHigh, ep.Confidence, "an independently reproduced 401 deserves the strongest confidence tier")
		}
	}
	assert.True(t, found, "expected the reproduced 401 to be kept")
}

// TestRunKatana_EscapedJSArtifacts_Dropped guards the fix for a real false-
// signal class found live against useruby.care, 2026-09-04: katana's -jc
// extractor, parsing an inline <script> tag's JSON-serialized route data
// (a Next.js app escapes its own paths as "\/en\/..." there), mis-parsed
// those escapes into endpoints like "/en%5C" and "/favicon.png%5C%5C" — a
// literal backslash is never valid in a real URL path, so these are always
// parsing artifacts, not genuine discovered endpoints, and must never reach
// the aggregated result (the Endpoints table, the JSON export, or any
// suggester that reads it) regardless of what status code katana reported
// for them.
func TestRunKatana_EscapedJSArtifacts_Dropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + srv.URL + `/en%5C","method":"GET","attribute":"text"},"response":{"status_code":404}}
{"request":{"endpoint":"` + srv.URL + `/about","method":"GET","attribute":"href"},"response":{"status_code":200}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		assert.NotContains(t, ep.URL, "%5C", "an escaped-backslash artifact must never reach the aggregated result")
		assert.NotContains(t, ep.URL, `\`, "a raw backslash artifact must never reach the aggregated result")
	}
	found := false
	for _, ep := range result.Endpoints {
		if ep.Source == "katana-crawl" && ep.URL == srv.URL+"/about" {
			found = true
		}
	}
	assert.True(t, found, "a genuine katana-crawl endpoint alongside the artifact must still be kept")
}

// --- LT-4 (docs/follow-up.md): hostErrors trip is now warned, not silent ---

// TestProbeCommonPaths_HostTripsCircuitBreaker_WarnsOnce guards the fix: a
// host whose every wave3 request fails must produce exactly one warning
// (naming the host), not zero (the old silent behavior) and not one per
// remaining commonPaths entry.
func TestProbeCommonPaths_HostTripsCircuitBreaker_WarnsOnce(t *testing.T) {
	_, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // every request against srv.URL now fails with connection refused

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	matches := 0
	for _, w := range result.Warnings {
		if strings.Contains(w, "no further common-path/auth-boundary probes will run against this host") {
			matches++
		}
	}
	assert.Equal(t, 1, matches, "exactly one warning expected once the host trips hostErrors, not zero and not one per remaining path")
}

// TestTagAuthBoundary_HostAlreadyTripped_SkipsRequest guards the new guard
// clause directly: a host already past the error threshold must not get a
// fresh auth-boundary probe, even when the server would actually answer
// (proving the skip is the guard firing, not the server being unreachable).
func TestTagAuthBoundary_HostAlreadyTripped_SkipsRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<input type="password">`)) // would tag as an auth boundary if reached
	}))
	defer srv.Close()

	r := New(newTestClient())
	host := hostOnly(srv.URL)
	for i := 0; i < hosterrors.DefaultThreshold; i++ {
		r.hostErrors.RecordError(host)
	}
	require.True(t, r.hostErrors.ShouldSkip(host))

	agg := &aggregator{target: srv.URL}
	r.tagAuthBoundary(context.Background(), agg, srv.URL)

	assert.Empty(t, agg.finalize().Endpoints, "a host already past the error threshold must not get a fresh auth-boundary probe")
}
