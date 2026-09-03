package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunWave3_SwaggerJSONExposed_SetsAPISpec(t *testing.T) {
	_, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	require.NotNil(t, result.APISpec, "expected APISpec to be set once /swagger.json returns 200")
	assert.Equal(t, "openapi", result.APISpec.Kind)
	assert.Equal(t, srv.URL+"/swagger.json", result.APISpec.URL)

	// The generic EndpointFact must still be recorded too — APISpecFact is
	// additive, never a replacement for the raw fact.
	found := false
	for _, ep := range result.Endpoints {
		if ep.URL == srv.URL+"/swagger.json" {
			found = true
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

func TestRunWave3_MultipleSpecPathsExposed_FirstOneWins(t *testing.T) {
	_, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // every commonPaths entry, including both spec paths
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
