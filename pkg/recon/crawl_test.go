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
