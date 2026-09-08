package recon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWalkOpenAPISpec_V3 covers LT-40's OpenAPI 3 path: a servers[].url
// prefix, a "{param}" path kept verbatim, and documented query keys
// appended keyless.
func TestWalkOpenAPISpec_V3(t *testing.T) {
	body := []byte(`{
	  "openapi": "3.0.1",
	  "servers": [{"url": "https://api.example.com/v1"}],
	  "paths": {
	    "/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path"}]}},
	    "/search": {"get": {"parameters": [{"name": "q", "in": "query"}, {"name": "url", "in": "query"}]}},
	    "/health": {"get": {}}
	  }
	}`)
	facts, truncated := walkOpenAPISpec("https://target.example/openapi.json", body)
	assert.False(t, truncated)

	got := map[string]string{}
	for _, f := range facts {
		got[f.URL] = f.Method
		assert.Equal(t, "api-spec", f.Source)
		assert.Equal(t, ConfidenceLow, f.Confidence)
	}
	assert.Equal(t, "GET", got["https://target.example/v1/users/{id}"], "the server URL's path is the prefix; only its host is dropped")
	assert.Equal(t, "GET", got["https://target.example/v1/search?q=&url="], "documented query keys are appended keyless and sorted")
	assert.Equal(t, "GET", got["https://target.example/v1/health"])
}

// TestWalkOpenAPISpec_V2BasePath covers the OpenAPI 2 basePath prefix and
// GET being chosen as the representative method when a path documents
// several.
func TestWalkOpenAPISpec_V2BasePath(t *testing.T) {
	body := []byte(`{
	  "swagger": "2.0",
	  "basePath": "/api/v2",
	  "paths": {
	    "/orders/{orderId}": {
	      "get": {"parameters": [{"name": "orderId", "in": "path"}]},
	      "delete": {"parameters": [{"name": "orderId", "in": "path"}]},
	      "parameters": [{"name": "trace", "in": "query"}]
	    }
	  }
	}`)
	facts, _ := walkOpenAPISpec("https://target.example/swagger.json", body)
	require.Len(t, facts, 1)
	assert.Equal(t, "https://target.example/api/v2/orders/{orderId}?trace=", facts[0].URL)
	assert.Equal(t, "GET", facts[0].Method)
}

// TestWalkOpenAPISpec_NotASpec: a JSON body with no version key, a
// non-JSON body, and an empty body all walk to nothing.
func TestWalkOpenAPISpec_NotASpec(t *testing.T) {
	facts, _ := walkOpenAPISpec("https://x/openapi.json", []byte(`{"foo": "bar", "paths": {"/a": {}}}`))
	assert.Nil(t, facts, "a JSON doc with no swagger/openapi version key is not an OpenAPI document")

	facts, _ = walkOpenAPISpec("https://x/openapi.json", []byte(`<html>not json</html>`))
	assert.Nil(t, facts)

	facts, _ = walkOpenAPISpec("https://x/openapi.json", nil)
	assert.Nil(t, facts)
}

// TestWalkOpenAPISpec_Truncates: a spec with more paths than the cap yields
// exactly maxSpecEndpoints facts and flags truncation.
func TestWalkOpenAPISpec_Truncates(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"openapi":"3.0.0","paths":{`)
	for i := 0; i < maxSpecEndpoints+50; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `"/p%04d":{"get":{}}`, i)
	}
	sb.WriteString(`}}`)

	facts, truncated := walkOpenAPISpec("https://t.example/openapi.json", []byte(sb.String()))
	assert.True(t, truncated)
	assert.Len(t, facts, maxSpecEndpoints)
}

// TestWalkOpenAPISpec_FeedsIDORCandidates ties LT-40 to its downstream
// consumer: a spec-derived "/{id}" route becomes an {{id}} IDOR candidate
// with no concrete id invented.
func TestWalkOpenAPISpec_FeedsIDORCandidates(t *testing.T) {
	body := []byte(`{"openapi":"3.0.0","paths":{"/api/accounts/{accountId}":{"get":{}}}}`)
	facts, _ := walkOpenAPISpec("https://t.example/openapi.json", body)
	require.NotEmpty(t, facts)

	cands := SuggestIDOREndpointCandidates(&ReconResult{Endpoints: facts})
	assert.Contains(t, cands, "/api/accounts/{{id}}")

	params := SuggestSSRFParamsFromRecon(&ReconResult{Endpoints: []EndpointFact{
		{URL: "https://t.example/fetch?url="},
	}})
	assert.Contains(t, params, "url", "a keyless documented query param still name-matches the SSRF table")
}

// TestProbeCommonPaths_WalksOpenAPISpec guards the crawl.go wiring: a real
// JSON spec served at /swagger.json is recorded as an APISpecFact AND
// walked into api-spec-sourced EndpointFacts, with an LT-40 warning.
func TestProbeCommonPaths_WalksOpenAPISpec(t *testing.T) {
	spec := `{"openapi":"3.0.0","servers":[{"url":"/v1"}],"paths":{"/widgets/{widgetId}":{"get":{}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, spec)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	agg := &aggregator{target: srv.URL}
	r := New(newTestClient())
	r.probeCommonPaths(context.Background(), agg, srv.URL)

	require.NotNil(t, agg.apiSpec)
	assert.Equal(t, "openapi", agg.apiSpec.Kind)

	var specEP *EndpointFact
	for i := range agg.endpoints {
		if agg.endpoints[i].Source == "api-spec" {
			specEP = &agg.endpoints[i]
		}
	}
	require.NotNil(t, specEP, "the spec's own route must be walked into an api-spec EndpointFact")
	assert.Equal(t, srv.URL+"/v1/widgets/{widgetId}", specEP.URL)

	joined := strings.Join(agg.warnings, " | ")
	assert.Contains(t, joined, "LT-40")
}
