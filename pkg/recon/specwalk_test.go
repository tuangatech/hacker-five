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

// TestWalkOpenAPISpec_RequestBodyProperties covers LT-96: a POST operation's
// requestBody JSON schema property names are captured onto BodyParamKeys —
// names only, no values invented — closing the gap where an attacker
// -controlled URL is taken in a JSON body field (e.g. crAPI's
// contact_mechanic) rather than a query param.
func TestWalkOpenAPISpec_RequestBodyProperties(t *testing.T) {
	body := []byte(`{
	  "openapi": "3.0.1",
	  "servers": [{"url": "https://api.example.com/v1"}],
	  "paths": {
	    "/merchant/contact_mechanic": {
	      "post": {
	        "requestBody": {
	          "content": {
	            "application/json": {
	              "schema": {
	                "properties": {
	                  "mechanic_api": {"type": "string"},
	                  "vehicle_id": {"type": "string"}
	                }
	              }
	            }
	          }
	        }
	      }
	    },
	    "/health": {"get": {}}
	  }
	}`)
	facts, _ := walkOpenAPISpec("https://target.example/openapi.json", body)

	got := map[string][]string{}
	for _, f := range facts {
		got[f.URL] = f.BodyParamKeys
	}
	assert.Equal(t, []string{"mechanic_api", "vehicle_id"}, got["https://target.example/v1/merchant/contact_mechanic"])
	assert.Nil(t, got["https://target.example/v1/health"], "an operation with no requestBody has no BodyParamKeys")
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

// TestWalkOpenAPISpec_YAMLBody covers LT-40(b): a YAML-serialised OpenAPI
// document (springdoc's /v3/api-docs.yaml, most hand-written specs) walks to
// the same EndpointFacts as its JSON equivalent.
func TestWalkOpenAPISpec_YAMLBody(t *testing.T) {
	body := []byte(`openapi: 3.0.1
servers:
  - url: https://api.example.com/v1
paths:
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
  /search:
    get:
      parameters:
        - name: q
          in: query
        - name: url
          in: query
`)
	facts, truncated := walkOpenAPISpec("https://target.example/v3/api-docs", body)
	assert.False(t, truncated)

	got := map[string]string{}
	for _, f := range facts {
		got[f.URL] = f.Method
		assert.Equal(t, "api-spec", f.Source)
		assert.Equal(t, ConfidenceLow, f.Confidence)
	}
	assert.Equal(t, "GET", got["https://target.example/v1/users/{id}"])
	assert.Equal(t, "GET", got["https://target.example/v1/search?q=&url="])
}

// TestWalkOpenAPISpec_YAMLNotASpec: a YAML scalar / sequence body, and a
// YAML mapping with no version key, all walk to nothing.
func TestWalkOpenAPISpec_YAMLNotASpec(t *testing.T) {
	facts, _ := walkOpenAPISpec("https://x/api-docs", []byte("- one\n- two\n"))
	assert.Nil(t, facts, "a top-level YAML sequence is not a spec document")

	facts, _ = walkOpenAPISpec("https://x/api-docs", []byte("foo: bar\npaths:\n  /a: {}\n"))
	assert.Nil(t, facts, "a YAML mapping with no swagger/openapi key is not an OpenAPI document")
}

// TestWalkOpenAPISpec_AuthRequired covers LT-90: a document-level `security`
// default flows onto every route, an operation-level `security` overrides
// it, and an explicit `security: []` opts a route back out.
func TestWalkOpenAPISpec_AuthRequired(t *testing.T) {
	body := []byte(`{
	  "openapi": "3.0.1",
	  "security": [{"bearerAuth": []}],
	  "paths": {
	    "/user/dashboard": {"get": {}},
	    "/auth/login": {"post": {"security": []}},
	    "/health": {"get": {"security": []}},
	    "/admin/keys": {"get": {"security": [{"bearerAuth": []}]}}
	  }
	}`)
	facts, _ := walkOpenAPISpec("https://api.example.com/openapi.json", body)

	got := map[string]bool{}
	for _, f := range facts {
		got[f.URL] = f.AuthRequired
	}
	assert.True(t, got["https://api.example.com/user/dashboard"], "inherits the document-level security default")
	assert.True(t, got["https://api.example.com/admin/keys"], "operation-level security requires auth")
	assert.False(t, got["https://api.example.com/auth/login"], "security: [] opts a route out of the doc default")
	assert.False(t, got["https://api.example.com/health"], "security: [] opts a route out of the doc default")
}

// TestWalkOpenAPISpec_NoSecurity: a spec with no security anywhere marks
// nothing auth-required.
func TestWalkOpenAPISpec_NoSecurity(t *testing.T) {
	facts, _ := walkOpenAPISpec("https://x/openapi.json",
		[]byte(`{"openapi":"3.0.0","paths":{"/a":{"get":{}},"/b":{"get":{}}}}`))
	require.NotEmpty(t, facts)
	for _, f := range facts {
		assert.False(t, f.AuthRequired)
	}
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

// TestProbeCommonPaths_WalksSpecAtFrameworkPath covers LT-40(c): a spec
// served only at a framework-convention path (springdoc's /v3/api-docs,
// here as YAML) is still probed, recorded, and walked.
func TestProbeCommonPaths_WalksSpecAtFrameworkPath(t *testing.T) {
	spec := "openapi: 3.0.0\nservers:\n  - url: /v1\npaths:\n  /widgets/{widgetId}:\n    get: {}\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v3/api-docs" {
			w.Header().Set("Content-Type", "application/yaml")
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
	assert.Equal(t, srv.URL+"/v3/api-docs", agg.apiSpec.URL)

	var specEP *EndpointFact
	for i := range agg.endpoints {
		if agg.endpoints[i].Source == "api-spec" {
			specEP = &agg.endpoints[i]
		}
	}
	require.NotNil(t, specEP, "the spec's own route must be walked into an api-spec EndpointFact")
	assert.Equal(t, srv.URL+"/v1/widgets/{widgetId}", specEP.URL)
}
