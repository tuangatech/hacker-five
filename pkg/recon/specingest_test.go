package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

const ingestSpecJSON = `{
  "openapi": "3.0.1",
  "servers": [{"url": "http://localhost:8888"}],
  "paths": {
    "/identity/api/v2/vehicle/{vehicleId}/location": {"get": {"parameters": [{"name": "vehicleId", "in": "path"}]}},
    "/workshop/api/shop/orders/{orderId}": {"get": {"parameters": [{"name": "orderId", "in": "path"}]}}
  }
}`

// TestIngestOpenAPISpecs_FileRef: a local spec file is walked and its routes
// rebase onto the target host (LT-89).
func TestIngestOpenAPISpecs_FileRef(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crapi.json")
	require.NoError(t, os.WriteFile(path, []byte(ingestSpecJSON), 0o644))

	out := IngestOpenAPISpecs(context.Background(), nil, nil, nil, []string{path}, "http://localhost:8888")

	require.Len(t, out.Endpoints, 2)
	require.NotNil(t, out.APISpec)
	assert.Equal(t, "openapi", out.APISpec.Kind)

	urls := map[string]bool{}
	for _, ef := range out.Endpoints {
		urls[ef.URL] = true
		assert.Equal(t, "api-spec", ef.Source)
	}
	assert.True(t, urls["http://localhost:8888/identity/api/v2/vehicle/{vehicleId}/location"])
	assert.True(t, urls["http://localhost:8888/workshop/api/shop/orders/{orderId}"])
	assert.Contains(t, strings.Join(out.Warnings, " | "), "walked 2 route(s)")
}

// TestIngestOpenAPISpecs_URLRef: an http(s) spec ref is fetched through the
// supplied client and rebased onto the fetch host.
func TestIngestOpenAPISpecs_URLRef(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(ingestSpecJSON))
	}))
	defer srv.Close()

	out := IngestOpenAPISpecs(context.Background(), newTestClient(), nil, nil, []string{srv.URL + "/openapi.json"}, "http://ignored.example")

	require.Len(t, out.Endpoints, 2)
	for _, ef := range out.Endpoints {
		assert.True(t, strings.HasPrefix(ef.URL, srv.URL+"/"), "a URL ref rebases routes onto the fetch host, not the target")
	}
}

// TestIngestOpenAPISpecs_ScopeFiltersRoutes: with a scope that excludes the
// rebase host, every walked route is diverted to OutOfScope.
func TestIngestOpenAPISpecs_ScopeFiltersRoutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	require.NoError(t, os.WriteFile(path, []byte(ingestSpecJSON), 0o644))

	sc, err := scope.New([]string{"only-this-host.example"})
	require.NoError(t, err)

	out := IngestOpenAPISpecs(context.Background(), nil, sc, nil, []string{path}, "http://localhost:8888")
	assert.Empty(t, out.Endpoints)
	assert.Nil(t, out.APISpec)
	assert.NotEmpty(t, out.OutOfScope)
	assert.Contains(t, strings.Join(out.Warnings, " | "), "outside --scope")
}

// TestIngestOpenAPISpecs_BadRefs: a missing file / non-spec body warn and
// contribute nothing, without aborting the rest.
func TestIngestOpenAPISpecs_BadRefs(t *testing.T) {
	dir := t.TempDir()
	notASpec := filepath.Join(dir, "x.json")
	require.NoError(t, os.WriteFile(notASpec, []byte(`{"hello":"world"}`), 0o644))
	good := filepath.Join(dir, "good.json")
	require.NoError(t, os.WriteFile(good, []byte(ingestSpecJSON), 0o644))

	out := IngestOpenAPISpecs(context.Background(), nil, nil, nil,
		[]string{filepath.Join(dir, "nope.json"), notASpec, good}, "http://localhost:8888")

	require.Len(t, out.Endpoints, 2, "the one good ref still lands despite two bad refs before it")
	joined := strings.Join(out.Warnings, " | ")
	assert.Contains(t, joined, "nope.json")
	assert.Contains(t, joined, "not a recognisable OpenAPI")
}
