package unit

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// countingServer returns an httptest server that records how many times
// each path was requested, plus a helper to read one path's count.
func countingServer(t *testing.T, body string) (*httptest.Server, func(path string) int) {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counts[r.URL.Path]++
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return counts[path]
	}
}

func loadOne(t *testing.T, yaml string) *nuclei.Template {
	t.Helper()
	dir := t.TempDir()
	writeTemplate(t, dir, "t.yaml", yaml)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	return templates[0]
}

func statusTemplate(id, path string) string {
	return fmt.Sprintf(`
id: %s
info:
  name: %s
  severity: info
http:
  - method: GET
    path:
      - "%s"
    matchers:
      - type: status
        status:
          - 200
`, id, id, path)
}

// TestExecutorRespCache_CoalescesIdenticalGET is D5's core claim: two
// templates whose only request is a byte-identical GET to the same URL,
// run on one Executor, issue a single HTTP request — the second is served
// from the response cache — yet both still produce their finding.
func TestExecutorRespCache_CoalescesIdenticalGET(t *testing.T) {
	srv, hits := countingServer(t, "hello")

	exec := nuclei.New(newExecutorClient())
	a := loadOne(t, statusTemplate("cache-a", "{{BaseURL}}/robots.txt"))
	b := loadOne(t, statusTemplate("cache-b", "{{BaseURL}}/robots.txt"))

	fa, err := exec.Run(context.Background(), srv.URL, a)
	require.NoError(t, err)
	fb, err := exec.Run(context.Background(), srv.URL, b)
	require.NoError(t, err)

	assert.Len(t, fa, 1)
	assert.Len(t, fb, 1, "the cached-response template still matches and reports")
	assert.Equal(t, 1, hits("/robots.txt"), "the identical second GET must be served from cache, not re-fetched")
}

// TestExecutorRespCache_DistinctURLsNotCoalesced is the negative guard: a
// different path is a different cache key and still hits the network.
func TestExecutorRespCache_DistinctURLsNotCoalesced(t *testing.T) {
	srv, hits := countingServer(t, "hello")

	exec := nuclei.New(newExecutorClient())
	a := loadOne(t, statusTemplate("dist-a", "{{BaseURL}}/a"))
	b := loadOne(t, statusTemplate("dist-b", "{{BaseURL}}/b"))

	_, err := exec.Run(context.Background(), srv.URL, a)
	require.NoError(t, err)
	_, err = exec.Run(context.Background(), srv.URL, b)
	require.NoError(t, err)

	assert.Equal(t, 1, hits("/a"))
	assert.Equal(t, 1, hits("/b"))
}

// TestExecutorRespCache_HeaderDifferenceNotCoalesced proves the key
// includes the rendered request headers: same URL, different template
// header, two requests.
func TestExecutorRespCache_HeaderDifferenceNotCoalesced(t *testing.T) {
	srv, hits := countingServer(t, "hello")

	exec := nuclei.New(newExecutorClient())
	a := loadOne(t, `
id: hdr-a
info: {name: hdr-a, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/h"]
    headers:
      X-Probe: alpha
    matchers:
      - type: status
        status: [200]
`)
	b := loadOne(t, `
id: hdr-b
info: {name: hdr-b, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/h"]
    headers:
      X-Probe: beta
    matchers:
      - type: status
        status: [200]
`)

	_, err := exec.Run(context.Background(), srv.URL, a)
	require.NoError(t, err)
	_, err = exec.Run(context.Background(), srv.URL, b)
	require.NoError(t, err)

	assert.Equal(t, 2, hits("/h"), "a differing request header must defeat the cache")
}

// TestExecutorRespCache_TimingTemplateAlwaysFetches: a template whose
// matcher reads the bare "duration" identifier (blind time-based check) is
// carved out — running it twice on one Executor issues two requests, so
// the second run measures a real elapsed time rather than a cached 0.
func TestExecutorRespCache_TimingTemplateAlwaysFetches(t *testing.T) {
	srv, hits := countingServer(t, "hello")

	exec := nuclei.New(newExecutorClient())
	tmpl := loadOne(t, `
id: timing-carveout
info: {name: timing-carveout, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/t"]
    matchers:
      - type: dsl
        dsl:
          - "duration >= 0"
`)

	_, err := exec.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)
	_, err = exec.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)

	assert.Equal(t, 2, hits("/t"), "a duration-matcher template must always hit the network")
}

// TestExecutorRespCache_InteractshTemplateAlwaysFetches: a request
// embedding {{interactsh-url}} is carved out even when OOB is unconfigured.
func TestExecutorRespCache_InteractshTemplateAlwaysFetches(t *testing.T) {
	srv, hits := countingServer(t, "OK")

	exec := nuclei.New(newExecutorClient())
	tmpl := loadOne(t, `
id: interactsh-carveout
info: {name: interactsh-carveout, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/cb?u={{interactsh-url}}"]
    matchers:
      - type: word
        words: ["OK"]
`)

	_, err := exec.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)
	_, err = exec.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)

	assert.Equal(t, 2, hits("/cb"), "an interactsh_ template must always hit the network")
}

// TestExecutorRespCache_PayloadsTemplateFiresEveryIteration: a payloads:
// template is carved out of the cache; every substitution pass still
// fires. Two payload values that don't appear in the URL path prove the
// carve-out itself (identical URL across iterations would otherwise
// coalesce to one request).
func TestExecutorRespCache_PayloadsTemplateFiresEveryIteration(t *testing.T) {
	srv, hits := countingServer(t, "hello")

	exec := nuclei.New(newExecutorClient())
	tmpl := loadOne(t, `
id: payloads-carveout
info: {name: payloads-carveout, severity: info}
http:
  - method: POST
    path: ["{{BaseURL}}/p"]
    body: "v={{val}}"
    attack: batteringram
    payloads:
      val:
        - one
        - two
    matchers:
      - type: status
        status: [200]
`)

	_, err := exec.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)

	assert.Equal(t, 2, hits("/p"), "each payloads: iteration must fire its own request")
}

// TestExecutorKnownDeadPaths_SkipsLoneMatcherOnlyTemplate: with a
// --recon-file-derived known-dead set and no --header, a single-request
// matcher-only template whose only path is known-dead makes no request and
// reports nothing; the same Executor carrying a credential (auth posture
// differs from recon's) still fires it.
func TestExecutorKnownDeadPaths_SkipsLoneMatcherOnlyTemplate(t *testing.T) {
	srv, hits := countingServer(t, "hello")
	tmpl := loadOne(t, statusTemplate("dead-x", "{{BaseURL}}/x"))

	unauth := nuclei.New(newExecutorClient()).WithKnownDeadPaths([]string{"/x"})
	f, err := unauth.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)
	assert.Empty(t, f)
	assert.Equal(t, 0, hits("/x"), "a known-dead lone matcher-only path: must not be requested")

	authed := nuclei.New(newExecutorClient()).
		WithHeaders(map[string]string{"Cookie": "session=abc"}).
		WithKnownDeadPaths([]string{"/x"})
	_, err = authed.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)
	assert.Equal(t, 1, hits("/x"), "an authenticated scan's 404 surface differs from recon's — it must still fire")
}

// TestExecutorKnownDeadPaths_DoesNotSkipMultiRequestTemplate: the skip is
// deliberately narrow — a template with more than one request keeps firing
// even if one path is known-dead, since an early request may exist to feed
// a later one.
func TestExecutorKnownDeadPaths_DoesNotSkipMultiRequestTemplate(t *testing.T) {
	srv, hits := countingServer(t, "hello")
	tmpl := loadOne(t, `
id: dead-multi
info: {name: dead-multi, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/x"]
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: ["{{BaseURL}}/y"]
    matchers:
      - type: status
        status: [200]
`)

	exec := nuclei.New(newExecutorClient()).WithKnownDeadPaths([]string{"/x"})
	_, err := exec.Run(context.Background(), srv.URL, tmpl)
	require.NoError(t, err)
	assert.Equal(t, 1, hits("/x"), "a multi-request template still fires every request")
	assert.Equal(t, 1, hits("/y"))
}
