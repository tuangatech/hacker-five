package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner"
)

func TestEngineRun_DetectorOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // no security headers set -> misconfig missing-header findings
	}))
	t.Cleanup(server.Close)

	cfg := scanner.Config{
		Targets:     []string{server.URL},
		Concurrency: 5,
		RateLimit:   50,
		Timeout:     5 * time.Second,
		Detector:    "misconfig",
	}
	require.NoError(t, cfg.Validate())

	findings, err := scanner.New(cfg).Run(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "missing security headers should be found")
	for _, f := range findings {
		assert.Equal(t, "misconfig", f.Type)
		assert.Contains(t, f.Evidence["request"], server.URL, "Finding.Evidence must carry raw request evidence — Future Enhancement #7")
		assert.Contains(t, f.Evidence["response"], "HTTP 404", "Finding.Evidence must carry raw response evidence — Future Enhancement #7 (handler always returns 404)")
	}
}

// TestEngineRun_TemplatesRunAlongsideDetector is the first test to exercise
// Engine.Run's Step 3 template-loading path (loadTemplates + both
// executors), which was previously entirely untested — see
// docs/10-implementation-plan-ph1b.md Step 4.
func TestEngineRun_TemplatesRunAlongsideDetector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello-from-target"))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "native.yaml"), []byte(`
id: native-hello-check
info:
  name: Native hello check
  severity: info
tags:
  - custom
requests:
  - path: "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "hello-from-target"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nuclei.yaml"), []byte(`
id: nuclei-hello-check
info:
  name: Nuclei hello check
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "hello-from-target"
`), 0o644))

	cfg := scanner.Config{
		Targets:       []string{server.URL},
		TemplatePaths: []string{dir},
		Concurrency:   5,
		RateLimit:     50,
		Timeout:       5 * time.Second,
		Detector:      "misconfig",
	}
	require.NoError(t, cfg.Validate())

	findings, err := scanner.New(cfg).Run(context.Background())
	require.NoError(t, err)

	var haveNative, haveNuclei bool
	for _, f := range findings {
		switch f.ID {
		case "native-native-hello-check-0":
			haveNative = true
		case "nuclei-nuclei-hello-check-0":
			haveNuclei = true
		}
	}
	assert.True(t, haveNative, "native template finding must be present alongside the built-in detector's")
	assert.True(t, haveNuclei, "nuclei-compatible template finding must be present alongside the built-in detector's")
}

// TestEngineRun_TagsFilterTemplates confirms --tags (Config.Tags) does the
// OR-match filtering documented in engine.go's loadTemplates: a template
// loads only if it carries at least one of the requested tags. Two
// templates, one per format, tagged "wordpress" and "grafana" respectively —
// requesting only "wordpress" must fire the first and skip the second.
func TestEngineRun_TagsFilterTemplates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello-from-target"))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "wanted.yaml"), []byte(`
id: wanted-check
info:
  name: Wanted check
  severity: info
tags:
  - wordpress
requests:
  - path: "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "hello-from-target"
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "unwanted.yaml"), []byte(`
id: unwanted-check
info:
  name: Unwanted check
  severity: info
  tags: grafana
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "hello-from-target"
`), 0o644))

	cfg := scanner.Config{
		Targets:       []string{server.URL},
		TemplatePaths: []string{dir},
		Tags:          []string{"WordPress"}, // deliberately mixed-case: filtering must normalize
		Concurrency:   5,
		RateLimit:     50,
		Timeout:       5 * time.Second,
		Detector:      "misconfig",
	}
	require.NoError(t, cfg.Validate())

	findings, err := scanner.New(cfg).Run(context.Background())
	require.NoError(t, err)

	var haveWanted, haveUnwanted bool
	for _, f := range findings {
		switch f.ID {
		case "native-wanted-check-0":
			haveWanted = true
		case "nuclei-unwanted-check-0":
			haveUnwanted = true
		}
	}
	assert.True(t, haveWanted, "template tagged wordpress must fire when --tags wordpress is set")
	assert.False(t, haveUnwanted, "template tagged grafana must be filtered out when --tags wordpress is set")
}

func TestEngineRun_MultipleTargets(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(server1.Close)
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(server2.Close)

	cfg := scanner.Config{
		Targets:     []string{server1.URL, server2.URL},
		Concurrency: 5,
		RateLimit:   50,
		Timeout:     5 * time.Second,
		Detector:    "misconfig",
	}
	require.NoError(t, cfg.Validate())

	findings, err := scanner.New(cfg).Run(context.Background())
	require.NoError(t, err)

	hosts := map[string]bool{}
	for _, f := range findings {
		u, err := url.Parse(f.Target)
		require.NoError(t, err)
		hosts[u.Host] = true
	}
	assert.Len(t, hosts, 2, "both targets must produce findings, not just one")
}

// TestEngineRun_ScopeFile_BlocksUnmatchedTarget confirms Engine.Run actually
// skips dispatching a target that --scope doesn't cover, per
// docs/11-implementation-plan-ph2.md Step 0 — the mechanism itself is
// covered in detail by tests/unit/scope_test.go; this locks in that Run
// wires it in, not just that scope.Allowed works in isolation.
func TestEngineRun_ScopeFile_BlocksUnmatchedTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(scopeFile, []byte("totally-different-domain.example\n"), 0o644))

	cfg := scanner.Config{
		Targets:     []string{server.URL},
		Concurrency: 5,
		RateLimit:   50,
		Timeout:     5 * time.Second,
		Detector:    "misconfig",
		ScopeFile:   scopeFile,
	}
	require.NoError(t, cfg.Validate())

	findings, err := scanner.New(cfg).Run(context.Background())
	require.NoError(t, err)
	assert.Empty(t, findings, "a target not covered by --scope must never be dispatched")
}

// TestEngineRun_ScopeFile_AllowsMatchedTarget is the positive counterpart —
// a --scope entry that does cover the target lets the scan proceed exactly
// as if --scope had been omitted.
func TestEngineRun_ScopeFile_AllowsMatchedTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(scopeFile, []byte("127.0.0.1\n"), 0o644))

	cfg := scanner.Config{
		Targets:     []string{server.URL},
		Concurrency: 5,
		RateLimit:   50,
		Timeout:     5 * time.Second,
		Detector:    "misconfig",
		ScopeFile:   scopeFile,
	}
	require.NoError(t, cfg.Validate())

	findings, err := scanner.New(cfg).Run(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, findings, "a target covered by --scope must be dispatched normally")
}
