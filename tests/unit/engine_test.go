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
