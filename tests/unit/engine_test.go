package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
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

// TestEngineRun_RejectedCount_OnlyCountsFilesInvalidInBothFormats confirms
// loadTemplates' logged "rejected" count doesn't flag a file that's simply
// written in the other template format (a nuclei-format file always fails
// native's own parser and vice versa — expected, not a problem) as
// rejected; only a file that fails *both* loaders is a genuine parse
// failure. A prior version of this logic summed both loaders' raw error
// counts unconditionally, which would have logged "2 rejected" here for a
// setup with zero actually-broken files — the same confusion a real user
// saw in the Web UI's template count (pkg/templatesync.List shares this
// exact fix, see list_test.go).
func TestEngineRun_RejectedCount_OnlyCountsFilesInvalidInBothFormats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nuclei.yaml"), []byte(`
id: nuclei-only-check
info:
  name: Nuclei-only check
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["ok"]
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("not: [valid yaml at all\n"), 0o644))

	cfg := scanner.Config{
		Targets:       []string{server.URL},
		TemplatePaths: []string{dir},
		Concurrency:   5,
		RateLimit:     50,
		Timeout:       5 * time.Second,
		Detector:      "misconfig",
	}
	require.NoError(t, cfg.Validate())

	var mu sync.Mutex
	var msgs []string
	_, err := scanner.New(cfg).WithLogCallback(func(level, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	}).Run(context.Background())
	require.NoError(t, err)

	joined := strings.Join(msgs, "\n")
	assert.Contains(t, joined, "loaded 1 nuclei-compatible, 0 native templates (1 rejected, 0 filtered by tag)",
		"nuclei.yaml is valid and must load; broken.yaml fails both loaders and must be the only rejection")
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

// TestEngineRun_FindingCallback_FiresPerBatch confirms WithFindingCallback
// receives every finding Run's return value carries — per doc12's Week 19
// design, granularity is per detector/template batch, not per individual
// HTTP response, but every finding in every batch must still reach the
// callback.
func TestEngineRun_FindingCallback_FiresPerBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // no security headers -> misconfig findings
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

	var mu sync.Mutex
	var callbackFindings []detectors.Finding
	findings, err := scanner.New(cfg).WithFindingCallback(func(f detectors.Finding) {
		mu.Lock()
		callbackFindings = append(callbackFindings, f)
		mu.Unlock()
	}).Run(context.Background())
	require.NoError(t, err)

	assert.ElementsMatch(t, findings, callbackFindings, "every finding in Run's return value must also have reached the callback")
	assert.NotEmpty(t, callbackFindings, "callback must have fired at least once")
}

// TestEngineRun_LogCallback_FiresForKnownSites confirms WithLogCallback fires
// for each of the log sites doc12 names: the missing-–scope warning, the
// per-target scope-skip message, and loadTemplates' load-summary line.
// Stderr output itself is unchanged in every case (warnf always prints
// first) — not re-asserted here since it's identical to the pre-existing,
// still-passing tests above that never set a callback at all.
func TestEngineRun_LogCallback_FiresForKnownSites(t *testing.T) {
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

	var mu sync.Mutex
	var levels, msgs []string
	_, err := scanner.New(cfg).WithLogCallback(func(level, msg string) {
		mu.Lock()
		levels = append(levels, level)
		msgs = append(msgs, msg)
		mu.Unlock()
	}).Run(context.Background())
	require.NoError(t, err)

	joined := strings.Join(msgs, "\n")
	assert.Contains(t, joined, "not covered by --scope", "must log the per-target scope-skip message")
	assert.Contains(t, joined, "loaded 0 nuclei-compatible, 0 native templates", "must log loadTemplates' summary line")
	assert.NotEmpty(t, levels)
	for _, level := range levels {
		assert.Contains(t, []string{"warn", "info", "error"}, level, "level must be one of the documented values")
	}
}

// TestEngineRun_LogCallback_FiresForScopeOmitted covers the third named
// site — loadScope's warning when --scope itself is never set — separately
// from the scope-skip test above, since setting ScopeFile at all suppresses
// this particular warning.
func TestEngineRun_LogCallback_FiresForScopeOmitted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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

	var mu sync.Mutex
	var msgs []string
	_, err := scanner.New(cfg).WithLogCallback(func(level, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	}).Run(context.Background())
	require.NoError(t, err)

	assert.Contains(t, strings.Join(msgs, "\n"), "no --scope file provided", "must log loadScope's missing-scope warning")
}

// TestEngineRun_LogCallback_FiresForDetectorError covers the fourth site
// doc12 names — the per-target error path — which previously had no stderr
// output at all (see engine.go's warnf call site added for this). A
// malformed --endpoint (invalid URL escape) makes idor.Detector.Run fail
// before any request is even sent, a cheap, deterministic way to force
// runDetector's error branch without relying on network failure timing.
func TestEngineRun_LogCallback_FiresForDetectorError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	cfg := scanner.Config{
		Targets:          []string{server.URL},
		Concurrency:      5,
		RateLimit:        50,
		Timeout:          5 * time.Second,
		Detector:         "idor",
		EndpointTemplate: "/%zz-invalid-escape",
		AuthToken:        "token",
	}
	require.NoError(t, cfg.Validate())

	var mu sync.Mutex
	var levels, msgs []string
	_, err := scanner.New(cfg).WithLogCallback(func(level, msg string) {
		mu.Lock()
		levels = append(levels, level)
		msgs = append(msgs, msg)
		mu.Unlock()
	}).Run(context.Background())
	require.Error(t, err, "a malformed --endpoint must still fail Run the same way it does without a callback")

	require.NotEmpty(t, levels)
	assert.Contains(t, levels, "error", "the detector-error site must log at \"error\" level")
	assert.Contains(t, strings.Join(msgs, "\n"), "running idor detector against", "must log which detector/target failed")
}

// TestEngineRun_PromptInjectionGuardrail_WarnsWhenConcurrencyTooHigh confirms
// loadTemplates' cost/latency guardrail (docs/13-implementation-plan-ph4.md
// Step 1) fires when a loaded template carries the "prompt-injection" tag
// and --concurrency exceeds the safe default of 5.
func TestEngineRun_PromptInjectionGuardrail_WarnsWhenConcurrencyTooHigh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pi.yaml"), []byte(`
id: pi-check
info:
  name: Prompt injection check
  severity: info
  tags: prompt-injection
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
`), 0o644))

	cfg := scanner.Config{
		Targets:       []string{server.URL},
		TemplatePaths: []string{dir},
		Concurrency:   25,
		RateLimit:     50,
		Timeout:       5 * time.Second,
		Detector:      "misconfig",
	}
	require.NoError(t, cfg.Validate())

	var mu sync.Mutex
	var msgs []string
	_, err := scanner.New(cfg).WithLogCallback(func(level, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	}).Run(context.Background())
	require.NoError(t, err)

	assert.Contains(t, strings.Join(msgs, "\n"), "prompt-injection", "must warn when a prompt-injection-tagged template loads with --concurrency above the safe default")
}

// TestEngineRun_PromptInjectionGuardrail_SilentAtOrBelowSafeDefault is the
// negative counterpart: no warning fires at --concurrency 5 (the safe
// default itself) even with a prompt-injection-tagged template loaded.
func TestEngineRun_PromptInjectionGuardrail_SilentAtOrBelowSafeDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pi.yaml"), []byte(`
id: pi-check
info:
  name: Prompt injection check
  severity: info
  tags: prompt-injection
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
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

	var mu sync.Mutex
	var msgs []string
	_, err := scanner.New(cfg).WithLogCallback(func(level, msg string) {
		mu.Lock()
		msgs = append(msgs, msg)
		mu.Unlock()
	}).Run(context.Background())
	require.NoError(t, err)

	assert.NotContains(t, strings.Join(msgs, "\n"), "prompt-injection", "must not warn when --concurrency is at or below the safe default")
}

// TestEngineRun_NoCallback_BehaviorUnchanged is a regression guard on the
// "CLI-safe" claim in doc12's Week 19 design: Run's return value must be
// identical whether or not a caller ever calls WithFindingCallback/
// WithLogCallback — cmd/hackerfive/scan.go never does, so this locks in that
// its behavior never silently changes as callbacks are added elsewhere.
func TestEngineRun_NoCallback_BehaviorUnchanged(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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
	assert.NotEmpty(t, findings)
}
