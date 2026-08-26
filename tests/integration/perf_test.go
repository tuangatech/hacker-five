//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// TestEngineRun_HundredTargetsPerformance measures wall-clock time for
// Engine.Run across 100 targets with the misconfig detector — doc03's Phase
// 1b success metric "scans 100 targets in <2 minutes", never actually
// measured before this test (see docs/10-implementation-plan-ph1b.md's
// Definition of Done).
//
// Grouped with the integration tests (build-tag `integration`, not run by
// default `go test ./...`) purely because it's slow, like they are — it
// doesn't need a live external target or an env var, since it stands up its
// own local httptest.Server.
//
// All 100 "targets" point at that one local server: standing up 100 distinct
// external hosts isn't practical for a repeatable, CI-safe test. This
// measures the engine's own per-target/per-request overhead (worker pool,
// rate limiter, the misconfig detector's ~50 requests/target — 20
// exposed-path + 1 missing-header + 3 disallowed-method + 1 CORS + 20
// verbose-error + 5 default-creds checks, see pkg/detectors/misconfig/rules.go),
// not real-world network variance across distinct hosts.
//
// Worth knowing going in: at the CLI's own defaults (--rate-limit 50,
// --concurrency 25) and misconfig's ~50 requests/target, 100 targets is
// ~5,000 requests total. The rate limiter allows a burst of 50 requests free,
// then paces the rest at 50/sec — so the theoretical floor here is roughly
// (5000-50)/50 ≈ 99s, regardless of target count or infrastructure. This
// metric is really testing the rate-limiter/detector-request-volume
// interaction, not raw engine throughput — worth knowing if the result lands
// close to the 2-minute boundary rather than comfortably under it.
func TestEngineRun_HundredTargetsPerformance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	targets := make([]string, 100)
	for i := range targets {
		targets[i] = server.URL
	}

	cfg := scanner.Config{
		Targets:     targets,
		Concurrency: 25, // matches cmd/hackerfive/scan.go's --concurrency default
		RateLimit:   50, // matches --rate-limit default
		Timeout:     5 * time.Second,
		Detector:    "misconfig",
	}
	require.NoError(t, cfg.Validate())

	start := time.Now()
	findings, err := scanner.New(cfg).Run(context.Background())
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.NotEmpty(t, findings, "missing security headers should be found across all 100 targets")

	t.Logf("100 targets, misconfig detector, default rate-limit/concurrency: %s elapsed (doc03 target: <2m)", elapsed)
	assert.Less(t, elapsed, 2*time.Minute, "doc03 Phase 1b success metric: scan 100 targets in <2 minutes")
}
