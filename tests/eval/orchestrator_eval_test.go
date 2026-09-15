//go:build eval

package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// orchestratorResult mirrors pkg/orchestrator.Result's JSON encoding — that
// struct carries no json tags, so encoding/json's case-insensitive
// field-name fallback decodes its plain Go field names directly. Only the
// fields this harness reports on are kept; Tree/History decode into nothing
// and are dropped.
type orchestratorResult struct {
	Findings   []detectors.Finding
	Iterations int
	SpendUSD   float64
}

// TestOrchestratorEvalHarness is M5 (docs/93-implementation-plan-agent-orchestrator.md):
// the third leg of this project's FP/FN comparison, alongside TestEvalHarness
// (deterministic `scan` baseline) and TestAgentEvalHarness (MCP-plan mode) —
// same lab targets, same tests/fixtures/expected-findings/*.json fixtures,
// same matchesAnyPrefix grading, same cost/tool-call/wall-clock metrics
// already logged by the other two, this time resolved through
// `hackerfive agent` (pkg/orchestrator's LLM-driven loop). Reports honestly
// (t.Logf) rather than gating on FP/FN beyond the same per-prefix subtests
// the other two harnesses run — an orchestrator-introduced miss here is
// itself part of the signal doc93 M5 exists to produce, and is the actual
// gate for pointing this mode at a real program (doc93 M5's own words: "Do
// not point this mode at a real program until this table exists and shows a
// genuine improvement").
//
// --allow-agent-scripts is deliberately never passed: this harness runs
// unattended (no human present for scriptexec's per-run approval prompt,
// and an unanswered prompt would just read EOF from the subprocess's empty
// stdin and auto-deny), and script.explore is not required to resolve any
// of these fixtures' known findings.
func TestOrchestratorEvalHarness(t *testing.T) {
	for _, sc := range OrchestratorScenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			for _, envVar := range sc.RequiredEnv {
				if os.Getenv(envVar) == "" {
					t.Skipf("%s not set — skipping (see docs/20-setup-testing-targets.md)", envVar)
				}
			}
			// Unlike TestAgentEvalHarness (MCP-plan mode has a non-LLM
			// fallback path), pkg/orchestrator.Run hard-requires an LLM
			// client — skip rather than fail when neither tier is
			// configured, since that's an environment gap, not a real miss.
			if _, err := llmfallback.New(); err != nil {
				t.Skipf("no LLM tier configured (%v) — hackerfive agent requires one, skipping", err)
			}

			var expected expectedFindings
			expectedRaw, err := os.ReadFile(filepath.Join(repoRoot(), sc.ExpectedFile))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(expectedRaw, &expected))

			target := sc.Target()
			scopeFile := filepath.Join(t.TempDir(), "scope.txt")
			require.NoError(t, os.WriteFile(scopeFile, []byte(hostOnly(target)+"\n"), 0o644))

			args := []string{
				"agent", "-t", target,
				"--recon-depth", sc.Depth,
				"--scope", scopeFile,
			}
			if sc.AuthTokenEnv != "" {
				args = append(args, "--auth-token", os.Getenv(sc.AuthTokenEnv))
			}
			if sc.OtherAuthTokenEnv != "" {
				args = append(args, "--other-auth-token", os.Getenv(sc.OtherAuthTokenEnv))
			}
			if sc.Header != nil {
				args = append(args, "--header", sc.Header())
			}

			// Same 10m rationale as TestAgentEvalHarness (LT-137): active-depth
			// recon plus one or more scan.leaf template-corpus passes
			// legitimately takes several minutes against a real target, on
			// top of however many LLM round trips NextAction makes.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, binPath, args...)
			cmd.Dir = repoRoot()
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			start := time.Now()
			runErr := cmd.Run()
			elapsed := time.Since(start)
			if runErr != nil {
				t.Logf("%s: hackerfive agent exited with error (non-fatal to this harness — an orchestrator-mode failure is itself part of the FP/FN picture): %v\nstderr:\n%s",
					sc.Name, runErr, stderr.String())
			}

			var result orchestratorResult
			trimmed := bytes.TrimSpace(stdout.Bytes())
			if len(trimmed) > 0 {
				require.NoError(t, json.Unmarshal(trimmed, &result), "agent output: %s", trimmed)
			}

			findings := result.Findings
			unexpected := 0
			for _, f := range findings {
				if !matchesAnyPrefix(f.ID, expected.ExpectedIDPrefixes) {
					unexpected++
				}
			}
			t.Logf("%s: %d finding(s), %d unexpected (candidate FPs), cost=$%.4f, tool_calls=%d, wall_clock=%s",
				sc.Name, len(findings), unexpected, result.SpendUSD, result.Iterations, elapsed.Round(time.Millisecond))

			for _, prefix := range expected.ExpectedIDPrefixes {
				prefix := prefix
				t.Run("finds_"+prefix, func(t *testing.T) {
					if contains(sc.SkipPrefixes, prefix) {
						t.Skipf("%q intentionally not exercised by this OrchestratorScenario — see orchestrator_run.go", prefix)
					}
					if !anyHasPrefix(findings, prefix) {
						t.Errorf("no finding with ID prefix %q — expected per %s (orchestrator-driven run, see t.Logf above for what it did produce)", prefix, sc.ExpectedFile)
					}
				})
			}
		})
	}
}
