//go:build eval

package eval

import (
	"bufio"
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

// agentStreamEvent mirrors cmd/hackerfive/agent.go's agentStreamEvent — one
// JSON-per-line event on `hackerfive agent`'s stdout/--output stream
// (docs/follow-up.md LT-163 item 3): a "finding" event the instant a
// scan.leaf dispatch produces one, and a final "result" event with the full
// Result once Run returns. Parsing line-by-line rather than requiring a
// single trailing JSON document is what lets this harness still see real
// findings from a run this test's own 20-minute context timeout killed
// before it ever produced a "result" event.
type agentStreamEvent struct {
	Type    string              `json:"type"`
	Finding *detectors.Finding  `json:"finding,omitempty"`
	Result  *orchestratorResult `json:"result,omitempty"`
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
			require.NoError(t, os.WriteFile(scopeFile, []byte(hostScopeEntry(target)+"\n"), 0o644))

			args := sc.AgentArgs(target, scopeFile)

			// 20m, not TestAgentEvalHarness's 10m (LT-137): active-depth recon
			// plus one or more scan.leaf template-corpus passes legitimately
			// takes several minutes against a real target, on top of however
			// many LLM round trips NextAction makes — and unlike the MCP-plan
			// mode that 10m was calibrated for, pkg/orchestrator.Config.
			// MinIterations (LT-162's fix) forces a floor of dispatched turns
			// even when the model wants to stop early, each with its own
			// NextAction round trip. Live-verified 2026-09-19 against crAPI:
			// individual NextAction calls took 60-150s+ against
			// deepseek-v4.1-flash, and a 10m ceiling killed the run
			// (signal: killed, 0 tool_calls) mid-way through only its 4th or
			// 5th turn — at the time, that discarded real findings already
			// surfaced via OnLog (e.g. a genuine misconfig-exposed-path-.env
			// hit), since `hackerfive agent` only emitted its final JSON
			// after the loop exited cleanly (docs/follow-up.md LT-163 item 3,
			// since fixed: findings now stream as individual JSONL events —
			// see agentStreamEvent below and the parsing loop that reads
			// them even from a killed run's partial output). 20m stays the
			// budget regardless, since the underlying NextAction latency is
			// unchanged.
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
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

			// Parse every event line rather than requiring a final "result"
			// line: a run this harness's own context timeout killed produces
			// no "result" event at all, but every "finding" event already
			// written before the kill is still real signal (LT-163 item 3) —
			// falling back to a single json.Unmarshal on the whole buffer
			// would report 0 findings for a run that actually found some.
			var findings []detectors.Finding
			var result orchestratorResult
			sawResult := false
			lineScanner := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
			lineScanner.Buffer(make([]byte, 0, 64*1024), 8<<20)
			for lineScanner.Scan() {
				line := bytes.TrimSpace(lineScanner.Bytes())
				if len(line) == 0 {
					continue
				}
				var ev agentStreamEvent
				require.NoError(t, json.Unmarshal(line, &ev), "agent output line: %s", line)
				switch ev.Type {
				case "finding":
					if ev.Finding != nil {
						findings = append(findings, *ev.Finding)
					}
				case "result":
					if ev.Result != nil {
						result = *ev.Result
						sawResult = true
					}
				}
			}
			require.NoError(t, lineScanner.Err(), "scanning agent output")
			if sawResult {
				// The final event's own Findings is the authoritative,
				// complete list (a superset of what streamed in via
				// "finding" events) — prefer it on a clean run.
				findings = result.Findings
			}

			unexpected := 0
			for _, f := range findings {
				if !matchesAnyPrefix(f.ID, expected.ExpectedIDPrefixes) {
					unexpected++
				}
			}
			t.Logf("%s: %d finding(s), %d unexpected (candidate FPs), cost=$%.4f, tool_calls=%d, wall_clock=%s, result_event=%v",
				sc.Name, len(findings), unexpected, result.SpendUSD, result.Iterations, elapsed.Round(time.Millisecond), sawResult)

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
