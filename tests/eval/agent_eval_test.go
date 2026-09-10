//go:build eval

package eval

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/mcpserver"
)

// hostOnly is agent_run.go's AgentScenarios' small helper — kept here
// (eval-tagged) since it's only ever called from this file.
func hostOnly(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}

// connectAgentClient/callTool/firstText are a small, deliberate duplicate of
// tests/integration/agent_e2e_test.go's own helpers of the same name — this
// package can't import tests/integration (both are independent `main`-less
// test packages with their own go:build tag), same proportionate-duplication
// precedent tests/integration/recon_plan_crapi_test.go's own comment
// documents for the tests/integration <-> cmd/hackerfive boundary.
func connectAgentClient(ctx context.Context, t *testing.T) *mcp.ClientSession {
	t.Helper()
	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := mcpserver.New().Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "g1-eval", Version: "v0"}, &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{
				"approve":                  true,
				"acknowledge_out_of_scope": true,
			}}, nil
		},
	})
	session, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	return session
}

func callTool(ctx context.Context, t *testing.T, s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

func firstText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatalf("no TextContent block in result: %+v", res.Content)
	return ""
}

// TestAgentEvalHarness is G1's real benchmark run (docs/16-implementation-plan-ph7.md
// Step 6): the same fixed challenge set TestEvalHarness grades, resolved
// through a real MCP-client-driven agent session (recon -> plan -> approve
// -> execute, then findings.triage when an LLM tier is configured) instead
// of a hand-built scan command. Reports agent-driven FP/FN against the same
// fixtures the detector-only baseline uses, plus per-run cost/tool-call/
// wall-clock accounting — logged honestly (t.Logf), not gated as a hard
// pass/fail beyond the same per-prefix subtests TestEvalHarness already
// runs, since an agent-introduced miss here is itself the signal this
// harness exists to surface.
func TestAgentEvalHarness(t *testing.T) {
	for _, sc := range AgentScenarios {
		sc := sc
		t.Run(sc.Name, func(t *testing.T) {
			for _, envVar := range sc.RequiredEnv {
				if os.Getenv(envVar) == "" {
					t.Skipf("%s not set — skipping (see docs/20-setup-testing-targets.md)", envVar)
				}
			}

			var expected expectedFindings
			expectedRaw, err := os.ReadFile(filepath.Join(repoRoot(), sc.ExpectedFile))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(expectedRaw, &expected))

			// 10m, not 5m: real, live-verified 2026-09-10 (LT-137's fix) — a
			// misconfig leaf's own template-corpus pass against a real target
			// legitimately takes ~3 minutes even tag-narrowed (the doc15
			// Step 6a floor's tags are broad category words, matching most
			// of the corpus for a target with no fingerprinted tech to add
			// product-specific extras); active-depth recon itself can also
			// take over a minute. This is real wall-clock the harness must
			// budget for, not a bug to hide behind a short timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			session := connectAgentClient(ctx, t)
			defer func() { _ = session.Close() }()

			start := time.Now()
			target := sc.Target()
			scope := []string{hostOnly(target)}

			reconRes := callTool(ctx, t, session, "recon", map[string]any{
				"target": target, "scope": scope, "depth": sc.Depth,
				"reason": "G1 eval: map the target before planning",
			})
			require.False(t, reconRes.IsError, "recon: %s", firstText(t, reconRes))

			planArgs := map[string]any{
				"target": target, "scope": scope, "depth": sc.Depth,
				"reason": "G1 eval: resolve and execute a plan",
			}
			if sc.AuthTokenEnv != "" {
				planArgs["auth_token"] = os.Getenv(sc.AuthTokenEnv)
			}
			if sc.OtherAuthTokenEnv != "" {
				planArgs["other_auth_token"] = os.Getenv(sc.OtherAuthTokenEnv)
			}
			planRes := callTool(ctx, t, session, "plan", planArgs)
			require.False(t, planRes.IsError, "plan: %s", firstText(t, planRes))

			var plan struct {
				Approved      bool                `json:"approved"`
				SpendUSD      float64             `json:"spend_usd"`
				Findings      []detectors.Finding `json:"findings"`
				SkippedLeaves []string            `json:"skipped_leaves"`
			}
			require.NoError(t, json.Unmarshal([]byte(firstText(t, planRes)), &plan))
			require.True(t, plan.Approved, "plan must come back approved after the auto-accepted elicitation")

			findings := plan.Findings
			cost := plan.SpendUSD
			if len(plan.SkippedLeaves) > 0 {
				t.Logf("%s: %d leaf/leaves skipped at execution: %v", sc.Name, len(plan.SkippedLeaves), plan.SkippedLeaves)
			}

			// findings.triage: only when an LLM tier is actually configured
			// (this harness must not silently no-op-succeed a paid call) and
			// there's something to rank.
			if os.Getenv("OPENROUTER_API_KEY") != "" && len(findings) > 0 {
				triageRes := callTool(ctx, t, session, "findings.triage", map[string]any{
					"findings": findings, "reason": "G1 eval: triage the run's findings",
				})
				if !triageRes.IsError {
					var triage struct {
						Approved        bool   `json:"approved"`
						EscalateToHuman string `json:"escalate_to_human,omitempty"`
					}
					if err := json.Unmarshal([]byte(firstText(t, triageRes)), &triage); err == nil && triage.EscalateToHuman != "" {
						t.Logf("%s: triage escalated to human: %s", sc.Name, triage.EscalateToHuman)
					}
				} else {
					t.Logf("%s: findings.triage call errored (non-fatal to this harness): %s", sc.Name, firstText(t, triageRes))
				}
			}

			elapsed := time.Since(start)

			logRes := callTool(ctx, t, session, "session.log", nil)
			var sessLog struct {
				Total int `json:"total"`
			}
			if !logRes.IsError {
				_ = json.Unmarshal([]byte(firstText(t, logRes)), &sessLog)
			}

			unexpected := 0
			for _, f := range findings {
				if !matchesAnyPrefix(f.ID, expected.ExpectedIDPrefixes) {
					unexpected++
				}
			}
			t.Logf("%s: %d finding(s), %d unexpected (candidate FPs), cost=$%.4f, tool_calls=%d, wall_clock=%s",
				sc.Name, len(findings), unexpected, cost, sessLog.Total, elapsed.Round(time.Millisecond))

			for _, prefix := range expected.ExpectedIDPrefixes {
				prefix := prefix
				t.Run("finds_"+prefix, func(t *testing.T) {
					if contains(sc.SkipPrefixes, prefix) {
						t.Skipf("%q intentionally not exercised by this AgentScenario — see agent_run.go", prefix)
					}
					if !anyHasPrefix(findings, prefix) {
						t.Errorf("no finding with ID prefix %q — expected per %s (agent-driven run, see t.Logf above for what it did produce)", prefix, sc.ExpectedFile)
					}
				})
			}
		})
	}
}
