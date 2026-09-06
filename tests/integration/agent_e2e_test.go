//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/mcpserver"
)

// TestAgentRoundTrip_MCPClient is doc15 Phase 6 Step 5's automated
// recon -> plan -> approve -> scan -> findings.export round trip, driven by
// a real in-memory MCP client against the real mcpserver.New() tool set, and
// closed out by asserting the session log (C1) captured every call in order.
//
// Two modes:
//
//   - default: a local httptest server standing in for a vulnerable target.
//     No recon toolchain is needed (this environment has none), so plan's own
//     internally-run recon is thin and its executed tree small — this mode
//     verifies the round-trip *mechanism* end to end (elicitation approval,
//     execution, export, session logging), not a rich plan.
//
//   - HACKERFIVE_E2E_TARGET set: the same flow against that URL, additionally
//     asserting plan produced a non-trivial tree. Set HACKERFIVE_E2E_EXPECT_NO_FALLBACK=1
//     for a target expected to resolve entirely deterministically (WebGoat /
//     bWAPP, doc15 Step 5) — the run must report zero LLM-fallback spend.
func TestAgentRoundTrip_MCPClient(t *testing.T) {
	target, scope, cleanup := e2eTarget(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	session := connectAgentClient(ctx, t)
	defer func() { _ = session.Close() }()

	// 1. recon
	reconRes := callTool(ctx, t, session, "recon", map[string]any{
		"target": target, "scope": scope, "depth": "passive",
		"reason": "map the target's surface before planning",
	})
	require.False(t, reconRes.IsError, "recon: %s", firstText(t, reconRes))

	// 2. plan -> elicitation auto-approved -> execution
	planRes := callTool(ctx, t, session, "plan", map[string]any{
		"target": target, "scope": scope, "depth": "passive",
		"reason": "resolve the target to a plan and run it",
	})
	require.False(t, planRes.IsError, "plan: %s", firstText(t, planRes))

	var plan struct {
		Approved      bool  `json:"approved"`
		SpendUSD      float64 `json:"spend_usd"`
		Findings      []map[string]any `json:"findings"`
		Tree          json.RawMessage  `json:"tree"`
		SkippedLeaves []string         `json:"skipped_leaves"`
	}
	require.NoError(t, json.Unmarshal([]byte(firstText(t, planRes)), &plan))
	assert.True(t, plan.Approved, "plan must come back approved after the auto-accepted elicitation")

	if _, live := os.LookupEnv("HACKERFIVE_E2E_TARGET"); live {
		assert.NotEmpty(t, plan.Tree, "a live target should resolve to a non-empty plan tree")
		if _, noFallback := os.LookupEnv("HACKERFIVE_E2E_EXPECT_NO_FALLBACK"); noFallback {
			assert.Zero(t, plan.SpendUSD, "an all-deterministic plan must make zero LLM-fallback calls")
		}
	}

	// 3. scan — an explicit detector run against the same target. In the
	// default (no-recon-toolchain) mode this is where real findings come
	// from; with a live target plan's own executor already produced some.
	// tags is set to a tag no template carries, so the run is the native
	// misconfig detector only — a synced template corpus (thousands of
	// files) would otherwise make this step a multi-minute scan, not a
	// round-trip smoke check.
	scanRes := callTool(ctx, t, session, "scan", map[string]any{
		"targets": []string{target}, "scope": scope, "detector": "misconfig",
		"tags":   []string{"hackerfive-e2e-native-only"},
		"reason": "confirm the exposed-config findings directly",
	})
	require.False(t, scanRes.IsError, "scan: %s", firstText(t, scanRes))

	var scan struct {
		Findings []map[string]any `json:"findings"`
	}
	require.NoError(t, json.Unmarshal([]byte(firstText(t, scanRes)), &scan))

	findings := scan.Findings
	if len(findings) == 0 {
		findings = plan.Findings
	}

	// 4. findings.export
	exportRes := callTool(ctx, t, session, "findings.export", map[string]any{
		"findings": findings, "format": "markdown",
		"reason": "draft the writeup",
	})
	require.False(t, exportRes.IsError, "findings.export: %s", firstText(t, exportRes))
	var export struct {
		Content string `json:"content"`
	}
	require.NoError(t, json.Unmarshal([]byte(firstText(t, exportRes)), &export))
	assert.NotEmpty(t, export.Content, "export must render something")

	// 5. session.log (C1) — the whole sequence, in order, with reasons.
	logRes := callTool(ctx, t, session, "session.log", nil)
	require.False(t, logRes.IsError, "session.log: %s", firstText(t, logRes))

	var log struct {
		Entries []struct {
			Seq    int64  `json:"seq"`
			Tool   string `json:"tool"`
			Reason string `json:"reason"`
			Result string `json:"result"`
			Error  string `json:"error"`
		} `json:"entries"`
		Total int `json:"total"`
	}
	require.NoError(t, json.Unmarshal([]byte(firstText(t, logRes)), &log))

	var gotTools []string
	for _, e := range log.Entries {
		gotTools = append(gotTools, e.Tool)
		assert.NotEmpty(t, e.Reason, "every recorded call carried a reason; %s did not", e.Tool)
		assert.Empty(t, e.Error, "%s recorded an error: %s", e.Tool, e.Error)
	}
	// plan records two entries (round 1 proposal + round 2 approval).
	assert.Equal(t, []string{
		"recon", "plan", "plan", "scan", "findings.export",
	}, gotTools, "session log must hold every action call in call order")
	assert.GreaterOrEqual(t, log.Total, 5)

	seqs := make([]int64, len(log.Entries))
	for i, e := range log.Entries {
		seqs[i] = e.Seq
	}
	for i := 1; i < len(seqs); i++ {
		assert.Greater(t, seqs[i], seqs[i-1], "seq must be strictly increasing in call order")
	}
}

// e2eTarget returns (target, scope, cleanup): HACKERFIVE_E2E_TARGET when set,
// otherwise a local httptest server that serves reliably misconfig-detectable
// responses (an exposed .git/config and .env, no security headers).
func e2eTarget(t *testing.T) (string, []string, func()) {
	t.Helper()
	if v, ok := os.LookupEnv("HACKERFIVE_E2E_TARGET"); ok {
		scope := []string{hostOf(t, v)}
		if s, ok := os.LookupEnv("HACKERFIVE_E2E_SCOPE"); ok {
			scope = strings.Split(s, ",")
		}
		return v, scope, func() {}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.git/config":
			fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
		case "/.env":
			fmt.Fprint(w, "DB_PASSWORD=hunter2\nAPP_KEY=base64:AAAA\nSECRET=xyzzy\n")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv.URL, []string{"127.0.0.1"}, srv.Close
}

func connectAgentClient(ctx context.Context, t *testing.T) *mcp.ClientSession {
	t.Helper()
	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := mcpserver.New().Connect(ctx, t1, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "agent-e2e", Version: "v0"}, &mcp.ClientOptions{
		// Auto-approve every elicitation — the human-in-the-loop step, stubbed
		// for the automated round trip (the live browser/MCP-host approval is
		// verified separately, doc15 Step 4/5). Both fields are always sent;
		// acknowledge_out_of_scope is simply ignored when the schema (B4,
		// doc15 Step 3) didn't ask for it.
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

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		t.Fatalf("HACKERFIVE_E2E_TARGET %q is not a URL with a host; set HACKERFIVE_E2E_SCOPE explicitly", raw)
	}
	return u.Hostname()
}
