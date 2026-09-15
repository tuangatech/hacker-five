package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// fakeRecon is a ReconRunner test double — every test that needs a real
// PlanTree feeds it a fixed *recon.ReconResult rather than exercising real
// network probes/external binaries.
type fakeRecon struct {
	result *recon.ReconResult
	err    error
	calls  int
}

func (f *fakeRecon) Run(_ context.Context, _ string, _ recon.Depth) (*recon.ReconResult, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

// fakeLLMClient is an LLMClient test double: NextAction plays back a fixed
// script of actions/costs (the last one repeats if the loop outlasts the
// script), so a test can assert the loop's own stop/budget/iteration
// invariants without exercising a real model tier.
type fakeLLMClient struct {
	actions []llmfallback.Action
	costs   []float64
	calls   int

	triageResult llmfallback.TriageResult
	triageCost   float64
	triageErr    error
}

func (f *fakeLLMClient) NextAction(_ context.Context, _ *agenttask.PlanTree, _ []llmfallback.ToolSpec, _ []llmfallback.TurnRecord) (llmfallback.Action, float64, error) {
	i := f.calls
	if i >= len(f.actions) {
		i = len(f.actions) - 1
	}
	f.calls++
	var cost float64
	if i < len(f.costs) {
		cost = f.costs[i]
	}
	return f.actions[i], cost, nil
}

func (f *fakeLLMClient) TriageFindings(_ context.Context, _ []detectors.Finding) (llmfallback.TriageResult, float64, error) {
	return f.triageResult, f.triageCost, f.triageErr
}

// reconResultOneLiveHost is the minimal ReconResult that resolves (via
// registry.Resolve, LT-57's baseline-leaf rule) to exactly one actionable
// (StatusPending) misconfig leaf — enough to drive the loop-invariant tests
// below without depending on any tech-fact-matching heuristic.
func reconResultOneLiveHost() *recon.ReconResult {
	return &recon.ReconResult{
		Target:    "example.test",
		Endpoints: []recon.EndpointFact{{URL: "http://example.test/", StatusCode: 200, Source: "httpx"}},
	}
}

func oneActionableLeafID(t *testing.T) string {
	t.Helper()
	tree, _ := registry.Resolve(reconResultOneLiveHost(), nil)
	leaves := agenttask.Leaves(tree.Root)
	if len(leaves) != 1 {
		t.Fatalf("reconResultOneLiveHost: got %d leaves, want exactly 1 (test fixture assumption broke)", len(leaves))
	}
	return leaves[0].ID
}

func TestRun_StopAction_EndsLoopImmediately(t *testing.T) {
	client := &fakeLLMClient{actions: []llmfallback.Action{{Kind: "stop", Rationale: "nothing to do"}}}
	result, err := Run(context.Background(), Config{
		Target: "example.test",
		Recon:  &fakeRecon{result: reconResultOneLiveHost()},
		Client: client,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Iterations != 0 {
		t.Fatalf("got Iterations=%d, want 0 (a stop action is not a dispatched turn)", result.Iterations)
	}
	if len(result.History) != 0 {
		t.Fatalf("got %d history entries, want 0", len(result.History))
	}
	if client.calls != 1 {
		t.Fatalf("got %d NextAction call(s), want exactly 1", client.calls)
	}
}

func TestRun_MaxIterations_StopsAtCeiling(t *testing.T) {
	lookup := llmfallback.Action{Kind: "registry.lookup", Params: json.RawMessage(`{"query":"idor"}`)}
	client := &fakeLLMClient{actions: []llmfallback.Action{lookup}} // never returns stop
	result, err := Run(context.Background(), Config{
		Target:        "example.test",
		Recon:         &fakeRecon{result: reconResultOneLiveHost()},
		Client:        client,
		MaxIterations: 3,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Iterations != 3 {
		t.Fatalf("got Iterations=%d, want 3 (MaxIterations ceiling)", result.Iterations)
	}
	if len(result.History) != 3 {
		t.Fatalf("got %d history entries, want 3", len(result.History))
	}
}

func TestRun_Budget_StopsWhenExceeded(t *testing.T) {
	lookup := llmfallback.Action{Kind: "registry.lookup", Params: json.RawMessage(`{"query":"idor"}`)}
	client := &fakeLLMClient{
		actions: []llmfallback.Action{lookup},
		costs:   []float64{0.6}, // repeats: 0.6, 1.2, 1.8, ...
	}
	result, err := Run(context.Background(), Config{
		Target:        "example.test",
		Recon:         &fakeRecon{result: reconResultOneLiveHost()},
		Client:        client,
		Budget:        1.0,
		MaxIterations: 10, // high enough that Budget, not this, is the real constraint
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Spend check runs before each NextAction call: 0<1 (call, ->0.6),
	// 0.6<1 (call, ->1.2), 1.2>=1 stop. Two turns dispatched.
	if result.Iterations != 2 {
		t.Fatalf("got Iterations=%d, want 2", result.Iterations)
	}
	if result.SpendUSD < 1.2-1e-9 {
		t.Fatalf("got SpendUSD=%.4f, want >= 1.2", result.SpendUSD)
	}
}

// blockingRecon is a ReconRunner that hangs until its ctx is done, then
// reports ctx.Err() — a stand-in for a hung external recon tool
// (naabu/httpx/katana), found live during the Web UI's own M4 smoke test.
type blockingRecon struct{}

func (blockingRecon) Run(ctx context.Context, _ string, _ recon.Depth) (*recon.ReconResult, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// blockingAfterFirstRecon succeeds on its first call (the initial
// tree-seeding recon) and hangs on every later call (a recon.refresh
// dispatch) — isolates the recon.refresh call site's own ReconTimeout bound
// from the initial call's.
type blockingAfterFirstRecon struct {
	result *recon.ReconResult
	calls  int
}

func (r *blockingAfterFirstRecon) Run(ctx context.Context, target string, depth recon.Depth) (*recon.ReconResult, error) {
	r.calls++
	if r.calls == 1 {
		return r.result, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestRun_ReconTimeout_BoundsAHungInitialRecon confirms Config.ReconTimeout
// (not just the caller's own ctx) bounds the initial recon call — without
// it, a hung external recon tool would stall the whole run indefinitely
// short of the caller cancelling ctx itself.
func TestRun_ReconTimeout_BoundsAHungInitialRecon(t *testing.T) {
	start := time.Now()
	_, err := Run(context.Background(), Config{
		Target:       "example.test",
		Recon:        blockingRecon{},
		Client:       &fakeLLMClient{},
		ReconTimeout: 50 * time.Millisecond,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Run: want an error from a recon call that never returns, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Run took %s to fail — ReconTimeout did not bound the hung recon call", elapsed)
	}
}

// TestRun_ReconTimeout_BoundsReconRefresh confirms the same bound applies to
// a later recon.refresh dispatch, not just the initial recon call.
func TestRun_ReconTimeout_BoundsReconRefresh(t *testing.T) {
	refresh := llmfallback.Action{Kind: "recon.refresh", Params: json.RawMessage(`{"target":"example.test"}`)}
	start := time.Now()
	result, err := Run(context.Background(), Config{
		Target:        "example.test",
		Recon:         &blockingAfterFirstRecon{result: reconResultOneLiveHost()},
		Client:        &fakeLLMClient{actions: []llmfallback.Action{refresh}},
		MaxIterations: 1,
		ReconTimeout:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v (a dispatch error is reported per-turn, not as Run's own error)", err)
	}
	if result.Iterations != 1 || result.History[0].Error == "" {
		t.Fatalf("got Iterations=%d History=%+v, want one turn recording a recon.refresh error", result.Iterations, result.History)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Run took %s to finish its one turn — ReconTimeout did not bound the hung recon.refresh call", elapsed)
	}
}

func TestRun_ScriptExploreDisallowedByDefault_MarksLeafUnresolvedAndContinues(t *testing.T) {
	leafID := oneActionableLeafID(t)
	scriptAction := llmfallback.Action{
		Kind:   "script.explore",
		NodeID: leafID,
		Params: json.RawMessage(`{"language":"python","source":"print(1)"}`),
	}
	client := &fakeLLMClient{actions: []llmfallback.Action{scriptAction, {Kind: "stop"}}}

	result, err := Run(context.Background(), Config{
		Target: "example.test",
		Recon:  &fakeRecon{result: reconResultOneLiveHost()},
		Client: client,
		// AllowAgentScripts left false (default) — the point of this test.
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Iterations != 1 {
		t.Fatalf("got Iterations=%d, want 1 (the gated script.explore turn still counts as dispatched)", result.Iterations)
	}
	if len(result.History) != 1 {
		t.Fatalf("got %d history entries, want 1", len(result.History))
	}
	if result.History[0].Error != ErrScriptsDisallowed.Error() {
		t.Fatalf("got history error %q, want %q", result.History[0].Error, ErrScriptsDisallowed.Error())
	}

	leaf := result.Tree.Find(leafID)
	if leaf == nil {
		t.Fatalf("leaf %q vanished from the tree", leafID)
	}
	if leaf.Status != agenttask.StatusUnresolved {
		t.Fatalf("got leaf status %q, want %q", leaf.Status, agenttask.StatusUnresolved)
	}
	if !strings.Contains(leaf.Rationale, "allow-agent-scripts") {
		t.Fatalf("got leaf rationale %q, want it to explain the --allow-agent-scripts gate", leaf.Rationale)
	}
}

func TestHasActionableLeaves(t *testing.T) {
	pending := agenttask.StatusPending
	done := agenttask.StatusDone
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "l1", Status: done},
	}}}
	if hasActionableLeaves(tree) {
		t.Fatal("got true, want false — every leaf is StatusDone")
	}
	tree.Root.Children = append(tree.Root.Children, &agenttask.PlanNode{ID: "l2", Status: pending})
	if !hasActionableLeaves(tree) {
		t.Fatal("got false, want true — one leaf is StatusPending")
	}
}

func TestDispatch_RegistryLookup(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}}
	var findings []detectors.Finding

	summary, err := dispatch(context.Background(), Config{}, tree, &findings, llmfallback.Action{
		Kind: "registry.lookup", Params: json.RawMessage(`{"query":"idor"}`),
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !strings.Contains(summary, "idor") {
		t.Fatalf("got summary %q, want it to mention the idor capability", summary)
	}

	if _, err := dispatch(context.Background(), Config{}, tree, &findings, llmfallback.Action{Kind: "registry.lookup"}); err == nil {
		t.Fatal("want an error for a registry.lookup action with no params.query")
	}
}

func TestDispatch_ScanLeaf_Errors(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf1", Target: "http://x.test", Status: agenttask.StatusPending},
	}}}
	var findings []detectors.Finding
	cfg := Config{}

	if _, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf"}); err == nil {
		t.Fatal("want an error for scan.leaf with no node_id")
	}
	if _, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf", NodeID: "missing"}); err == nil {
		t.Fatal("want an error for scan.leaf naming an unknown node_id")
	}
	if _, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf", NodeID: "leaf1"}); err == nil {
		t.Fatal("want an error for scan.leaf on a leaf with no detector assigned yet")
	}
}

// TestDispatch_ScanLeaf_RunsThroughPlanexecAgainstRealHTTPServer proves
// scan.leaf's dispatch actually reuses pkg/planexec.RunPlan end to end
// (real scanner.Engine, real HTTP request) rather than a stub — the only
// path in this package that may ever produce a real detectors.Finding. An
// httptest server stands in for the target so this stays a fast, network-
// free-of-the-real-internet unit test.
func TestDispatch_ScanLeaf_RunsThroughPlanexecAgainstRealHTTPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>hi</html>"))
	}))
	defer srv.Close()

	leaf := &agenttask.PlanNode{ID: "leaf1", Target: srv.URL, Detector: "misconfig", Status: agenttask.StatusPending}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	var findings []detectors.Finding
	var logged []string

	cfg := Config{
		BaseScanConfig: scanner.Config{Concurrency: 1, RateLimit: 10, Timeout: 5 * time.Second},
		OnLog: func(_, msg string) {
			logged = append(logged, msg)
		},
	}

	summary, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf", NodeID: "leaf1"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !strings.Contains(summary, "finding") {
		t.Fatalf("got summary %q, want it to report a finding count", summary)
	}
	if leaf.Status != agenttask.StatusDone {
		t.Fatalf("got leaf status %q, want %q — planexec.RunPlan should have marked it done", leaf.Status, agenttask.StatusDone)
	}
	if len(logged) == 0 {
		t.Fatal("want at least one log line streamed through Config.OnLog")
	}
}

func TestDispatch_TriageRank_NoFindingsSkipsClientCall(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}}
	var findings []detectors.Finding // empty

	summary, err := dispatch(context.Background(), Config{Client: nil}, tree, &findings, llmfallback.Action{Kind: "triage.rank"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !strings.Contains(summary, "no findings") {
		t.Fatalf("got summary %q, want it to say there's nothing to triage yet", summary)
	}
}

func TestDispatch_ScriptExplore_InvalidParamsRejectedBeforeSandbox(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}}
	var findings []detectors.Finding
	cfg := Config{AllowAgentScripts: true}

	cases := []struct {
		name   string
		params json.RawMessage
	}{
		{"malformed json", json.RawMessage(`{not json`)},
		{"unsupported language", json.RawMessage(`{"language":"ruby","source":"puts 1"}`)},
		{"empty source", json.RawMessage(`{"language":"python","source":"   "}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "script.explore", Params: tc.params}); err == nil {
				t.Fatal("want an error — invalid params must never reach the sandbox")
			}
		})
	}
}

func TestDispatch_ScriptExplore_DisallowedNeverParsesParams(t *testing.T) {
	// AllowAgentScripts false: dispatch must short-circuit before even
	// looking at Params, so a malformed script still degrades cleanly
	// instead of surfacing a params-parsing error that would misattribute
	// the failure.
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf1", Target: "http://x.test", Status: agenttask.StatusPending},
	}}}
	var findings []detectors.Finding

	summary, err := dispatch(context.Background(), Config{AllowAgentScripts: false}, tree, &findings, llmfallback.Action{
		Kind: "script.explore", NodeID: "leaf1", Params: json.RawMessage(`{not json`),
	})
	if !errors.Is(err, ErrScriptsDisallowed) {
		t.Fatalf("got err=%v, want ErrScriptsDisallowed", err)
	}
	if !strings.Contains(summary, "allow-agent-scripts") {
		t.Fatalf("got summary %q, want it to mention --allow-agent-scripts", summary)
	}
}
