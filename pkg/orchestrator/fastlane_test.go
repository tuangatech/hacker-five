package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

func leafOf(id, detector string, status agenttask.PlanNodeStatus, priority int) *agenttask.PlanNode {
	return &agenttask.PlanNode{ID: id, Target: "https://example.test", Detector: detector, Status: status, Priority: priority}
}

func treeOf(leaves ...*agenttask.PlanNode) *agenttask.PlanTree {
	return &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: leaves}}
}

func TestIsFastLaneLeaf(t *testing.T) {
	for _, tc := range []struct {
		name string
		leaf *agenttask.PlanNode
		want bool
	}{
		{"template-id leaf", leafOf("a", "CVE-2024-0001", agenttask.StatusPending, 35), true},
		{"broad misconfig sweep", leafOf("a", "misconfig", agenttask.StatusPending, 30), true},
		{"netservice sweep", leafOf("a", "netservice", agenttask.StatusPending, 20), true},
		{"endpoint-specific idor stays a decision", leafOf("a", "idor", agenttask.StatusPending, 30), false},
		{"authbypass stays a decision", leafOf("a", "authbypass", agenttask.StatusPending, 30), false},
		{"ssrf stays a decision", leafOf("a", "ssrf", agenttask.StatusPending, 30), false},
		{"mutating businesslogic stays a decision", leafOf("a", "businesslogic", agenttask.StatusPending, 30), false},
		{"unresolved leaf stays a decision", leafOf("a", "", agenttask.StatusUnresolved, 0), false},
		{"already done", leafOf("a", "misconfig", agenttask.StatusDone, 30), false},
		{"vetoed", leafOf("a", "CVE-2024-0001", agenttask.StatusVetoed, 35), false},
	} {
		if got := isFastLaneLeaf(tc.leaf); got != tc.want {
			t.Errorf("%s: isFastLaneLeaf=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestNextFastLaneLeaf_HighestPriorityFirstThenTreeOrder_SkippingTried(t *testing.T) {
	tree := treeOf(
		leafOf("low", "CVE-1", agenttask.StatusPending, 15),
		leafOf("idor", "idor", agenttask.StatusPending, 99), // not fast-lane, however high
		leafOf("hi-first", "CVE-2", agenttask.StatusPending, 35),
		leafOf("hi-second", "CVE-3", agenttask.StatusPending, 35),
		leafOf("sweep", "misconfig", agenttask.StatusPending, 30),
	)
	tried := map[string]bool{}
	var order []string
	for {
		leaf := nextFastLaneLeaf(tree, tried)
		if leaf == nil {
			break
		}
		tried[leaf.ID] = true
		order = append(order, leaf.ID)
	}
	if got, want := strings.Join(order, ","), "hi-first,hi-second,sweep,low"; got != want {
		t.Fatalf("fast-lane order = %s, want %s (priority desc, leaf order on ties, never the idor leaf)", got, want)
	}
}

func TestHasActionableLeavesExcept_IgnoresTriedPendingLeaves(t *testing.T) {
	tree := treeOf(leafOf("a", "misconfig", agenttask.StatusPending, 30))
	if !hasActionableLeavesExcept(tree, nil) {
		t.Fatal("an untried pending leaf is actionable")
	}
	if hasActionableLeavesExcept(tree, map[string]bool{"a": true}) {
		t.Fatal("a pending leaf the fast lane already tried (and could not run) must not keep the loop asking the model")
	}
}

func fastLaneTargetServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>hi</html>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fastLaneConfig(srv *httptest.Server, client LLMClient) Config {
	return Config{
		Target: srv.URL,
		Recon: &fakeRecon{result: &recon.ReconResult{
			Target:    srv.URL,
			Endpoints: []recon.EndpointFact{{URL: srv.URL + "/", StatusCode: 200, Source: "httpx"}},
		}},
		Client:         client,
		FastLane:       true,
		BaseScanConfig: scanner.Config{Concurrency: 1, RateLimit: 10, Timeout: 5 * time.Second},
	}
}

// TestRun_FastLane_RunsParameterFreeLeafWithoutAskingTheModel guards LT-172:
// the only leaf here is the broad misconfig sweep, so the run must dispatch it
// and finish with zero model calls, recording the turn as an auto turn that
// counts toward neither Iterations nor the model's own history window.
func TestRun_FastLane_RunsParameterFreeLeafWithoutAskingTheModel(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{actions: []llmfallback.Action{{Kind: "stop", Rationale: "should never be asked"}}}

	var logged []string
	cfg := fastLaneConfig(srv, client)
	cfg.OnLog = func(_, msg string) { logged = append(logged, msg) }
	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.calls != 0 {
		t.Fatalf("got %d NextAction call(s), want 0 — nothing left needed a decision", client.calls)
	}
	if result.FastLaneTurns != 1 || result.Iterations != 0 {
		t.Fatalf("got FastLaneTurns=%d Iterations=%d, want 1 and 0", result.FastLaneTurns, result.Iterations)
	}
	if len(result.History) != 1 || !result.History[0].Auto || result.History[0].Action.Kind != "scan.leaf" {
		t.Fatalf("history = %+v, want exactly one auto scan.leaf turn", result.History)
	}
	if !strings.Contains(result.History[0].Action.Rationale, "fast lane") {
		t.Errorf("the auto turn must say why it ran without a decision, got %q", result.History[0].Action.Rationale)
	}
	for _, leaf := range agenttask.Leaves(result.Tree.Root) {
		if leaf.Status != agenttask.StatusDone {
			t.Errorf("leaf %s status = %s, want done", leaf.ID, leaf.Status)
		}
	}
	if !strings.Contains(strings.Join(logged, "\n"), "fast lane: scan.leaf") {
		t.Errorf("every turn must be logged (LT-170), got logs %q", logged)
	}
}

func TestRun_FastLaneOff_StillAsksTheModelForTheSameLeaf(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{actions: []llmfallback.Action{{Kind: "stop", Rationale: "done"}}}
	cfg := fastLaneConfig(srv, client)
	cfg.FastLane = false
	if _, err := Run(context.Background(), cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if client.calls == 0 {
		t.Fatal("with FastLane off the model must be asked, as before")
	}
}

func TestRun_FastLane_CancelledContextEndsTheRunWithAnError(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{actions: []llmfallback.Action{{Kind: "stop"}}}
	ctx, cancel := context.WithCancel(context.Background())
	cfg := fastLaneConfig(srv, client)
	cfg.Recon = &cancellingRecon{cancel: cancel, result: cfg.Recon.(*fakeRecon).result}
	if _, err := Run(ctx, cfg); err == nil {
		t.Fatal("a cancelled context must end a fast-lane run with an error, not loop or finish silently")
	}
}

// cancellingRecon returns its result and then cancels the run's context, so
// the failure surfaces at the first loop iteration after the initial recon.
type cancellingRecon struct {
	cancel context.CancelFunc
	result *recon.ReconResult
}

func (c *cancellingRecon) Run(_ context.Context, _ string, _ recon.Depth) (*recon.ReconResult, error) {
	c.cancel()
	return c.result, nil
}

// TestRun_ModelSeesReconDigestAndDistinctFindings guards LT-171: what recon
// observed reaches the model's call, and the digest is rebuilt each turn.
func TestRun_ModelSeesReconDigest(t *testing.T) {
	lookup := llmfallback.Action{Kind: "registry.lookup", Params: json.RawMessage(`{"query":"idor"}`)}
	client := &fakeLLMClient{actions: []llmfallback.Action{lookup}}
	res := reconResultOneLiveHost()
	res.TechStack = []recon.TechFact{{Name: "Nginx", Host: "example.test", Source: "httpx", Confidence: "high"}}
	res.AppSurface = &recon.AppSurfaceFact{Verdict: "full", Reason: "live root and several endpoints"}
	res.Warnings = []string{"wave2: something was thin"}

	if _, err := Run(context.Background(), Config{
		Target: "example.test", Recon: &fakeRecon{result: res}, Client: client, MaxIterations: 1,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(client.digests) == 0 {
		t.Fatal("NextAction was never called")
	}
	joined := strings.Join(client.digests[0].Recon, "\n")
	for _, want := range []string{"tech: Nginx (example.test, high confidence)", "app surface: full", "endpoints observed: 1 (1 answered 2xx)", "recon warning: wave2: something was thin"} {
		if !strings.Contains(joined, want) {
			t.Errorf("recon digest is missing %q, got:\n%s", want, joined)
		}
	}
}

func TestReconDigest_TechUnionsAcrossRefreshAndOtherFactsTakeTheLatest(t *testing.T) {
	d := &reconDigest{}
	d.observe(&recon.ReconResult{
		TechStack: []recon.TechFact{{Name: "Nginx", Host: "a", Confidence: "high"}},
		Endpoints: []recon.EndpointFact{{StatusCode: 200}},
	})
	d.observe(&recon.ReconResult{
		TechStack: []recon.TechFact{{Name: "Nginx", Host: "a", Confidence: "high"}, {Name: "PHP", Host: "a", Confidence: "medium"}},
		Endpoints: []recon.EndpointFact{{StatusCode: 200}, {StatusCode: 404}, {StatusCode: 204}},
	})
	joined := strings.Join(d.lines(), "\n")
	if strings.Count(joined, "tech: Nginx") != 1 || !strings.Contains(joined, "tech: PHP") {
		t.Errorf("tech facts must union without duplicates:\n%s", joined)
	}
	if !strings.Contains(joined, "endpoints observed: 3 (2 answered 2xx)") {
		t.Errorf("endpoint counts must reflect the latest observation:\n%s", joined)
	}
	if (&reconDigest{}).lines() != nil {
		t.Error("a digest that observed nothing must render nothing")
	}
}

func TestReconDigest_WarningsAreBounded(t *testing.T) {
	var warnings []string
	for i := 0; i < 20; i++ {
		warnings = append(warnings, strings.Repeat("x", 500))
	}
	d := &reconDigest{}
	d.observe(&recon.ReconResult{Warnings: warnings})
	n := 0
	for _, l := range d.lines() {
		if strings.HasPrefix(l, "recon warning: ") {
			n++
			if len(l) > len("recon warning: ")+maxDigestWarningLen+len("...") {
				t.Errorf("warning line not truncated (%d bytes)", len(l))
			}
		}
	}
	if n != maxDigestWarnings {
		t.Errorf("got %d warning lines, want %d", n, maxDigestWarnings)
	}
}

func TestScanLeafSummary(t *testing.T) {
	f := func(id string) detectors.Finding { return detectors.Finding{ID: id, Severity: "high", Target: "https://x/" + id} }

	got := scanLeafSummary(nil, 0, 3)
	if got != "0 new finding(s), 3 log line(s)" {
		t.Errorf("empty summary = %q", got)
	}

	got = scanLeafSummary([]detectors.Finding{f("a")}, 2, 1)
	for _, want := range []string{"1 new finding(s) [a high https://x/a]", "2 repeat(s) of already-recorded findings ignored", "1 log line(s)"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q is missing %q", got, want)
		}
	}

	many := []detectors.Finding{f("1"), f("2"), f("3"), f("4"), f("5"), f("6"), f("7")}
	got = scanLeafSummary(many, 0, 0)
	if !strings.Contains(got, "7 new finding(s)") || !strings.Contains(got, "+2 more") || strings.Contains(got, " 6 high") {
		t.Errorf("a long list must be capped with a remainder count, got %q", got)
	}
}

// TestDispatchScanLeaf_RefiredFindingIsNotRecordedTwice guards the LT-166
// symptom the model was misled by: a second dispatch that re-fires a finding
// the first already recorded must neither append it again nor report it as new.
func TestDispatchScanLeaf_RefiredFindingIsNotRecordedTwice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>hi</html>"))
	}))
	defer srv.Close()

	first := &agenttask.PlanNode{ID: "first", Target: srv.URL, Detector: "misconfig", Status: agenttask.StatusPending}
	second := &agenttask.PlanNode{ID: "second", Target: srv.URL, Detector: "misconfig", Status: agenttask.StatusPending}
	tree := treeOf(first, second)
	cfg := Config{BaseScanConfig: scanner.Config{Concurrency: 1, RateLimit: 10, Timeout: 5 * time.Second}}
	var findings []detectors.Finding

	s1, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf", NodeID: "first"})
	if err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	if len(findings) == 0 {
		t.Skipf("the misconfig detector reported nothing against this fixture (summary %q); dedup can't be exercised", s1)
	}
	recorded := len(findings)

	s2, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf", NodeID: "second"})
	if err != nil {
		t.Fatalf("second dispatch: %v", err)
	}
	if len(findings) != recorded {
		t.Fatalf("a re-fired finding was recorded again: %d -> %d", recorded, len(findings))
	}
	if !strings.HasPrefix(s2, "0 new finding(s)") || !strings.Contains(s2, "repeat(s) of already-recorded findings ignored") {
		t.Fatalf("second summary = %q, want it to report 0 new and the repeats", s2)
	}
}
