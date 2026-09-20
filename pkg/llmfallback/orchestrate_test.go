package llmfallback

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func sampleOrchestrateTree() *agenttask.PlanTree {
	pending := agenttask.StatusPending
	return &agenttask.PlanTree{
		Root: &agenttask.PlanNode{
			ID:     "root",
			Target: "example.test",
			Children: []*agenttask.PlanNode{
				{ID: "leaf-1", Target: "https://example.test/api", Detector: "idor", Status: pending},
			},
		},
	}
}

var sampleOrchestrateCatalog = []ToolSpec{
	{Kind: "scan.leaf", Description: "run one leaf's detector"},
	{Kind: "stop", Description: "stop the run"},
}

func TestNextAction_ValidResponse(t *testing.T) {
	srv := fakeChatServer(t, `{"kind":"scan.leaf","node_id":"leaf-1","rationale":"leaf is pending and dispatchable"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.NextAction(context.Background(), sampleOrchestrateTree(), sampleOrchestrateCatalog, nil)
	if err != nil {
		t.Fatalf("NextAction: %v", err)
	}
	if got.Kind != "scan.leaf" || got.NodeID != "leaf-1" {
		t.Fatalf("got %+v", got)
	}
}

func TestNextAction_MalformedResponse_DegradesToStop(t *testing.T) {
	srv := fakeChatServer(t, `not json at all`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.NextAction(context.Background(), sampleOrchestrateTree(), sampleOrchestrateCatalog, nil)
	if err != nil {
		t.Fatalf("NextAction: %v", err)
	}
	if got.Kind != "stop" || got.Rationale == "" {
		t.Fatalf("got %+v, want degraded stop with a reason", got)
	}
}

func TestNextAction_UnrecognizedKind_DegradesToStop(t *testing.T) {
	srv := fakeChatServer(t, `{"kind":"delete_everything","rationale":"why not"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.NextAction(context.Background(), sampleOrchestrateTree(), sampleOrchestrateCatalog, nil)
	if err != nil {
		t.Fatalf("NextAction: %v", err)
	}
	if got.Kind != "stop" {
		t.Fatalf("got %+v, want degraded stop", got)
	}
}

func TestNextAction_KindNotInOfferedCatalog_DegradesToStop(t *testing.T) {
	// script.explore is a real, allow-listed kind, but wasn't offered in this
	// call's catalog — the model must not be trusted to pick outside what it
	// was actually given.
	srv := fakeChatServer(t, `{"kind":"script.explore","rationale":"let's try a script"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.NextAction(context.Background(), sampleOrchestrateTree(), sampleOrchestrateCatalog, nil)
	if err != nil {
		t.Fatalf("NextAction: %v", err)
	}
	if got.Kind != "stop" {
		t.Fatalf("got %+v, want degraded stop", got)
	}
}

func TestNextAction_UnknownNodeID_DegradesToStop(t *testing.T) {
	srv := fakeChatServer(t, `{"kind":"scan.leaf","node_id":"nonexistent","rationale":"go for it"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.NextAction(context.Background(), sampleOrchestrateTree(), sampleOrchestrateCatalog, nil)
	if err != nil {
		t.Fatalf("NextAction: %v", err)
	}
	if got.Kind != "stop" {
		t.Fatalf("got %+v, want degraded stop", got)
	}
}

func TestNextAction_StopKindNeedsNoOffer(t *testing.T) {
	srv := fakeChatServer(t, `{"kind":"stop","rationale":"nothing left to do"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.NextAction(context.Background(), sampleOrchestrateTree(), nil, nil)
	if err != nil {
		t.Fatalf("NextAction: %v", err)
	}
	if got.Kind != "stop" {
		t.Fatalf("got %+v", got)
	}
}

// TestBuildOrchestratePrompt_CapsHistoryLength is LT-162's fix
// (docs/follow-up.md): a Config.MinIterations floor in pkg/orchestrator
// forces more dispatched turns than before, and this function used to render
// the full, unbounded history every call — found live growing a prompt large
// enough that a NextAction call blew past its 240s request timeout entirely.
// Only the most recent maxHistoryTurnsInPrompt entries should ever be
// rendered verbatim; older ones are summarized by count, not silently
// dropped.
func TestBuildOrchestratePrompt_CapsHistoryLength(t *testing.T) {
	history := make([]TurnRecord, maxHistoryTurnsInPrompt+3)
	for i := range history {
		history[i] = TurnRecord{
			Action:        Action{Kind: "scan.leaf", NodeID: "leaf-1"},
			ResultSummary: fmt.Sprintf("turn-%d", i),
		}
	}

	prompt := buildOrchestratePrompt(sampleOrchestrateTree(), sampleOrchestrateCatalog, history)

	if !strings.Contains(prompt, "3 earlier turn(s) omitted") {
		t.Fatalf("prompt does not note the omitted turn count:\n%s", prompt)
	}
	if strings.Contains(prompt, `result="turn-0"`) {
		t.Fatalf("prompt still contains an omitted early turn verbatim:\n%s", prompt)
	}
	if !strings.Contains(prompt, fmt.Sprintf(`result="turn-%d"`, len(history)-1)) {
		t.Fatalf("prompt is missing the most recent turn:\n%s", prompt)
	}
	got := strings.Count(prompt, "kind=scan.leaf node_id=leaf-1")
	if got != maxHistoryTurnsInPrompt {
		t.Fatalf("got %d rendered history line(s), want exactly %d", got, maxHistoryTurnsInPrompt)
	}
}

func TestBuildOrchestratePrompt_ShortHistoryNotTruncated(t *testing.T) {
	history := []TurnRecord{
		{Action: Action{Kind: "scan.leaf", NodeID: "leaf-1"}, ResultSummary: "1 finding(s)"},
	}
	prompt := buildOrchestratePrompt(sampleOrchestrateTree(), sampleOrchestrateCatalog, history)
	if strings.Contains(prompt, "omitted") {
		t.Fatalf("short history should never be reported as truncated:\n%s", prompt)
	}
}

func leavesWithStatus(n int, status agenttask.PlanNodeStatus, prefix string) []*agenttask.PlanNode {
	out := make([]*agenttask.PlanNode, n)
	for i := range out {
		out[i] = &agenttask.PlanNode{ID: fmt.Sprintf("%s-%d", prefix, i), Status: status}
	}
	return out
}

func TestBoundedLeavesForPrompt_UnderCap_ReturnsAllUnomitted(t *testing.T) {
	leaves := leavesWithStatus(5, agenttask.StatusPending, "leaf")
	shown, omitted := boundedLeavesForPrompt(leaves)
	if omitted != 0 || len(shown) != 5 {
		t.Fatalf("got shown=%d omitted=%d, want 5/0 (under the cap)", len(shown), omitted)
	}
}

// TestBoundedLeavesForPrompt_OverCap_KeepsActionableDropsSettledFirst is
// LT-165's fix (docs/follow-up.md): every actionable (pending/unresolved)
// leaf must survive the cap since those are the only ones a node_id could
// usefully target this turn; an already-settled leaf (done here) is dropped
// first.
func TestBoundedLeavesForPrompt_OverCap_KeepsActionableDropsSettledFirst(t *testing.T) {
	actionable := leavesWithStatus(10, agenttask.StatusPending, "pending")
	settled := leavesWithStatus(maxLeafNodesInPrompt, agenttask.StatusDone, "done")
	leaves := append(append([]*agenttask.PlanNode{}, actionable...), settled...)

	shown, omitted := boundedLeavesForPrompt(leaves)
	if len(shown) != maxLeafNodesInPrompt {
		t.Fatalf("got %d shown, want exactly the cap (%d)", len(shown), maxLeafNodesInPrompt)
	}
	if omitted != len(leaves)-maxLeafNodesInPrompt {
		t.Fatalf("got omitted=%d, want %d", omitted, len(leaves)-maxLeafNodesInPrompt)
	}
	shownIDs := make(map[string]bool, len(shown))
	for _, l := range shown {
		shownIDs[l.ID] = true
	}
	for _, l := range actionable {
		if !shownIDs[l.ID] {
			t.Fatalf("actionable leaf %q was dropped — every actionable leaf must survive the cap", l.ID)
		}
	}
}

// TestBoundedLeavesForPrompt_ActionableAloneExceedsCap covers the edge case
// where even the actionable set is larger than the cap — it gets truncated
// too rather than growing the prompt further, since NextAction only ever
// needs one node_id per turn and an omitted actionable leaf stays visible on
// a later call.
func TestBoundedLeavesForPrompt_ActionableAloneExceedsCap(t *testing.T) {
	leaves := leavesWithStatus(maxLeafNodesInPrompt+20, agenttask.StatusPending, "pending")
	shown, omitted := boundedLeavesForPrompt(leaves)
	if len(shown) != maxLeafNodesInPrompt {
		t.Fatalf("got %d shown, want exactly the cap (%d)", len(shown), maxLeafNodesInPrompt)
	}
	if omitted != 20 {
		t.Fatalf("got omitted=%d, want 20", omitted)
	}
}

// TestBuildOrchestratePrompt_CapsLeafListAndNotesOmission is the end-to-end
// version of the boundedLeavesForPrompt unit tests above, through the real
// prompt builder.
func TestBuildOrchestratePrompt_CapsLeafListAndNotesOmission(t *testing.T) {
	leaves := leavesWithStatus(maxLeafNodesInPrompt+15, agenttask.StatusDone, "done")
	leaves = append(leaves, &agenttask.PlanNode{ID: "the-one-pending-leaf", Target: "https://example.test", Detector: "idor", Status: agenttask.StatusPending})
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: leaves}}

	prompt := buildOrchestratePrompt(tree, sampleOrchestrateCatalog, nil)

	if !strings.Contains(prompt, "leaf/leaves omitted for space") {
		t.Fatalf("prompt does not note the omitted leaf count:\n%s", prompt)
	}
	if !strings.Contains(prompt, "id=the-one-pending-leaf") {
		t.Fatalf("prompt is missing the one actionable leaf — it must never be dropped by the cap:\n%s", prompt)
	}
}
