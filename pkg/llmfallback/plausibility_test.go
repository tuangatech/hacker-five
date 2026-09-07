package llmfallback

import (
	"context"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func pendingLeaf(id string, conf agenttask.Confidence) *agenttask.PlanNode {
	return &agenttask.PlanNode{
		ID: id, Target: "http://h.test", Detector: "misconfig",
		Status: agenttask.StatusPending, Confidence: conf,
		Rationale: `tech fact "X" (source: httpx) matched registry capability "misconfig"`,
	}
}

// TestVetPendingLeaves_ParsesVerdicts: a well-formed verdict set round-trips.
func TestVetPendingLeaves_ParsesVerdicts(t *testing.T) {
	srv := fakeChatServer(t, `{"verdicts":[
		{"id":"l1","action":"keep","reason":"sound"},
		{"id":"l2","action":"demote","reason":"weak signal fanned out"},
		{"id":"l3","action":"drop","reason":"SPA catch-all, fabricated route"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	res, _, err := c.VetPendingLeaves(context.Background(), []*agenttask.PlanNode{
		pendingLeaf("l1", agenttask.ConfidenceHigh),
		pendingLeaf("l2", agenttask.ConfidenceHigh),
		pendingLeaf("l3", agenttask.ConfidenceMedium),
	})
	if err != nil {
		t.Fatalf("VetPendingLeaves: %v", err)
	}
	if len(res.Verdicts) != 3 {
		t.Fatalf("got %d verdicts, want 3", len(res.Verdicts))
	}
}

// TestVetPendingLeaves_RejectsUnknownLeafID: a verdict naming a leaf that
// wasn't in the input is caught in code, not trusted.
func TestVetPendingLeaves_RejectsUnknownLeafID(t *testing.T) {
	srv := fakeChatServer(t, `{"verdicts":[
		{"id":"l1","action":"keep","reason":"ok"},
		{"id":"ghost","action":"drop","reason":"made up"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	res, _, err := c.VetPendingLeaves(context.Background(), []*agenttask.PlanNode{pendingLeaf("l1", agenttask.ConfidenceHigh)})
	if err != nil {
		t.Fatalf("VetPendingLeaves returned a hard error, want a soft escalation: %v", err)
	}
	if res.EscalateToHuman == "" {
		t.Fatal("an invalid verdict set must degrade to EscalateToHuman, not silently apply")
	}
	if len(res.Verdicts) != 0 {
		t.Fatal("no verdicts should be returned when the set is invalid")
	}
}

// TestVetPendingLeaves_MissingLeafRejected: every input leaf must be covered.
func TestVetPendingLeaves_MissingLeafRejected(t *testing.T) {
	srv := fakeChatServer(t, `{"verdicts":[{"id":"l1","action":"keep","reason":"ok"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	res, _, _ := c.VetPendingLeaves(context.Background(), []*agenttask.PlanNode{
		pendingLeaf("l1", agenttask.ConfidenceHigh),
		pendingLeaf("l2", agenttask.ConfidenceHigh),
	})
	if res.EscalateToHuman == "" {
		t.Fatal("a verdict set that skips a leaf must degrade to EscalateToHuman")
	}
}

// TestVetoImplausibleLeaves_AppliesVerdicts: demote lowers a band + prefixes
// the rationale; drop flips to StatusVetoed; keep is untouched.
func TestVetoImplausibleLeaves_AppliesVerdicts(t *testing.T) {
	srv := fakeChatServer(t, `{"verdicts":[
		{"id":"keep-leaf","action":"keep","reason":"sound"},
		{"id":"demote-leaf","action":"demote","reason":"one weak signal"},
		{"id":"drop-leaf","action":"drop","reason":"fabricated APISpec"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		pendingLeaf("keep-leaf", agenttask.ConfidenceHigh),
		pendingLeaf("demote-leaf", agenttask.ConfidenceHigh),
		pendingLeaf("drop-leaf", agenttask.ConfidenceHigh),
	}}}

	notes := VetoImplausibleLeaves(context.Background(), c, nil, tree)
	if len(notes) != 2 {
		t.Fatalf("want one note per demoted/dropped leaf (2), got %d: %v", len(notes), notes)
	}
	if got := tree.Find("keep-leaf"); got.Status != agenttask.StatusPending || got.Confidence != agenttask.ConfidenceHigh {
		t.Fatalf("keep leaf must be untouched, got status=%q conf=%q", got.Status, got.Confidence)
	}
	if got := tree.Find("demote-leaf"); got.Confidence != agenttask.ConfidenceMedium {
		t.Fatalf("demote leaf confidence = %q, want medium", got.Confidence)
	}
	if got := tree.Find("drop-leaf"); got.Status != agenttask.StatusVetoed {
		t.Fatalf("drop leaf status = %q, want vetoed", got.Status)
	}
}

// TestVetoImplausibleLeaves_NilClientIsSafe: no tier configured -> a single
// advisory note, tree untouched, never a panic or hard error.
func TestVetoImplausibleLeaves_NilClientIsSafe(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		pendingLeaf("l1", agenttask.ConfidenceHigh),
	}}}
	notes := VetoImplausibleLeaves(context.Background(), nil, ErrNoTierAvailable, tree)
	if len(notes) != 1 {
		t.Fatalf("want a single 'skipped' note, got %v", notes)
	}
	if tree.Find("l1").Status != agenttask.StatusPending {
		t.Fatal("a nil-client veto pass must not mutate the tree")
	}
}

// TestVetoImplausibleLeaves_NoPendingLeaves_NoCall: nothing pending -> no
// call, no note.
func TestVetoImplausibleLeaves_NoPendingLeaves_NoCall(t *testing.T) {
	srv := fakeChatServer(t, `{"verdicts":[]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "u1", Status: agenttask.StatusUnresolved},
		{ID: "d1", Status: agenttask.StatusDone},
	}}}
	if notes := VetoImplausibleLeaves(context.Background(), c, nil, tree); notes != nil {
		t.Fatalf("want nil (nothing to review), got %v", notes)
	}
}

// TestVetoImplausibleLeaves_RespectsSpendCeiling: ceiling already reached ->
// skipped without a call.
func TestVetoImplausibleLeaves_RespectsSpendCeiling(t *testing.T) {
	srv := fakeChatServer(t, `{"verdicts":[{"id":"l1","action":"drop","reason":"x"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		pendingLeaf("l1", agenttask.ConfidenceHigh),
	}}, SpendCeilingUSD: 1.0}
	tree.AddSpend(1.0) // at the ceiling

	notes := VetoImplausibleLeaves(context.Background(), c, nil, tree)
	if len(notes) != 1 {
		t.Fatalf("want a single 'ceiling reached' note, got %v", notes)
	}
	if tree.Find("l1").Status != agenttask.StatusPending {
		t.Fatal("no verdict should have been applied once the ceiling was reached")
	}
}
