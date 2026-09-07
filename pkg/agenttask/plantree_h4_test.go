package agenttask

import "testing"

func leafTree(leaf *PlanNode) *PlanTree {
	return &PlanTree{Root: &PlanNode{ID: "root", Children: []*PlanNode{leaf}}}
}

func TestPlanNode_ShouldEscalate(t *testing.T) {
	cases := []struct {
		name string
		node PlanNode
		want bool
	}{
		{"fresh leaf", PlanNode{ID: "l"}, false},
		{"one attempt, cheap", PlanNode{ID: "l", Attempts: 1, SpendUSD: 0.001}, false},
		{"attempt ceiling reached", PlanNode{ID: "l", Attempts: MaxLeafResolveAttempts}, true},
		{"attempt ceiling exceeded", PlanNode{ID: "l", Attempts: MaxLeafResolveAttempts + 2}, true},
		{"spend ceiling reached", PlanNode{ID: "l", Attempts: 1, SpendUSD: MaxLeafResolveSpendUSD}, true},
		{"non-leaf never escalates", PlanNode{ID: "n", Attempts: 99, Children: []*PlanNode{{ID: "c"}}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.node.ShouldEscalate(); got != c.want {
				t.Fatalf("ShouldEscalate() = %v, want %v", got, c.want)
			}
		})
	}
	var nilNode *PlanNode
	if nilNode.ShouldEscalate() {
		t.Fatal("nil node must not escalate")
	}
}

func TestPlanTree_RecordLeafAttempt(t *testing.T) {
	leaf := &PlanNode{ID: "leaf-1", Status: StatusUnresolved}
	tree := leafTree(leaf)

	exhausted, err := tree.RecordLeafAttempt("leaf-1", 0.02)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exhausted {
		t.Fatal("one 2c attempt must not exhaust the budget")
	}
	if leaf.Attempts != 1 || leaf.SpendUSD != 0.02 {
		t.Fatalf("got Attempts=%d SpendUSD=%v, want 1 / 0.02", leaf.Attempts, leaf.SpendUSD)
	}

	// A second attempt that pushes cumulative spend over the ceiling.
	exhausted, _ = tree.RecordLeafAttempt("leaf-1", 0.04)
	if !exhausted {
		t.Fatalf("cumulative $0.06 spend must exhaust the $%.2f ceiling", MaxLeafResolveSpendUSD)
	}
	// RecordLeafAttempt reports the state but does not itself change Status.
	if leaf.Status != StatusUnresolved {
		t.Fatalf("RecordLeafAttempt must not mutate Status, got %q", leaf.Status)
	}

	if _, err := tree.RecordLeafAttempt("missing", 0); err != ErrNodeNotFound {
		t.Fatalf("got %v, want ErrNodeNotFound", err)
	}
	if _, err := tree.RecordLeafAttempt("root", 0); err != ErrNotLeaf {
		t.Fatalf("got %v, want ErrNotLeaf", err)
	}
}

func TestPlanTree_ApplyLeafUpdate_H4Fields(t *testing.T) {
	leaf := &PlanNode{ID: "leaf-1", Status: StatusUnresolved}
	tree := leafTree(leaf)

	att, spend := 2, 0.03
	if err := tree.ApplyLeafUpdate("leaf-1", PlanNodePatch{Attempts: &att, SpendUSD: &spend}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if leaf.Attempts != 2 || leaf.SpendUSD != 0.03 {
		t.Fatalf("patch did not assign H4 fields: Attempts=%d SpendUSD=%v", leaf.Attempts, leaf.SpendUSD)
	}
}
