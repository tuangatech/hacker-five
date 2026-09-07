package unit

import (
	"context"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// TestH4_OverBudgetLeaf_EscalatesWithoutAModelCall is the D-step DoD for
// H4: a StatusUnresolved leaf that has already ground through its per-leaf
// attempt budget on prior passes is flipped to StatusEscalated by
// ResolveTreeLeaves *before* any model client is consulted — proven here
// by passing a nil fallback client, which the pre-filter never dereferences
// for the over-budget leaf. A second, fresh unresolved leaf still takes the
// normal "fallback unavailable" path, confirming the escalation is
// leaf-scoped, not a blanket short-circuit.
func TestH4_OverBudgetLeaf_EscalatesWithoutAModelCall(t *testing.T) {
	overBudget := &agenttask.PlanNode{
		ID:       "leaf-ground",
		Status:   agenttask.StatusUnresolved,
		Attempts: agenttask.MaxLeafResolveAttempts, // already at the ceiling
	}
	fresh := &agenttask.PlanNode{ID: "leaf-fresh", Status: agenttask.StatusUnresolved}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{
		ID:       "root",
		Children: []*agenttask.PlanNode{overBudget, fresh},
	}}

	notes := llmfallback.ResolveTreeLeaves(
		context.Background(),
		nil, // no fallback client — must not be called for the escalated leaf
		llmfallback.ErrNoTierAvailable,
		tree, nil, nil, nil,
	)

	if overBudget.Status != agenttask.StatusEscalated {
		t.Fatalf("over-budget leaf: got Status=%q, want %q", overBudget.Status, agenttask.StatusEscalated)
	}
	if fresh.Status != agenttask.StatusUnresolved {
		t.Fatalf("fresh leaf must be untouched, got Status=%q", fresh.Status)
	}

	var gotEscalation, gotUnavailable bool
	for _, n := range notes {
		if strings.HasPrefix(n, "leaf-ground:") && strings.Contains(n, "escalated") {
			gotEscalation = true
		}
		if strings.HasPrefix(n, "leaf-fresh:") && strings.Contains(n, "unavailable") {
			gotUnavailable = true
		}
	}
	if !gotEscalation {
		t.Fatalf("expected an escalation note for leaf-ground, got %v", notes)
	}
	if !gotUnavailable {
		t.Fatalf("expected a 'fallback unavailable' note for leaf-fresh, got %v", notes)
	}
}

// TestH4_EscalatedLeafStaysTerminalOnReResolve confirms a StatusEscalated
// leaf is never picked up again: it isn't StatusUnresolved, so a later
// ResolveTreeLeaves pass ignores it entirely.
func TestH4_EscalatedLeafStaysTerminalOnReResolve(t *testing.T) {
	leaf := &agenttask.PlanNode{ID: "leaf-1", Status: agenttask.StatusEscalated, Attempts: 5}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}

	notes := llmfallback.ResolveTreeLeaves(context.Background(), nil, llmfallback.ErrNoTierAvailable, tree, nil, nil, nil)
	if len(notes) != 0 {
		t.Fatalf("an already-escalated leaf must produce no new work, got %v", notes)
	}
	if leaf.Status != agenttask.StatusEscalated {
		t.Fatalf("status changed to %q", leaf.Status)
	}
}
