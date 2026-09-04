package llmfallback

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func TestApplyLeafDecision_UseExistingTag(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf-1", Status: agenttask.StatusUnresolved},
	}}}
	var escalations []string
	addEscalation := func(format string, args ...any) { escalations = append(escalations, format) }

	applyLeafDecision(tree, tree.Find("leaf-1"), LeafDecision{UseExistingTag: "misconfig"}, addEscalation)

	leaf := tree.Find("leaf-1")
	if leaf.Detector != "misconfig" {
		t.Fatalf("got Detector=%q, want misconfig", leaf.Detector)
	}
	if leaf.Status != agenttask.StatusPending {
		t.Fatalf("got Status=%q, want pending", leaf.Status)
	}
	if len(escalations) != 0 {
		t.Fatalf("expected no escalation for a clean use_existing_tag resolution, got %v", escalations)
	}
}

func TestApplyLeafDecision_Escalate(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf-1", Status: agenttask.StatusUnresolved},
	}}}
	var escalations []string
	addEscalation := func(format string, args ...any) { escalations = append(escalations, format) }

	applyLeafDecision(tree, tree.Find("leaf-1"), LeafDecision{EscalateToHuman: "not confident"}, addEscalation)

	if tree.Find("leaf-1").Detector != "" {
		t.Fatal("an escalated leaf must not gain a Detector")
	}
	if len(escalations) != 1 {
		t.Fatalf("expected exactly one escalation, got %v", escalations)
	}
}

func TestWriteProposedTemplate_RejectsDisallowedBlock(t *testing.T) {
	t.Chdir(t.TempDir()) // writeProposedTemplate uses a relative path

	_, err := writeProposedTemplate("leaf-x", "id: bad\njavascript:\n  - code: \"1\"\n")
	if err == nil {
		t.Fatal("expected the disallowed javascript: block to be rejected")
	}
	if _, statErr := os.Stat(filepath.Join(proposedTemplatesDir, "leaf-x.yaml")); !os.IsNotExist(statErr) {
		t.Fatal("a rejected draft must not be left on disk")
	}
}

// TestResolveTreeLeaves_NilClientEscalatesEveryUnresolvedLeaf confirms
// ResolveTreeLeaves absorbs the fb == nil case itself (e.g. New() returned
// ErrNoTierAvailable) rather than requiring every caller to special-case a
// nil client before calling in — pkg/mcpserver's plan tool and
// pkg/webui's plan-preview resolve action both rely on this.
func TestResolveTreeLeaves_NilClientEscalatesEveryUnresolvedLeaf(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf-1", Status: agenttask.StatusUnresolved},
		{ID: "leaf-2", Status: agenttask.StatusPending}, // already resolved — must not appear
	}}}

	got := ResolveTreeLeaves(context.Background(), nil, ErrNoTierAvailable, tree, nil, nil, nil)
	if len(got) != 1 {
		t.Fatalf("got %d escalations, want 1: %v", len(got), got)
	}
	if got[0] != "leaf-1: LLM fallback unavailable (llmfallback: no local model or OpenRouter tier configured/reachable)" {
		t.Fatalf("unexpected escalation text: %q", got[0])
	}
}

// TestResolveTreeLeaves_NoUnresolvedLeaves_ReturnsNilWithoutTouchingClient
// confirms a tree with nothing to resolve is a no-op — in particular, it
// must not require a non-nil client just because the tree happens to have
// leaves at all.
func TestResolveTreeLeaves_NoUnresolvedLeaves_ReturnsNilWithoutTouchingClient(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf-1", Status: agenttask.StatusPending},
	}}}

	got := ResolveTreeLeaves(context.Background(), nil, nil, tree, nil, nil, nil)
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}
