package llmfallback

import (
	"context"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func TestResolveLeaf_UseExistingTag(t *testing.T) {
	srv := fakeChatServer(t, `{"decision":"use_existing_tag","tag":"wordpress","reason":"matched"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	leaf := &agenttask.PlanNode{ID: "leaf-1", Target: "example.com", Rationale: `tech fact "wordpress" matched no registry capability or template tag`}

	got, cost, err := c.ResolveLeaf(context.Background(), leaf, nil, nil)
	if err != nil {
		t.Fatalf("ResolveLeaf: %v", err)
	}
	if got.UseExistingTag != "wordpress" {
		t.Fatalf("got %+v, want UseExistingTag=wordpress", got)
	}
	if got.DraftTemplate != "" || got.EscalateToHuman != "" {
		t.Fatalf("expected only UseExistingTag set, got %+v", got)
	}
	if cost != 0 {
		t.Fatalf("local-only resolution cost = %v, want 0", cost)
	}
}

func TestResolveLeaf_Escalate(t *testing.T) {
	srv := fakeChatServer(t, `{"decision":"escalate","reason":"not confident"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	leaf := &agenttask.PlanNode{ID: "leaf-1"}
	got, _, err := c.ResolveLeaf(context.Background(), leaf, nil, nil)
	if err != nil {
		t.Fatalf("ResolveLeaf: %v", err)
	}
	if got.EscalateToHuman != "not confident" {
		t.Fatalf("got %+v, want EscalateToHuman=\"not confident\"", got)
	}
}

func TestResolveLeaf_NeedsNewTemplate_NoFrontierConfigured_Escalates(t *testing.T) {
	srv := fakeChatServer(t, `{"decision":"needs_new_template","reason":"nothing fits"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL) // OpenRouter deliberately unconfigured

	leaf := &agenttask.PlanNode{ID: "leaf-1"}
	got, _, err := c.ResolveLeaf(context.Background(), leaf, nil, nil)
	if err != nil {
		t.Fatalf("ResolveLeaf: %v", err)
	}
	if got.EscalateToHuman == "" {
		t.Fatalf("got %+v, want an EscalateToHuman reason (no frontier tier to draft with)", got)
	}
	if got.DraftTemplate != "" {
		t.Fatalf("got %+v, want no DraftTemplate without a frontier tier", got)
	}
}
