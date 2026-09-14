package llmfallback

import (
	"context"
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
