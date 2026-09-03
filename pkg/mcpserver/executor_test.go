package mcpserver

import (
	"context"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// TestRunPlan_SkipsUnexecutableLeaves confirms three of the four skip
// reasons (unrecognized detector/template-ID, missing required field) never
// reach scanner.New — no network call is attempted for them, only the
// eligible leaf is dispatched (against an unreachable address, so it fails
// fast rather than needing a real target — this test is about dispatch
// eligibility, not scan correctness).
func TestRunPlan_SkipsUnexecutableLeaves(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "template-id-leaf", Target: "http://127.0.0.1:1", Detector: "wordpress-xmlrpc-enabled"}, // raw template ID, not a recognized detector
		{ID: "idor-no-endpoint", Target: "http://127.0.0.1:1", Detector: "idor"},                      // recognized, but EndpointTemplate unset on baseCfg
		{ID: "misconfig-leaf", Target: "http://127.0.0.1:1", Detector: "misconfig"},                   // eligible
	}}}

	baseCfg := scanner.Config{
		Concurrency:  1,
		RateLimit:    50,
		Timeout:      2 * time.Second,
		OutputFormat: "json",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, skipped, _ := RunPlan(ctx, nil, nil, tree, baseCfg, nil) // nil templateIndex — "wordpress-xmlrpc-enabled" matches no known template ID either

	if len(skipped) != 2 {
		t.Fatalf("got %d skipped leaves, want 2 (template-id-leaf, idor-no-endpoint); skipped=%v", len(skipped), skipped)
	}

	// The eligible leaf must have been dispatched (its Status moved off
	// pending, whatever the outcome against an unreachable target).
	if tree.Find("misconfig-leaf").Status != agenttask.StatusDone {
		t.Fatalf("got Status=%q for the eligible leaf, want done (dispatched, regardless of scan outcome)", tree.Find("misconfig-leaf").Status)
	}
	// The two skipped leaves must be untouched — never dispatched.
	if tree.Find("template-id-leaf").Status == agenttask.StatusDone {
		t.Fatal("a skipped leaf must not be marked done")
	}
	if tree.Find("idor-no-endpoint").Status == agenttask.StatusDone {
		t.Fatal("a skipped leaf must not be marked done")
	}
}

// TestRunPlan_DispatchesKnownTemplateIDLeaf locks in the fix for what was
// previously always-skipped: a leaf whose Detector matches a real
// templatesync.Entry.ID (not a built-in detector name) now dispatches as a
// templates-only run instead of landing in skipped.
func TestRunPlan_DispatchesKnownTemplateIDLeaf(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "template-id-leaf", Target: "http://127.0.0.1:1", Detector: "wordpress-xmlrpc-enabled"},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}
	templateIndex := []templatesync.Entry{{ID: "wordpress-xmlrpc-enabled", Tags: []string{"wordpress"}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _, skipped, _ := RunPlan(ctx, nil, nil, tree, baseCfg, templateIndex)

	if len(skipped) != 0 {
		t.Fatalf("got skipped=%v, want none — the leaf's Detector matches a real template ID", skipped)
	}
	if tree.Find("template-id-leaf").Status != agenttask.StatusDone {
		t.Fatalf("got Status=%q, want done (dispatched as a templates-only run, regardless of scan outcome)", tree.Find("template-id-leaf").Status)
	}
}

// TestRunPlan_UnknownTemplateIDStillSkipped confirms a Detector value that
// matches neither a built-in detector name nor any entry in templateIndex
// (a hallucination, or a stale/renamed template) keeps the original
// skip-and-report behavior — no new silent-execution risk from this fix.
func TestRunPlan_UnknownTemplateIDStillSkipped(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "hallucinated-leaf", Target: "http://127.0.0.1:1", Detector: "totally-made-up-template-id"},
	}}}
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50, Timeout: 2 * time.Second, OutputFormat: "json"}
	templateIndex := []templatesync.Entry{{ID: "wordpress-xmlrpc-enabled", Tags: []string{"wordpress"}}}

	_, _, skipped, _ := RunPlan(context.Background(), nil, nil, tree, baseCfg, templateIndex)

	if len(skipped) != 1 {
		t.Fatalf("got skipped=%v, want exactly 1 (the hallucinated Detector)", skipped)
	}
	if tree.Find("hallucinated-leaf").Status == agenttask.StatusDone {
		t.Fatal("a hallucinated Detector must not be dispatched")
	}
}

func TestRunPlan_EmptyTree_NoPanic(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}} // root itself is a leaf, but has no Detector
	baseCfg := scanner.Config{Concurrency: 1, RateLimit: 50}

	findings, logs, skipped, err := RunPlan(context.Background(), nil, nil, tree, baseCfg, nil)
	if findings != nil || logs != nil || skipped != nil || err != nil {
		t.Fatalf("got (%v, %v, %v, %v), want all zero values for a tree with no Detector on its only leaf", findings, logs, skipped, err)
	}
}
