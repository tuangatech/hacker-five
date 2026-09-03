package mcpserver

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// TestPlanTool_MissingScope_Refused/InvalidDepth mirror recon's own tests
// (tools_recon_test.go) — plan wraps the same recon.Run pipeline, so the
// same pre-flight rejections apply before any network call happens. The
// full elicitation/execution round trip needs a real target and a real
// elicitation-capable client and is covered by doc15 Step 2's live
// verification, not an offline unit test.
func TestPlanTool_MissingScope_Refused(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "plan",
		Arguments: map[string]any{"target": "example.com", "scope": []string{}},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want a tool-level error result: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for a plan call with an empty scope list")
	}
}

func TestPlanTool_InvalidDepth_Rejected(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "plan",
		Arguments: map[string]any{
			"target": "example.com",
			"scope":  []string{"example.com"},
			"depth":  "not-a-real-depth",
		},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want a tool-level error result: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for an invalid depth value")
	}
}

func TestMissingRequiredField(t *testing.T) {
	cases := []struct {
		name     string
		detector string
		cfg      scanner.Config
		wantMiss bool
	}{
		{"idor missing endpoint", "idor", scanner.Config{}, true},
		{"idor has endpoint", "idor", scanner.Config{EndpointTemplate: "/x/{{id}}"}, false},
		{"authbypass missing protected paths", "authbypass", scanner.Config{}, true},
		{"authbypass has protected paths", "authbypass", scanner.Config{ProtectedPaths: []string{"/admin"}}, false},
		{"ssrf missing params", "ssrf", scanner.Config{}, true},
		{"ssrf has params", "ssrf", scanner.Config{SSRFParams: []string{"url"}}, false},
		{"misconfig has no requirement", "misconfig", scanner.Config{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := missingRequiredField(tc.detector, tc.cfg) != ""
			if got != tc.wantMiss {
				t.Fatalf("got miss=%v, want %v", got, tc.wantMiss)
			}
		})
	}
}

func TestApplyLeafDecision_UseExistingTag(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "leaf-1", Status: agenttask.StatusUnresolved},
	}}}
	var escalations []string
	addEscalation := func(format string, args ...any) { escalations = append(escalations, format) }

	applyLeafDecision(tree, tree.Find("leaf-1"), llmfallback.LeafDecision{UseExistingTag: "misconfig"}, addEscalation)

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

	applyLeafDecision(tree, tree.Find("leaf-1"), llmfallback.LeafDecision{EscalateToHuman: "not confident"}, addEscalation)

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
