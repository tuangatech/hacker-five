package mcpserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

func TestFindingsExportTool_Formats(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	finding := map[string]any{
		"id":          "f1",
		"type":        "misconfig",
		"severity":    "medium",
		"confidence":  "high",
		"target":      "https://example.com/",
		"description": "directory listing enabled",
		"evidence":    map[string]any{},
	}

	cases := []struct {
		format string
		want   string
	}{
		{"", `"id": "f1"`}, // default: json
		{"markdown", "directory listing enabled"},
		{"html", "directory listing enabled"},
		{"hackerone-json", "medium"},
	}
	for _, c := range cases {
		t.Run(c.format, func(t *testing.T) {
			args := map[string]any{"findings": []any{finding}}
			if c.format != "" {
				args["format"] = c.format
			}
			res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "findings.export", Arguments: args})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if res.IsError {
				t.Fatalf("unexpected tool error: %s", textContent(t, res))
			}
			var out findingsExportOutput
			if err := json.Unmarshal([]byte(textContent(t, res)), &out); err != nil {
				t.Fatalf("unmarshaling result: %v", err)
			}
			if !strings.Contains(out.Content, c.want) {
				t.Errorf("format %q: expected output to contain %q, got %s", c.format, c.want, out.Content)
			}
		})
	}
}

// TestFindingsExportTool_CitedIDNotPresent_Rejected covers C3 (doc16 Phase
// 7 Step 3): an export whose cited_finding_ids names an ID absent from the
// finding set is rejected at the tool boundary — an agent-drafted narrative
// cannot cite evidence that does not exist.
func TestFindingsExportTool_CitedIDNotPresent_Rejected(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	finding := map[string]any{
		"id": "real-1", "type": "misconfig", "severity": "low", "confidence": "high",
		"target": "https://example.com/", "description": "x", "evidence": map[string]any{},
	}

	// A present citation passes.
	okRes, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "findings.export", Arguments: map[string]any{
		"findings": []any{finding}, "cited_finding_ids": []any{"real-1"},
	}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if okRes.IsError {
		t.Fatalf("a citation to a present finding must pass, got: %s", textContent(t, okRes))
	}

	// An absent citation is rejected, and the offending ID is named.
	badRes, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "findings.export", Arguments: map[string]any{
		"findings": []any{finding}, "cited_finding_ids": []any{"real-1", "ghost-9"},
	}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !badRes.IsError {
		t.Fatal("expected IsError=true for a citation to a nonexistent finding ID")
	}
	if !strings.Contains(textContent(t, badRes), "ghost-9") {
		t.Errorf("rejection should name the missing ID, got: %s", textContent(t, badRes))
	}
}

func TestFindingsExportTool_UnknownFormat_Rejected(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "findings.export",
		Arguments: map[string]any{
			"findings": []detectors.Finding{},
			"format":   "not-a-real-format",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for an unrecognized format")
	}
}
