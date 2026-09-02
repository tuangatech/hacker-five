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
