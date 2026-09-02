package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func TestToolsSearchTool_ReturnsMatchingCapabilities(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "tools.search",
		Arguments: map[string]any{"query": "idor"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textContent(t, res))
	}

	var out toolsSearchOutput
	if err := json.Unmarshal([]byte(textContent(t, res)), &out); err != nil {
		t.Fatalf("unmarshaling result: %v", err)
	}
	found := false
	for _, c := range out.Capabilities {
		if c.Name == "idor" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the idor capability among results, got %+v", out.Capabilities)
	}
}

func TestSearchTemplateEntries_MatchesNameAndTags(t *testing.T) {
	entries := []templatesync.Entry{
		{ID: "t1", Name: "WordPress Panel Exposure", Tags: []string{"wordpress", "misconfig"}},
		{ID: "t2", Name: "Generic Login Page", Tags: []string{"auth"}},
	}

	byName := searchTemplateEntries("wordpress", entries)
	if len(byName) != 1 || byName[0].ID != "t1" {
		t.Fatalf("expected a name match on t1, got %+v", byName)
	}

	byTag := searchTemplateEntries("auth", entries)
	if len(byTag) != 1 || byTag[0].ID != "t2" {
		t.Fatalf("expected a tag match on t2, got %+v", byTag)
	}

	if got := searchTemplateEntries("", entries); got != nil {
		t.Fatalf("expected nil for an empty query, got %+v", got)
	}
}

func TestTemplatesSearchTool_MissingIndex_DegradesToEmpty(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	// No templates/index.json exists relative to the test binary's working
	// directory — must degrade to an empty result, not a tool error, same
	// posture as cmd/hackerfive/plan.go and pkg/webui's plan-preview page.
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "templates.search",
		Arguments: map[string]any{"query": "wordpress"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected a graceful degrade, not a tool error: %s", textContent(t, res))
	}
}

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
		t.Fatal("expected IsError=true for a plan call with an empty scope list — D3 applies to plan too, since it runs recon internally")
	}
}
