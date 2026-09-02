package mcpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestScanTool_MissingScope_RefusedBeforeAnyRequest covers D3's two defense
// layers (doc15 Step 1): the "scope" field is schema-required (rejected by
// the SDK's own input validation before the handler ever runs if the field
// is entirely absent), and requireScope additionally rejects an explicitly
// empty scope list (a caller that satisfies the schema's mere presence
// check with "scope": [] must still be refused). Both cases use a clearly-
// unroutable target, since neither should ever reach a real request.
func TestScanTool_MissingScope_RefusedBeforeAnyRequest(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	t.Run("scope field entirely absent", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "scan",
			Arguments: map[string]any{
				"targets":  []string{"http://127.0.0.1:1/"},
				"detector": "misconfig",
			},
		})
		if err != nil {
			t.Fatalf("CallTool returned a protocol error, want a tool-level error result: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected IsError=true for a scan call with no scope field at all")
		}
	})

	t.Run("scope field present but empty", func(t *testing.T) {
		res, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "scan",
			Arguments: map[string]any{
				"targets":  []string{"http://127.0.0.1:1/"},
				"detector": "misconfig",
				"scope":    []string{},
			},
		})
		if err != nil {
			t.Fatalf("CallTool returned a protocol error, want a tool-level error result: %v", err)
		}
		if !res.IsError {
			t.Fatal("expected IsError=true for a scan call with an empty scope list")
		}
		text := textContent(t, res)
		if !strings.Contains(text, "scope is required") {
			t.Errorf("expected requireScope's own message, got %q", text)
		}
	})
}

// textContent extracts the first TextContent block's text from a
// CallToolResult, failing the test if none is present.
func textContent(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatalf("expected at least one TextContent block in result, got %+v", res.Content)
	return ""
}
