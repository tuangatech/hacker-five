package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestTemplatesListTool_NoErrorEvenWithNothingSynced only checks the tool
// wiring (arguments in, no tool error out) — pkg/templatesync.List's own
// loading/filtering logic already has its own tests (pkg/templatesync).
// DefaultBundledDir is relative to the process's working directory, which
// under `go test` is this package's own directory, not the repo root, so
// this legitimately returns zero templates here — that's fine, this test
// only guards against the wrapper itself erroring.
func TestTemplatesListTool_NoErrorEvenWithNothingSynced(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "templates.list", Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textContent(t, res))
	}
}
