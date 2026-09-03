package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect wires server to a fresh in-memory client session — the same
// pattern the SDK's own example tests use (mcp.NewInMemoryTransports),
// exercising the real tools/call round trip rather than calling handler
// closures directly.
func connect(ctx context.Context, server *mcp.Server) (*mcp.ClientSession, error) {
	return connectWithOptions(ctx, server, nil)
}

// connectWithElicitation is connect, but the client declares elicitation
// support and answers every elicitation request with handler — the shape
// Phase 6 Step 2's plan/findings.triage tools need to test the real
// approve/decline round trip, not just the tool-wiring smoke tests
// connect's callers already cover.
func connectWithElicitation(ctx context.Context, server *mcp.Server, handler func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error)) (*mcp.ClientSession, error) {
	return connectWithOptions(ctx, server, &mcp.ClientOptions{ElicitationHandler: handler})
}

func connectWithOptions(ctx context.Context, server *mcp.Server, opts *mcp.ClientOptions) (*mcp.ClientSession, error) {
	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, opts)
	return client.Connect(ctx, t2, nil)
}
