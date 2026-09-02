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
	t1, t2 := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, t1, nil); err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	return client.Connect(ctx, t2, nil)
}
