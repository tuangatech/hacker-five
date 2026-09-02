package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestReconTool_MissingScope_Refused(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "recon",
		Arguments: map[string]any{"target": "example.com", "scope": []string{}},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want a tool-level error result: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for a recon call with an empty scope list — D3 (doc15 Step 1)")
	}
}

func TestReconTool_InvalidDepth_Rejected(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "recon",
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
