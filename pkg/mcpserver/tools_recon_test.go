package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
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

// TestReconTool_HappyPath_LocalTarget drives the recon tool's real handler
// end to end against a local httptest.Server — depth=passive skips the
// shelled active-probe binaries, isolateFromInstalledReconBinaries keeps
// subfinder/tlsx from being shelled out to for real even when this machine
// has them installed (see that helper's own doc comment), and the loopback
// target means pkg/recon's own isPrivateOrLoopbackHost guard skips WHOIS/ASN
// too — so the only real request made is Wave 0's security.txt probe, back
// to this same local server.
func TestReconTool_HappyPath_LocalTarget(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx := context.Background()
	session, err := connect(ctx, New())
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "recon",
		Arguments: map[string]any{
			"target": srv.URL,
			"scope":  []string{"127.0.0.1"},
			"depth":  "passive",
		},
	})
	require.NoError(t, err)
	if res.IsError {
		t.Fatalf("expected a successful recon run against a local target, got error result: %s", textContent(t, res))
	}
}
