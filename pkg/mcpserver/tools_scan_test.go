package mcpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
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

// TestScanTool_PolicyDisallowed_RefusedBeforeAnyRequest covers D2 (doc15 Step
// 3): HACKERFIVE_POLICY_FILE marking a target automated_scanning: disallowed
// makes the scan tool refuse outright, before the engine ever runs. The
// target is deliberately non-loopback — the pre-flight no-ops for lab hosts.
func TestScanTool_PolicyDisallowed_RefusedBeforeAnyRequest(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(policy, []byte("targets:\n  - match: \"*.blocked.example\"\n    automated_scanning: disallowed\n"), 0o644))
	t.Setenv("HACKERFIVE_POLICY_FILE", policy)

	ctx := context.Background()
	session, err := connect(ctx, New())
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: map[string]any{
			"targets":  []string{"https://api.blocked.example"},
			"scope":    []string{"*.blocked.example"},
			"detector": "misconfig",
		},
	})
	require.NoError(t, err)
	require.True(t, res.IsError, "a policy-disallowed target must be refused")
	require.Contains(t, textContent(t, res), "disallows automated scanning")
}

// TestScanTool_ValidationError_MissingEndpointForIDOR confirms
// scanner.Config.Validate()'s own required-field check surfaces as a
// tool-level error, not a panic or a silently-empty result — reached only
// after requireScope passes, so scope is set here to a value that would
// otherwise let the call through.
func TestScanTool_ValidationError_MissingEndpointForIDOR(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: map[string]any{
			"targets":  []string{"http://127.0.0.1:1/"},
			"scope":    []string{"127.0.0.1"},
			"detector": "idor",
		},
	})
	require.NoError(t, err)
	if !res.IsError {
		t.Fatal("expected IsError=true for detector=idor with no endpoint_template")
	}
}

// TestScanTool_HappyPath_MisconfigAgainstLocalTarget drives the scan tool's
// real handler end to end (cfg construction, engine.New/Run, the
// finding/log callbacks) against a local httptest.Server — matching the
// pattern pkg/webui's own end-to-end launch tests already use to stay free
// of live external network dependency.
func TestScanTool_HappyPath_MisconfigAgainstLocalTarget(t *testing.T) {
	// Without this, a machine that has ever run 'hackerfive templates sync'
	// (this repo's own dev environment has) would load the full ~9,652-
	// template synced corpus on top of the bundled dir, turning this test
	// from a few real requests into thousands — same class of hidden local-
	// state dependency as isolateFromInstalledReconBinaries fixes for the
	// recon binaries; see pkg/webui's newTestServer for the same fix applied
	// there first.
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
		Name: "scan",
		Arguments: map[string]any{
			"targets":  []string{srv.URL},
			"scope":    []string{"127.0.0.1"},
			"detector": "misconfig",
		},
	})
	require.NoError(t, err)
	if res.IsError {
		t.Fatalf("expected a successful scan run against a local target, got error result: %s", textContent(t, res))
	}
}

// TestScanTool_TechStackNarrowing_DegradesGracefullyWithoutIndex is LT-17's
// (docs/follow-up.md) MCP-parity regression guard: passing tech_stack with
// no template index reachable (the common test/CI case — nothing has run
// 'hackerfive templates index' from this working directory) must degrade to
// running the full corpus with a logged note, never a hard error — the same
// "full corpus is the safe fallback" posture LT-16 established for the Web
// UI's own checkbox.
func TestScanTool_TechStackNarrowing_DegradesGracefullyWithoutIndex(t *testing.T) {
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
		Name: "scan",
		Arguments: map[string]any{
			"targets":  []string{srv.URL},
			"scope":    []string{"127.0.0.1"},
			"detector": "misconfig",
			"tech_stack": []map[string]any{
				{"name": "WordPress", "host": "127.0.0.1", "source": "httpx-tech-detect", "confidence": "medium"},
			},
		},
	})
	require.NoError(t, err)
	if res.IsError {
		t.Fatalf("expected a successful scan run even when narrow-by-tech can't load an index, got error result: %s", textContent(t, res))
	}
}

// TestIsWritesAttested is B2's unit check: only accept + approve=true +
// acknowledge_writes=true clears the gate.
func TestIsWritesAttested(t *testing.T) {
	tests := []struct {
		name string
		resp mcp.InputResponse
		want bool
	}{
		{"both true", &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_writes": true}}, true},
		{"approve true, ack absent", &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, false},
		{"approve true, ack false", &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_writes": false}}, false},
		{"ack true, approve false", &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": false, "acknowledge_writes": true}}, false},
		{"declined", &mcp.ElicitResult{Action: "decline"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isWritesAttested(tt.resp))
		})
	}
}

// TestScanTool_BusinessLogicWrites_NonElicitationClient_SkipsWrites covers
// B2's degrade path: a client with no elicitation capability cannot attest,
// so the businesslogic scan still runs but with writes off and a log line
// saying the grant was requested and withheld — never an error, never a
// silent write.
func TestScanTool_BusinessLogicWrites_NonElicitationClient_SkipsWrites(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx := context.Background()
	session, err := connect(ctx, New()) // no ElicitationHandler
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: map[string]any{
			"targets":      []string{srv.URL},
			"scope":        []string{"127.0.0.1"},
			"detector":     "businesslogic",
			"allow_writes": true,
			"auth_token":   "test-owner-token", // businesslogic's Config.Validate requires one; no real request needs it here
		},
	})
	require.NoError(t, err)
	require.False(t, res.IsError, "a writes-requested businesslogic scan must still run read-only, not error: %s", textContent(t, res))

	var out scanOutput
	decodeToolResult(t, res, &out)
	require.True(t, hasLogContaining(out.Logs, "not attested"),
		"expected a log line recording that allow_writes was withheld, got %v", out.Logs)
}

// TestScanTool_BusinessLogicWrites_ElicitationDeclined_SkipsWrites: an
// elicitation-capable client that declines (or omits acknowledge_writes)
// gets the same writes-off outcome as a non-capable client.
func TestScanTool_BusinessLogicWrites_ElicitationDeclined_SkipsWrites(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx := context.Background()
	// The SDK's client middleware validates the elicitation response against
	// the requested schema, so acknowledge_writes must be present — false here
	// is the real "approved the scan, did NOT authorize writes" answer.
	session, err := connectWithElicitation(ctx, New(), func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_writes": false}}, nil
	})
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: map[string]any{
			"targets":      []string{srv.URL},
			"scope":        []string{"127.0.0.1"},
			"detector":     "businesslogic",
			"allow_writes": true,
			"auth_token":   "test-owner-token", // businesslogic's Config.Validate requires one; no real request needs it here
		},
	})
	require.NoError(t, err)
	require.False(t, res.IsError, "declined attestation must not error: %s", textContent(t, res))

	var out scanOutput
	decodeToolResult(t, res, &out)
	require.True(t, hasLogContaining(out.Logs, "not attested"),
		"expected the writes-withheld log line after a declined attestation, got %v", out.Logs)
}

// TestScanTool_BusinessLogicWrites_Attested_Completes: approve=true +
// acknowledge_writes=true clears the gate; the scan runs and the
// writes-withheld log line is absent.
func TestScanTool_BusinessLogicWrites_Attested_Completes(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	ctx := context.Background()
	session, err := connectWithElicitation(ctx, New(), func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_writes": true}}, nil
	})
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan",
		Arguments: map[string]any{
			"targets":      []string{srv.URL},
			"scope":        []string{"127.0.0.1"},
			"detector":     "businesslogic",
			"allow_writes": true,
			"auth_token":   "test-owner-token", // businesslogic's Config.Validate requires one; no real request needs it here
		},
	})
	require.NoError(t, err)
	require.False(t, res.IsError, "an attested businesslogic scan must run: %s", textContent(t, res))

	var out scanOutput
	decodeToolResult(t, res, &out)
	require.False(t, hasLogContaining(out.Logs, "not attested"),
		"the writes-withheld log line must be absent once attested, got %v", out.Logs)
}

func hasLogContaining(logs []string, sub string) bool {
	for _, l := range logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
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
