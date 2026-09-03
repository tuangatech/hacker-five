package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestTriageTool_EmptyFindings_NoErrorNoRanking(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "findings.triage",
		Arguments: map[string]any{"findings": []map[string]any{}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error for an empty finding list: %s", textContent(t, res))
	}
}

func TestTriageTool_NoFallbackConfigured_Escalates(t *testing.T) {
	t.Setenv("HACKERFIVE_LOCAL_MODEL_URL", "http://127.0.0.1:1/unreachable")
	t.Setenv("OPENROUTER_API_KEY", "")

	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "findings.triage",
		Arguments: map[string]any{"findings": []map[string]any{
			{"id": "f1", "type": "misconfig", "severity": "low", "confidence": "high", "target": "https://example.com", "description": "exposed .git directory", "evidence": map[string]string{}},
		}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected a graceful escalate_to_human result, not a tool error: %s", textContent(t, res))
	}

	var out findingsTriageOutput
	decodeToolResult(t, res, &out)
	if out.EscalateToHuman == "" {
		t.Fatal("expected EscalateToHuman to be set when no LLM tier is configured")
	}
	if out.Approved {
		t.Fatal("must not be Approved without a real ranking")
	}
}

// TestTriageTool_FallbackCallFails_EscalatesNotHardError covers the real
// gap found live-verifying against the actual binary (2026-09-02): a
// reachable local tier that then fails the actual chat-completion call
// (model not found, in that live run) must escalate gracefully, the same
// posture ResolveLeaf/ResolveField's own call failures already get inside
// the plan tool — not surface as a protocol-level tool error.
func TestTriageTool_FallbackCallFails_EscalatesNotHardError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"message":"model not found"}}`))
	}))
	defer srv.Close()
	t.Setenv("HACKERFIVE_LOCAL_MODEL_URL", srv.URL)
	t.Setenv("OPENROUTER_API_KEY", "")

	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "findings.triage",
		Arguments: map[string]any{"findings": []map[string]any{
			{"id": "f1", "type": "misconfig", "severity": "low", "confidence": "high", "target": "https://example.com", "description": "test", "evidence": map[string]string{}},
		}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected a graceful escalate_to_human result, not a tool error: %s", textContent(t, res))
	}

	var out findingsTriageOutput
	decodeToolResult(t, res, &out)
	if out.EscalateToHuman == "" {
		t.Fatal("expected EscalateToHuman when the fallback call itself fails")
	}
}

// TestTriageTool_ClientWithoutElicitationSupport_DegradesGracefully covers
// the real gap found and fixed 2026-09-02 (see clientSupportsElicitation's
// own doc comment in scope.go): a client that never declares elicitation
// capability — connect()'s plain client, with no ElicitationHandler set —
// must get a clean, usable result back, not a failed InputRequests round
// trip it can't fulfill.
func TestTriageTool_ClientWithoutElicitationSupport_DegradesGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"ranked\":[{\"finding_id\":\"f1\",\"rank\":1,\"rationale\":\"only finding\"}]}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer srv.Close()
	t.Setenv("HACKERFIVE_LOCAL_MODEL_URL", srv.URL)
	t.Setenv("OPENROUTER_API_KEY", "")

	ctx := context.Background()
	session, err := connect(ctx, New()) // no ElicitationHandler
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "findings.triage",
		Arguments: map[string]any{"findings": []map[string]any{
			{"id": "f1", "type": "misconfig", "severity": "low", "confidence": "high", "target": "https://example.com", "description": "test", "evidence": map[string]string{}},
		}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected a graceful degrade, not a tool/protocol error: %s", textContent(t, res))
	}

	var out findingsTriageOutput
	decodeToolResult(t, res, &out)
	if len(out.Ranked) != 1 {
		t.Fatalf("expected the ranking still returned for inspection, got %+v", out)
	}
	if out.Approved {
		t.Fatal("must not be Approved without a real elicitation round trip")
	}
}

// TestTriageTool_ApprovedRoundTrip exercises the full path: a mocked local
// model returns a valid ranking, the in-memory client accepts the
// elicitation, and the tool reports Approved=true.
func TestTriageTool_ApprovedRoundTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"ranked\":[{\"finding_id\":\"f1\",\"rank\":1,\"rationale\":\"only finding\"}]}"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer srv.Close()
	t.Setenv("HACKERFIVE_LOCAL_MODEL_URL", srv.URL)
	t.Setenv("OPENROUTER_API_KEY", "")

	ctx := context.Background()
	session, err := connectWithElicitation(ctx, New(), func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
	})
	if err != nil {
		t.Fatalf("connectWithElicitation: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "findings.triage",
		Arguments: map[string]any{"findings": []map[string]any{
			{"id": "f1", "type": "misconfig", "severity": "low", "confidence": "high", "target": "https://example.com", "description": "exposed .git directory", "evidence": map[string]string{}},
		}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error: %s", textContent(t, res))
	}

	var out findingsTriageOutput
	decodeToolResult(t, res, &out)
	if !out.Approved {
		t.Fatalf("expected Approved=true after an accepting elicitation response, got %+v", out)
	}
	if len(out.Ranked) != 1 || out.Ranked[0].FindingID != "f1" {
		t.Fatalf("got %+v", out.Ranked)
	}
}

func decodeToolResult(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(textContent(t, res)), v); err != nil {
		t.Fatalf("decoding tool result: %v", err)
	}
}
