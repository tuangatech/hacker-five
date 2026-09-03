package llmfallback

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestClient points the local tier at a real httptest server and leaves
// OpenRouter unconfigured, unless env overrides are supplied.
func newTestClient(t *testing.T, localURL string) *Client {
	t.Helper()
	t.Setenv(envLocalModelURL, localURL)
	t.Setenv(envOpenRouterKey, "")
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func fakeChatServer(t *testing.T, content string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		resp := chatResponse{}
		resp.Choices = []struct {
			Message chatMessage `json:"message"`
		}{{Message: chatMessage{Role: "assistant", Content: content}}}
		resp.Usage.PromptTokens = 10
		resp.Usage.CompletionTokens = 5
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestNew_NoTierConfigured(t *testing.T) {
	t.Setenv(envLocalModelURL, "http://127.0.0.1:1/unreachable")
	t.Setenv(envOpenRouterKey, "")
	if _, err := New(); err != ErrNoTierAvailable {
		t.Fatalf("got %v, want ErrNoTierAvailable", err)
	}
}

func TestNew_LocalTierOnly(t *testing.T) {
	srv := fakeChatServer(t, "{}")
	defer srv.Close()
	c := newTestClient(t, srv.URL)
	if !c.localAvailable {
		t.Fatal("expected local tier available")
	}
	if c.openRouterKey != "" {
		t.Fatal("expected OpenRouter tier unconfigured")
	}
}

func TestComplete_LocalTier_ZeroCost(t *testing.T) {
	srv := fakeChatServer(t, `{"decision":"escalate","reason":"test"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	text, cost, err := c.complete(context.Background(), tierLocal, "system", "user")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if cost != 0 {
		t.Fatalf("local tier cost = %v, want 0", cost)
	}
	if text == "" {
		t.Fatal("expected non-empty response text")
	}
}

func TestDecodeJSONResponse_StripsMarkdownFence(t *testing.T) {
	var out map[string]string
	err := decodeJSONResponse("```json\n{\"foo\":\"bar\"}\n```", &out)
	if err != nil {
		t.Fatalf("decodeJSONResponse: %v", err)
	}
	if out["foo"] != "bar" {
		t.Fatalf("got %v, want foo=bar", out)
	}
}

func TestDecodeJSONResponse_InvalidJSON(t *testing.T) {
	var out map[string]string
	if err := decodeJSONResponse("not json", &out); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
