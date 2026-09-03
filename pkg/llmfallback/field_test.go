package llmfallback

import (
	"context"
	"testing"
)

func TestResolveField_SuggestedValue(t *testing.T) {
	srv := fakeChatServer(t, `{"suggested_value":"/orders/{{id}}","rationale":"most specific"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, cost, err := c.ResolveField(context.Background(), "idor", "endpoint_template", []string{"/orders/{{id}}", "/invoices?invoice_id={{id}}"})
	if err != nil {
		t.Fatalf("ResolveField: %v", err)
	}
	if got.SuggestedValue != "/orders/{{id}}" {
		t.Fatalf("got %+v", got)
	}
	if cost != 0 {
		t.Fatalf("local tier cost = %v, want 0", cost)
	}
}

func TestResolveField_NoLocalTier_Escalates(t *testing.T) {
	t.Setenv(envLocalModelURL, "http://127.0.0.1:1/unreachable")
	t.Setenv(envOpenRouterKey, "dummy-key-for-config-only")
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, cost, err := c.ResolveField(context.Background(), "idor", "endpoint_template", nil)
	if err != nil {
		t.Fatalf("ResolveField: %v", err)
	}
	if got.EscalateToHuman == "" {
		t.Fatalf("got %+v, want an EscalateToHuman reason", got)
	}
	if cost != 0 {
		t.Fatalf("cost = %v, want 0 (no call made)", cost)
	}
}
