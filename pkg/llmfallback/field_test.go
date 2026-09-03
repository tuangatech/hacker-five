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

// TestResolveField_ModelEscalates confirms an explicit escalate_to_human
// response passes straight through — replaces a now-obsolete test
// (TestResolveField_NoLocalTier_Escalates) that asserted the old
// local-tier-only design's "unreachable local = immediate escalate, never
// try OpenRouter" behavior; ResolveField now delegates to
// completeBestAvailable (same as ResolveLeaf/triage) and genuinely
// attempts the frontier tier when local fails, so that scenario can no
// longer be asserted without a real network call — same untested-by-design
// gap ResolveLeaf's own tests already accept (defaultOpenRouterBaseURL has
// no test-seam override).
func TestResolveField_ModelEscalates(t *testing.T) {
	srv := fakeChatServer(t, `{"escalate_to_human":"not confident"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, cost, err := c.ResolveField(context.Background(), "idor", "endpoint_template", nil)
	if err != nil {
		t.Fatalf("ResolveField: %v", err)
	}
	if got.EscalateToHuman != "not confident" {
		t.Fatalf("got %+v, want EscalateToHuman=\"not confident\"", got)
	}
	if got.SuggestedValue != "" {
		t.Fatalf("got %+v, want no SuggestedValue", got)
	}
	if cost != 0 {
		t.Fatalf("local tier cost = %v, want 0", cost)
	}
}

func TestResolveFieldMiss_NilClientEscalates(t *testing.T) {
	got, cost := ResolveFieldMiss(context.Background(), nil, ErrNoTierAvailable, "idor", "endpoint_template", nil)
	if got.EscalateToHuman == "" {
		t.Fatalf("got %+v, want an EscalateToHuman reason", got)
	}
	if got.SuggestedValue != "" {
		t.Fatalf("got %+v, want no SuggestedValue when fb is nil", got)
	}
	if cost != 0 {
		t.Fatalf("cost = %v, want 0", cost)
	}
}

func TestResolveFieldMiss_CallSuccess_PassesDecisionThrough(t *testing.T) {
	srv := fakeChatServer(t, `{"suggested_value":"/orders/{{id}}","rationale":"most specific"}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, cost := ResolveFieldMiss(context.Background(), c, nil, "idor", "endpoint_template", []string{"/orders/{{id}}", "/invoices?invoice_id={{id}}"})
	if got.SuggestedValue != "/orders/{{id}}" {
		t.Fatalf("got %+v", got)
	}
	if got.EscalateToHuman != "" {
		t.Fatalf("got %+v, want no EscalateToHuman on success", got)
	}
	if cost != 0 {
		t.Fatalf("local tier cost = %v, want 0", cost)
	}
}
