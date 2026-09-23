package orchestrator

import (
	"context"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// TestRun_ResultCarriesTheReconLedgerWithoutValues guards LT-185's one new
// stream input: the endpoints recon observed ride on Result so pkg/coverage can
// say where a missed vulnerability was lost, and they carry names, not values.
func TestRun_ResultCarriesTheReconLedgerWithoutValues(t *testing.T) {
	srv := fastLaneTargetServer(t)
	cfg := fastLaneConfig(srv, &fakeLLMClient{actions: []llmfallback.Action{{Kind: "stop"}}})
	cfg.Recon = &fakeRecon{result: &recon.ReconResult{
		Target: srv.URL,
		Endpoints: []recon.EndpointFact{
			{URL: srv.URL + "/", StatusCode: 200, Source: "httpx"},
			{URL: srv.URL + "/api/orders/48213?session=s3cr3t&page=2", Method: "GET", Source: "katana"},
			{URL: srv.URL + "/api/orders/48213?session=s3cr3t&page=2", Method: "GET", Source: "katana"}, // a duplicate observation
		},
	}}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Recon) != 2 {
		t.Fatalf("Recon = %+v, want the root and one orders endpoint (the duplicate collapsed)", result.Recon)
	}
	var orders string
	for _, ep := range result.Recon {
		if strings.Contains(ep.URL, "/api/orders/") {
			orders = ep.URL
		}
	}
	if !strings.HasSuffix(orders, "/api/orders/{id}?session=&page=") {
		t.Fatalf("orders endpoint = %q, want the id and the query values stripped", orders)
	}
	for _, ep := range result.Recon {
		if strings.Contains(ep.URL, "s3cr3t") || strings.Contains(ep.URL, "48213") {
			t.Fatalf("a value leaked into the ledger: %q", ep.URL)
		}
	}
}
