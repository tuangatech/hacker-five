package llmfallback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/coveragegap"
)

func sampleLedger() []coveragegap.GapRow {
	return []coveragegap.GapRow{
		{Host: "gateway.example.com", Product: "Webmin 2.111", Reason: coveragegap.ReasonNoCoverage},
	}
}

func TestSuggest_ValidActions(t *testing.T) {
	srv := fakeChatServer(t, `{"actions":[{"kind":"draft_template","description":"draft a Webmin check","detail":{"host":"gateway.example.com"}}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.Suggest(context.Background(), sampleLedger(), sampleFindings())
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if len(got.Actions) != 1 || got.Actions[0].Kind != "draft_template" {
		t.Fatalf("got %+v", got)
	}
}

func TestSuggest_ModelInventsUnknownKind_Drops(t *testing.T) {
	srv := fakeChatServer(t, `{"actions":[{"kind":"delete_target","description":"x"},{"kind":"run_leaf","description":"y"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.Suggest(context.Background(), sampleLedger(), sampleFindings())
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if len(got.Actions) != 1 || got.Actions[0].Kind != "run_leaf" {
		t.Fatalf("got %+v, want only the valid-kind action to survive", got)
	}
}

func TestSuggest_EmptyInput_NoCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Errorf("unexpected call to %s — Suggest must not call out for empty ledger + findings", r.URL.Path)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, cost, err := c.Suggest(context.Background(), nil, nil)
	if err != nil || cost != 0 || got.Actions != nil {
		t.Fatalf("got (%+v, %v, %v), want zero-value result and no call", got, cost, err)
	}
}
