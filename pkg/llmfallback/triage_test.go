package llmfallback

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

func sampleFindings() []detectors.Finding {
	return []detectors.Finding{
		{ID: "f1", Type: "idor", Severity: "high", Confidence: "high", Target: "https://example.com/orders/1"},
		{ID: "f2", Type: "misconfig", Severity: "low", Confidence: "high", Target: "https://example.com/.git"},
	}
}

func TestTriageFindings_ValidRanking(t *testing.T) {
	srv := fakeChatServer(t, `{"ranked":[{"finding_id":"f1","rank":1,"rationale":"higher severity"},{"finding_id":"f2","rank":2,"rationale":"lower severity"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.TriageFindings(context.Background(), sampleFindings())
	if err != nil {
		t.Fatalf("TriageFindings: %v", err)
	}
	if len(got.Ranked) != 2 || got.Ranked[0].FindingID != "f1" {
		t.Fatalf("got %+v", got)
	}
}

func TestTriageFindings_ModelInventsUnknownID_Escalates(t *testing.T) {
	srv := fakeChatServer(t, `{"ranked":[{"finding_id":"f1","rank":1,"rationale":"x"},{"finding_id":"f99","rank":2,"rationale":"y"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.TriageFindings(context.Background(), sampleFindings())
	if err != nil {
		t.Fatalf("TriageFindings: %v", err)
	}
	if got.EscalateToHuman == "" {
		t.Fatalf("got %+v, want an EscalateToHuman reason (invalid ranking)", got)
	}
	if got.Ranked != nil {
		t.Fatalf("got %+v, want no Ranked on an invalid response", got)
	}
}

func TestTriageFindings_EmptyInput_NoCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Errorf("unexpected call to %s — TriageFindings must not call out for an empty input", r.URL.Path)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, cost, err := c.TriageFindings(context.Background(), nil)
	if err != nil || cost != 0 || got.Ranked != nil {
		t.Fatalf("got (%+v, %v, %v), want zero-value result and no call", got, cost, err)
	}
}

func TestValidateRanking_DuplicateID(t *testing.T) {
	err := validateRanking(sampleFindings(), []RankedFinding{
		{FindingID: "f1", Rank: 1}, {FindingID: "f1", Rank: 2},
	})
	if err == nil {
		t.Fatal("expected error for duplicate finding_id")
	}
}

func TestValidateRanking_MissingID(t *testing.T) {
	err := validateRanking(sampleFindings(), []RankedFinding{{FindingID: "f1", Rank: 1}})
	if err == nil {
		t.Fatal("expected error for incomplete ranking")
	}
}
