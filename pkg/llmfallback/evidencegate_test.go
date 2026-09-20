package llmfallback

import (
	"context"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

func TestEvidenceGateText_NoOverclaimPhrase_PassesThroughUnchanged(t *testing.T) {
	f := detectors.Finding{ID: "f1", Severity: "low", Confidence: "low"}
	got := evidenceGateText(f, "worth investigating, could expose sensitive data")
	if got != "worth investigating, could expose sensitive data" {
		t.Fatalf("got %q, want unchanged text (no overclaim phrase present)", got)
	}
}

func TestEvidenceGateText_StrongFinding_OverclaimAllowedThrough(t *testing.T) {
	f := detectors.Finding{ID: "f1", Severity: "critical", Confidence: "high"}
	rationale := "this is fully exploitable and grants full access to the admin panel"
	got := evidenceGateText(f, rationale)
	if got != rationale {
		t.Fatalf("got %q, want unchanged — high confidence + critical severity already supports strong language", got)
	}
}

func TestEvidenceGateText_LowConfidenceFinding_OverclaimGetsCaveated(t *testing.T) {
	f := detectors.Finding{ID: "idor-42", Severity: "high", Confidence: "low"}
	rationale := "this is fully exploitable and should be reported first"
	got := evidenceGateText(f, rationale)
	if !strings.Contains(got, "unverified claim") {
		t.Fatalf("got %q, want an unverified-claim caveat prefix", got)
	}
	if !strings.Contains(got, "idor-42") {
		t.Fatalf("got %q, want the finding ID named in the caveat", got)
	}
	if !strings.Contains(got, rationale) {
		t.Fatalf("got %q, want the model's own rationale preserved verbatim, not dropped", got)
	}
}

// TestEvidenceGateText_LowSeverityFinding_OverclaimGetsCaveated is LT-157's
// concrete motivating case: a misconfig-cors finding down-ranked to
// low/medium severity (LT-139, a literal wildcard origin without a real
// reflected-origin confirmation) still shouldn't be described as an
// unqualified compromise, even if Confidence happens to be "high".
func TestEvidenceGateText_LowSeverityFinding_OverclaimGetsCaveated(t *testing.T) {
	f := detectors.Finding{ID: "misconfig-cors", Severity: "low", Confidence: "high"}
	rationale := "any site can access credentials via this wildcard CORS config"
	got := evidenceGateText(f, rationale)
	if !strings.Contains(got, "unverified claim") {
		t.Fatalf("got %q, want an unverified-claim caveat — severity=low doesn't support this certainty", got)
	}
}

func TestEvidenceGateText_EmptyText_PassesThrough(t *testing.T) {
	f := detectors.Finding{ID: "f1", Severity: "low", Confidence: "low"}
	if got := evidenceGateText(f, ""); got != "" {
		t.Fatalf("got %q, want empty string unchanged", got)
	}
}

func TestEvidenceGateText_ZeroValueFinding_PassesThroughUnchanged(t *testing.T) {
	// An unresolved finding_id reference (byID miss) yields a zero-value
	// Finding{} — evidenceGateText must not fabricate a caveat naming an
	// empty ID; the caller-side lookup miss is a separate, already-handled
	// concern (validateRanking/findingsFromDetail).
	rationale := "this is fully exploitable"
	if got := evidenceGateText(detectors.Finding{}, rationale); got != rationale {
		t.Fatalf("got %q, want unchanged for a zero-value Finding (no ID)", got)
	}
}

func TestWeakestFinding_PicksLowestConfidenceThenSeverity(t *testing.T) {
	strong := detectors.Finding{ID: "a", Severity: "critical", Confidence: "high"}
	weak := detectors.Finding{ID: "b", Severity: "low", Confidence: "low"}
	got := weakestFinding([]detectors.Finding{strong, weak})
	if got.ID != "b" {
		t.Fatalf("got %q, want the low-confidence/low-severity finding", got.ID)
	}

	// Same confidence, different severity: severity breaks the tie.
	highSev := detectors.Finding{ID: "c", Severity: "high", Confidence: "high"}
	lowSev := detectors.Finding{ID: "d", Severity: "low", Confidence: "high"}
	got = weakestFinding([]detectors.Finding{highSev, lowSev})
	if got.ID != "d" {
		t.Fatalf("got %q, want the lower-severity finding when confidence ties", got.ID)
	}
}

func TestFindingsFromDetail_SingleAndListReferences(t *testing.T) {
	byID := map[string]detectors.Finding{
		"f1": {ID: "f1"},
		"f2": {ID: "f2"},
	}

	single := findingsFromDetail(map[string]any{"finding_id": "f1"}, byID)
	if len(single) != 1 || single[0].ID != "f1" {
		t.Fatalf("got %+v, want exactly [f1]", single)
	}

	list := findingsFromDetail(map[string]any{"finding_ids": []any{"f1", "f2", "unknown"}}, byID)
	if len(list) != 2 {
		t.Fatalf("got %d ref(s), want 2 (unknown id silently dropped, not errored)", len(list))
	}

	none := findingsFromDetail(map[string]any{"host": "example.com"}, byID)
	if len(none) != 0 {
		t.Fatalf("got %+v, want no references when Detail names neither key", none)
	}
}

func TestTriageFindings_OverclaimingRationaleOnWeakFinding_GetsCaveated(t *testing.T) {
	srv := fakeChatServer(t, `{"ranked":[{"finding_id":"f1","rank":1,"rationale":"higher severity"},{"finding_id":"f2","rank":2,"rationale":"this is fully exploitable and grants full access"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.TriageFindings(context.Background(), sampleFindings())
	if err != nil {
		t.Fatalf("TriageFindings: %v", err)
	}
	var f2Rationale string
	for _, r := range got.Ranked {
		if r.FindingID == "f2" {
			f2Rationale = r.Rationale
		}
	}
	// sampleFindings' f2 is Severity:"low" — doesn't support "fully exploitable".
	if !strings.Contains(f2Rationale, "unverified claim") {
		t.Fatalf("got f2 rationale %q, want an unverified-claim caveat (f2 is low severity)", f2Rationale)
	}
}

func TestSuggest_RunLeafOverclaimingReferencedFinding_GetsCaveated(t *testing.T) {
	srv := fakeChatServer(t, `{"actions":[{"kind":"run_leaf","description":"this is fully exploitable, run it now","detail":{"finding_id":"f2"}}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.Suggest(context.Background(), sampleLedger(), sampleFindings())
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if len(got.Actions) != 1 {
		t.Fatalf("got %+v, want exactly one action", got.Actions)
	}
	// sampleFindings' f2 is Severity:"low" — doesn't support "fully exploitable".
	if !strings.Contains(got.Actions[0].Description, "unverified claim") {
		t.Fatalf("got description %q, want an unverified-claim caveat", got.Actions[0].Description)
	}
}

func TestSuggest_ActionWithNoFindingReference_DescriptionUnaffected(t *testing.T) {
	srv := fakeChatServer(t, `{"actions":[{"kind":"draft_template","description":"this is fully exploitable but nothing to gate against","detail":{"host":"gateway.example.com"}}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.Suggest(context.Background(), sampleLedger(), sampleFindings())
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if len(got.Actions) != 1 || strings.Contains(got.Actions[0].Description, "unverified claim") {
		t.Fatalf("got %+v, want the description untouched — draft_template's detail names no finding_id", got.Actions)
	}
}
