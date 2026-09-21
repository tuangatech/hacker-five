package eval

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/coverage"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/orchestrator"
)

// streamOf renders res the way `hackerfive agent` does (a "result" event), so
// the test exercises the real JSON shape rather than a hand-written copy of it.
func streamOf(t *testing.T, res orchestrator.Result) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		Type   string               `json:"type"`
		Result *orchestrator.Result `json:"result"`
	}{"result", &res})
	require.NoError(t, err)
	return append(raw, '\n')
}

func attributionFixture() orchestrator.Result {
	idor := &agenttask.PlanNode{ID: "idor-1", Target: "t.example", Detector: "idor", Status: agenttask.StatusDone, EndpointTemplate: "/workshop/api/mechanic/mechanic_report?report_id={{id}}"}
	auth := &agenttask.PlanNode{ID: "auth-1", Target: "t.example", Detector: "authbypass", Status: agenttask.StatusPending}
	return orchestrator.Result{
		Tree: &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{idor, auth}}},
		History: []llmfallback.TurnRecord{
			{Action: llmfallback.Action{Kind: "scan.leaf", NodeID: "idor-1"}, ResultSummary: "9 new finding(s) [...]", Auto: true},
			{Action: llmfallback.Action{Kind: "scan.leaf", NodeID: "auth-1"}, ResultSummary: "skipped: auth-1: missing required field ProtectedPaths", Auto: true},
		},
		Findings: []detectors.Finding{{ID: "idor-x", Target: "https://t.example/workshop/api/mechanic/mechanic_report?report_id=3"}},
		Recon: []coverage.Endpoint{
			{Method: "GET", URL: "https://t.example/workshop/api/mechanic/mechanic_report?report_id="},
			{Method: "GET", URL: "https://t.example/api/me"},
			{Method: "GET", URL: "https://t.example/static/app.js"},
		},
	}
}

var attributionKnown = []KnownVuln{
	{ID: "bola-mechanic", IDPrefixes: []string{"idor-"}, EndpointContains: "/mechanic_report"},
	{ID: "bola-orders", IDPrefixes: []string{"idor-"}, EndpointContains: "/shop/orders/"},
	{ID: "jwt", IDPrefixes: []string{"authbypass-jwt-"}},
	{ID: "bfla-delete", IDPrefixes: []string{"mutatebfla-"}, EndpointContains: "/video/delete/", Gated: "needs an operator flag"},
}

func TestAddAttribution_RoundTripsTheAgentStreamAndNamesTheStage(t *testing.T) {
	parsed, err := ParseAgentStream(streamOf(t, attributionFixture()))
	require.NoError(t, err)
	require.True(t, parsed.SawResult)

	rec := NewRunRecord("lab", "arm", 1, parsed, GradeRun(parsed.Findings, nil, attributionKnown), 1, "")
	rec.AddAttribution(parsed, attributionKnown)

	assert.Equal(t, map[string]string{
		"bola-mechanic": "7-found",
		"bola-orders":   "0-not-observed",
		"jwt":           "2-blocked",
		"bfla-delete":   "6-gated",
	}, rec.KnownStages)
	assert.Contains(t, rec.KnownWhy["jwt"], "ProtectedPaths", "the skip reason must reach the record")
	assert.Equal(t, 3, rec.ReconEndpoints)
	assert.Equal(t, map[string]int{"7-found": 1, "1-no-leaf": 1}, rec.EndpointStages, "the static asset is excluded, the covered endpoint has a finding, /api/me has no leaf")
	assert.Equal(t, []string{"idor-x https://t.example/workshop/api/mechanic/mechanic_report?report_id=3"}, rec.FindingIDs)
}

func TestAddAttribution_SkipsARunThatNeverProducedAResult(t *testing.T) {
	rec := RunRecord{}
	rec.AddAttribution(ParsedRun{Findings: []detectors.Finding{{ID: "idor-1"}}}, attributionKnown)
	assert.Nil(t, rec.KnownStages, "without a tree and history every miss would read as no-leaf, a claim the run cannot support")
}

func TestFormatMissAttribution_ShowsStagePerVulnAndAMeanPerStage(t *testing.T) {
	mk := func(stage string) RunRecord {
		return RunRecord{Lab: "lab", Arm: "arm", Model: "m", KnownStages: map[string]string{"v1": stage, "v2": "1-no-leaf"}, KnownWhy: map[string]string{"v1": "why", "v2": "why2"}}
	}
	out := FormatMissAttribution([]RunRecord{mk("1-no-leaf"), mk("4-no-finding"), {Lab: "lab", Arm: "other"}})
	assert.Contains(t, out, "lab / arm [m] (2 run(s))")
	assert.Contains(t, out, "1-no-leaf x1, 4-no-finding x1", "a vulnerability that landed at different stages across runs is shown as a split")
	assert.Contains(t, out, "lost at (mean vulns per run): 1-no-leaf 1.5, 4-no-finding 0.5")
	assert.False(t, strings.Contains(out, "other"), "an arm with no attribution is left out")
}

func TestShippedCrapiFixtureMarksTheGatedEntry(t *testing.T) {
	kf, err := LoadKnownVulns("../fixtures/known-vulns/crapi.json")
	require.NoError(t, err)
	for _, v := range kf.Vulns {
		if v.ID == "crapi-bfla-delete-video" {
			assert.NotEmpty(t, v.Gated)
			return
		}
	}
	t.Fatal("crapi-bfla-delete-video not found")
}
