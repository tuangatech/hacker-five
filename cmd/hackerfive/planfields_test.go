package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

func treeWith(detectors ...string) *agenttask.PlanTree {
	root := &agenttask.PlanNode{ID: "root", Target: "https://example.com"}
	for i, d := range detectors {
		root.Children = append(root.Children, &agenttask.PlanNode{
			ID:       string(rune('a'+i)) + "-leaf",
			Target:   "https://example.com",
			Detector: d,
		})
	}
	return &agenttask.PlanTree{Root: root}
}

func reconWith(endpoints ...recon.EndpointFact) *recon.ReconResult {
	return &recon.ReconResult{Target: "https://example.com", Endpoints: endpoints}
}

func TestPlanLeafDetectors(t *testing.T) {
	got := planLeafDetectors(treeWith("idor", "misconfig", "idor"))
	assert.True(t, got["idor"])
	assert.True(t, got["misconfig"])
	assert.False(t, got["ssrf"])
	assert.Empty(t, planLeafDetectors(nil))
}

// Without --llm-assist a genuine miss is surfaced as an advisory
// escalate-to-human note, and no model call is attempted.
func TestPlanFieldSuggestions_MissWithoutLLMAssist_AdvisoryOnly(t *testing.T) {
	r := reconWith(recon.EndpointFact{URL: "https://example.com/about"})
	tree := treeWith("idor")
	var stderr bytes.Buffer

	sugs := planFieldSuggestions(context.Background(), r, tree, false, nil, nil, &stderr)

	require.Len(t, sugs, 1)
	assert.Equal(t, "idor", sugs[0].Detector)
	assert.NotEmpty(t, sugs[0].EscalateToHuman)
	assert.Contains(t, sugs[0].EscalateToHuman, "--llm-assist")
	assert.Equal(t, float64(0), tree.SpendSoFar(), "no model call, no spend")
}

func TestPlanFieldSuggestions_DeterministicAutoFill(t *testing.T) {
	r := reconWith(recon.EndpointFact{URL: "https://example.com/api/report?report_id=482"})
	tree := treeWith("idor")
	var stderr bytes.Buffer

	sugs := planFieldSuggestions(context.Background(), r, tree, false, nil, nil, &stderr)

	require.Len(t, sugs, 1)
	assert.Equal(t, "/api/report?report_id={{id}}", sugs[0].SuggestedValue)
	assert.Empty(t, sugs[0].EscalateToHuman)
}

func TestApplyReconFieldSuggestion_ExplicitFlagWins(t *testing.T) {
	cfg := scanner.Config{EndpointTemplate: "/set/by/flag?id={{id}}"}
	applied, _ := applyReconFieldSuggestion(&cfg, agenttask.FieldSuggestion{
		Field: "endpoint_template", SuggestedValue: "/from/recon?id={{id}}",
	})
	assert.False(t, applied)
	assert.Equal(t, "/set/by/flag?id={{id}}", cfg.EndpointTemplate)
}

func TestApplyReconFieldSuggestion_FillsWhenUnset(t *testing.T) {
	cfg := scanner.Config{}

	applied, value := applyReconFieldSuggestion(&cfg, agenttask.FieldSuggestion{
		Field: "endpoint_template", SuggestedValue: "/from/recon?id={{id}}",
	})
	assert.True(t, applied)
	assert.Equal(t, "/from/recon?id={{id}}", value)
	assert.Equal(t, "/from/recon?id={{id}}", cfg.EndpointTemplate)

	applied, _ = applyReconFieldSuggestion(&cfg, agenttask.FieldSuggestion{
		Field: "protected_paths", Candidates: []string{"/admin", "/settings"},
	})
	assert.True(t, applied)
	assert.Equal(t, []string{"/admin", "/settings"}, cfg.ProtectedPaths)

	applied, _ = applyReconFieldSuggestion(&cfg, agenttask.FieldSuggestion{
		Field: "ssrf_params", Candidates: []string{"url"},
	})
	assert.True(t, applied)
	assert.Equal(t, []string{"url"}, cfg.SSRFParams)
}

func TestApplyReconFieldSuggestion_EmptySuggestionNoOp(t *testing.T) {
	cfg := scanner.Config{}
	applied, _ := applyReconFieldSuggestion(&cfg, agenttask.FieldSuggestion{Field: "ssrf_params"})
	assert.False(t, applied)
	assert.Nil(t, cfg.SSRFParams)
}
