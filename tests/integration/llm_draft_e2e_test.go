//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/registry"
)

// TestLiveLLM_DraftTemplate_LandsInProposedDir closes doc15 Phase 6 Step 5's
// last open DoD line: confirm — against the real OpenRouter frontier tier,
// not a mock — that an I4 "needs_new_template" decision drafts YAML that
// runs through writeProposedTemplate's real nuclei rejection pipeline and
// lands in ./templates-proposed/ (or is cleanly rejected there), and that
// the leaf is only ever left pending/unresolved, never turned into a
// dispatchable detector the plan run would execute.
//
// Gated: needs HACKERFIVE_LIVE_LLM=1 and OPENROUTER_API_KEY. Costs one
// classify + one draft frontier call, bounded by the per-call spend ceiling.
func TestLiveLLM_DraftTemplate_LandsInProposedDir(t *testing.T) {
	if os.Getenv("HACKERFIVE_LIVE_LLM") != "1" {
		t.Skip("set HACKERFIVE_LIVE_LLM=1 (and OPENROUTER_API_KEY) to run the live frontier-tier draft-template check")
	}
	require.NotEmpty(t, os.Getenv("OPENROUTER_API_KEY"), "OPENROUTER_API_KEY must be set for the live frontier tier")

	// writeProposedTemplate writes to "templates-proposed/" relative to cwd.
	t.Chdir(t.TempDir())

	fb, fbErr := llmfallback.New()
	require.NoError(t, fbErr, "llmfallback.New needs a usable tier (frontier here)")

	// A bespoke product with no registry capability and no synced-corpus
	// template — the model's only honest choices are needs_new_template or
	// escalate; the rationale nudges hard toward drafting.
	leaf := &agenttask.PlanNode{
		ID:     "live-draft-acme-widgetproxy",
		Target: "https://example.com",
		Status: agenttask.StatusUnresolved,
		Rationale: `recon tech fact "Acme WidgetProxy 4.2" (a bespoke HTTP reverse proxy that exposes an unauthenticated /widget-status debug endpoint leaking build metadata) ` +
			`matched no registry capability and no existing nuclei template tag; a new targeted detection template is needed`,
	}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	tree.SpendCeilingUSD = llmfallback.PerCallDefaultSpendCeilingUSD() * 4

	escalations := llmfallback.ResolveTreeLeaves(context.Background(), fb, fbErr, tree, registry.Capabilities, nil, nil)
	t.Logf("escalations: %v", escalations)
	t.Logf("leaf after resolve: status=%s detector=%q", leaf.Status, leaf.Detector)
	t.Logf("resolution spend: $%.4f", tree.SpendSoFar())

	// Invariant regardless of the model's choice: a needs_new_template leaf
	// must never become an executable detector leaf.
	require.Empty(t, leaf.Detector, "a drafted-template leaf must not gain a dispatchable Detector")
	require.NotEqual(t, agenttask.StatusPending, leaf.Status, "a drafted-template leaf must not be marked pending/executable")

	entries, _ := os.ReadDir("templates-proposed")
	var proposed []string
	for _, e := range entries {
		proposed = append(proposed, e.Name())
	}

	draftAttempted := len(proposed) > 0
	for _, e := range escalations {
		if strings.Contains(e, "drafted template written to") || strings.Contains(e, "drafted template rejected") {
			draftAttempted = true
		}
	}
	require.True(t, draftAttempted,
		"expected a real frontier draft attempt — a file under templates-proposed/ or a 'drafted template ...' escalation. Got escalations=%v. If the model only escalated, the leaf rationale nudge above needs strengthening.", escalations)

	if len(proposed) > 0 {
		body, err := os.ReadFile(filepath.Join("templates-proposed", proposed[0]))
		require.NoError(t, err)
		t.Logf("landed proposed template %s (%d bytes):\n%s", proposed[0], len(body), body)
		require.Contains(t, string(body), "id:", "a template that passed the load pipeline should look like a nuclei template")
	}
}
