package llmfallback

import (
	"context"
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

// plausibilitySystemPrompt frames C7b (doc16 Phase 7 Step 3 /
// docs/follow-up.md LT-49): the deterministic decision engine already
// matched every leaf below to a recon fact it was confident about. This
// pass is the one thing the per-fact rule table structurally can't do —
// notice that the *fact itself* is implausible (a single-page-app catch-all
// that made every path look like a live API route, a CDN/hosting brand
// treated as an installed product) and that a cluster of confident leaves is
// really one weak signal fanned out. It can only demote or drop; it can
// never add a leaf or raise a confidence.
const plausibilitySystemPrompt = `You are HackerFive's plan plausibility reviewer. A deterministic rule engine has already produced the candidate checks below from a recon run, each with a confidence band it assigned. Your ONLY job is to catch checks that rest on an implausible or irrelevant premise — for example:
- the recon "fact" behind it looks fabricated or is an artifact (a single-page-app catch-all route making every path look real; a CDN, hosting, or analytics brand treated as an installed, scannable product)
- many near-identical checks clearly come from one weak signal fanned out
- the check simply does not apply to the stated target/technology

For every check, return exactly one verdict:
- "keep": the premise is sound, leave it as-is
- "demote": plausible but weaker than the engine thought — its confidence should drop one band
- "drop": the premise is implausible or irrelevant — it should not run

You must NOT invent checks, raise any confidence, or change a target/detector. Include every id exactly once.

Respond with ONLY a JSON object, no other text, matching exactly one of these shapes:
{"verdicts": [{"id": "<leaf id>", "action": "keep|demote|drop", "reason": "<short reason>"}, ...]}
{"escalate_to_human": "<short reason you cannot review these>"}`

// LeafVerdict is one plausibility verdict — keyed by an existing leaf ID, so
// this caller can only demote/drop, never add or mutate the leaf's
// target/detector.
type LeafVerdict struct {
	ID     string `json:"id"`
	Action string `json:"action"` // "keep" | "demote" | "drop"
	Reason string `json:"reason"`
}

// PlausibilityResult is VetPendingLeaves' return: a verdict list, or an
// escalation when the model declined to review.
type PlausibilityResult struct {
	Verdicts        []LeafVerdict `json:"verdicts,omitempty"`
	EscalateToHuman string        `json:"escalate_to_human,omitempty"`
}

type plausibilityResponse struct {
	Verdicts        []LeafVerdict `json:"verdicts"`
	EscalateToHuman string        `json:"escalate_to_human"`
}

// VetPendingLeaves is C7b's single classification call: given the tree's
// StatusPending leaves, get back one keep/demote/drop verdict per leaf.
// Local tier first, frontier only if local is unconfigured — same tiering as
// TriageFindings (a reasoning task over structured data, not template
// authoring). costUSD is the cost of the one call (0 on the local tier).
func (c *Client) VetPendingLeaves(ctx context.Context, leaves []*agenttask.PlanNode) (PlausibilityResult, float64, error) {
	if len(leaves) == 0 {
		return PlausibilityResult{}, 0, nil
	}

	text, cost, err := c.completeBestAvailable(ctx, plausibilitySystemPrompt, buildPlausibilityPrompt(leaves))
	if err != nil {
		return PlausibilityResult{}, cost, err
	}

	var resp plausibilityResponse
	if err := decodeJSONResponse(text, &resp); err != nil {
		return PlausibilityResult{}, cost, err
	}
	if resp.EscalateToHuman != "" {
		return PlausibilityResult{EscalateToHuman: resp.EscalateToHuman}, cost, nil
	}
	if err := validateVerdicts(leaves, resp.Verdicts); err != nil {
		return PlausibilityResult{EscalateToHuman: "model returned an invalid verdict set: " + err.Error()}, cost, nil
	}
	return PlausibilityResult{Verdicts: resp.Verdicts}, cost, nil
}

func buildPlausibilityPrompt(leaves []*agenttask.PlanNode) string {
	var b strings.Builder
	for _, leaf := range leaves {
		det := leaf.Detector
		if det == "" {
			det = "(unresolved)"
		}
		fmt.Fprintf(&b, "- id=%s target=%s detector=%s confidence=%s rationale=%q\n",
			leaf.ID, leaf.Target, det, leaf.Confidence, leaf.Rationale)
	}
	return b.String()
}

// validateVerdicts enforces the contract in code, not just the prompt:
// every input leaf id appears exactly once, no unknown id, and every action
// is one of keep/demote/drop.
func validateVerdicts(leaves []*agenttask.PlanNode, verdicts []LeafVerdict) error {
	want := make(map[string]bool, len(leaves))
	for _, l := range leaves {
		want[l.ID] = true
	}
	seen := make(map[string]bool, len(verdicts))
	for _, v := range verdicts {
		if !want[v.ID] {
			return fmt.Errorf("unknown leaf id %q", v.ID)
		}
		if seen[v.ID] {
			return fmt.Errorf("duplicate leaf id %q", v.ID)
		}
		switch v.Action {
		case "keep", "demote", "drop":
		default:
			return fmt.Errorf("leaf %q: unrecognized action %q", v.ID, v.Action)
		}
		seen[v.ID] = true
	}
	if len(seen) != len(want) {
		return fmt.Errorf("verdicts cover %d leaves, expected %d", len(seen), len(want))
	}
	return nil
}

// VetoImplausibleLeaves runs one VetPendingLeaves pass over tree's
// StatusPending leaves and applies the demote/drop verdicts via
// ApplyLeafUpdate (C7b). Shared by cmd/hackerfive's `plan --llm-assist`, the
// MCP plan tool, and pkg/webui's plan-preview resolve action, so this
// orchestration — and its safety posture — is described once:
//
//   - fb may be nil (New() returned ErrNoTierAvailable) — then this is a
//     no-op returning nil, exactly like ResolveTreeLeaves. It is never a
//     hard failure of the plan.
//   - It respects tree.SpendCeilingUSD: skipped entirely once the ceiling is
//     already reached, and the one call's cost is added via tree.AddSpend.
//   - It can only ever weaken the plan — demote lowers a leaf's Confidence
//     one band and prefixes its Rationale; drop flips it to StatusVetoed
//     (kept visible, never dispatched, never re-resolved). It never adds a
//     leaf or raises a confidence.
//
// Returns one human-readable note per demoted/dropped leaf (plus any model
// escalation) for the caller to surface at the approval step.
func VetoImplausibleLeaves(ctx context.Context, fb *Client, fbErr error, tree *agenttask.PlanTree) []string {
	if tree == nil || tree.Root == nil {
		return nil
	}
	var pending []*agenttask.PlanNode
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Status == agenttask.StatusPending {
			pending = append(pending, leaf)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if fb == nil {
		return []string{fmt.Sprintf("plausibility review skipped — LLM fallback unavailable (%v)", fbErr)}
	}
	if tree.SpendCeilingUSD > 0 && tree.SpendSoFar() >= tree.SpendCeilingUSD {
		return []string{"plausibility review skipped — spend ceiling already reached"}
	}

	result, cost, err := fb.VetPendingLeaves(ctx, pending)
	if tree.AddSpend(cost) {
		return []string{"plausibility review: spend ceiling exceeded during the call — verdicts not applied"}
	}
	if err != nil {
		return []string{fmt.Sprintf("plausibility review call failed: %v", err)}
	}
	if result.EscalateToHuman != "" {
		return []string{"plausibility review escalated: " + result.EscalateToHuman}
	}

	var notes []string
	for _, v := range result.Verdicts {
		leaf := tree.Find(v.ID)
		if leaf == nil {
			continue // validated against `pending` already, defensive
		}
		switch v.Action {
		case "demote":
			demoted := agenttask.DemoteConfidence(leaf.Confidence)
			rationale := "plausibility veto (demoted): " + v.Reason + " | " + leaf.Rationale
			_ = tree.ApplyLeafUpdate(v.ID, agenttask.PlanNodePatch{Confidence: &demoted, Rationale: &rationale})
			notes = append(notes, fmt.Sprintf("%s: confidence demoted to %s — %s", v.ID, demoted, v.Reason))
		case "drop":
			vetoed := agenttask.StatusVetoed
			rationale := "plausibility veto (dropped): " + v.Reason + " | " + leaf.Rationale
			_ = tree.ApplyLeafUpdate(v.ID, agenttask.PlanNodePatch{Status: &vetoed, Rationale: &rationale})
			notes = append(notes, fmt.Sprintf("%s: dropped (will not run) — %s", v.ID, v.Reason))
		}
	}
	return notes
}
