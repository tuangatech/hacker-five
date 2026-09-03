package llmfallback

import (
	"context"
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

const triageSystemPrompt = `You help a human security researcher decide which findings from a completed HackerFive scan are worth writing up first. You are given a list of findings (id, type, severity, confidence, target, description only — never raw request/response bodies). Rank every finding from most to least worth investigating first, and give a short rationale for each. You must include every finding_id exactly once. You never invent a finding that isn't in the input, and you never change any finding's severity or confidence — ranking only.

Respond with ONLY a JSON object, no other text, matching exactly one of these shapes:
{"ranked": [{"finding_id": "<id>", "rank": 1, "rationale": "<short reason>"}, ...]}
{"escalate_to_human": "<short reason you can't produce a ranking>"}`

type triageResponse struct {
	Ranked          []RankedFinding `json:"ranked"`
	EscalateToHuman string          `json:"escalate_to_human"`
}

// TriageFindings is I4's third caller: given a completed job's real
// findings, get back a ranking only — never a mutation of the input list.
// Local tier first, frontier only if local is unconfigured, mirroring
// ResolveLeaf's classification-call tiering (this is a reasoning task over
// structured data, not template authoring, so it doesn't need the
// frontier-only draft-authoring treatment ResolveLeaf reserves for that
// specific case).
func (c *Client) TriageFindings(ctx context.Context, findings []detectors.Finding) (TriageResult, float64, error) {
	if len(findings) == 0 {
		return TriageResult{}, 0, nil
	}

	user := buildTriagePrompt(findings)
	text, cost, err := c.completeBestAvailable(ctx, triageSystemPrompt, user)
	if err != nil {
		return TriageResult{}, 0, err
	}

	var resp triageResponse
	if err := decodeJSONResponse(text, &resp); err != nil {
		return TriageResult{}, cost, err
	}
	if resp.EscalateToHuman != "" {
		return TriageResult{EscalateToHuman: resp.EscalateToHuman}, cost, nil
	}
	if err := validateRanking(findings, resp.Ranked); err != nil {
		return TriageResult{EscalateToHuman: "model returned an invalid ranking: " + err.Error()}, cost, nil
	}
	return TriageResult{Ranked: resp.Ranked}, cost, nil
}

func buildTriagePrompt(findings []detectors.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "- id=%s type=%s severity=%s confidence=%s target=%s description=%q\n",
			f.ID, f.Type, f.Severity, f.Confidence, f.Target, f.Description)
	}
	return b.String()
}

// validateRanking enforces TriageFindings' own contract in code, not just
// in the prompt: every input finding_id must appear exactly once, and no
// finding_id outside the input is allowed — a model deviating from
// instructions must be caught here, not trusted.
func validateRanking(findings []detectors.Finding, ranked []RankedFinding) error {
	want := make(map[string]bool, len(findings))
	for _, f := range findings {
		want[f.ID] = true
	}
	seen := make(map[string]bool, len(ranked))
	for _, r := range ranked {
		if !want[r.FindingID] {
			return fmt.Errorf("unknown finding_id %q", r.FindingID)
		}
		if seen[r.FindingID] {
			return fmt.Errorf("duplicate finding_id %q", r.FindingID)
		}
		seen[r.FindingID] = true
	}
	if len(seen) != len(want) {
		return fmt.Errorf("ranked %d findings, expected %d", len(seen), len(want))
	}
	return nil
}
