package llmfallback

import (
	"context"
	"fmt"
	"strings"
)

const fieldSystemPrompt = `You help resolve an ambiguous or missing recon-derived scanner config field for HackerFive, a defensive security scanner used only against explicitly authorized targets. Given a detector name, a field name, and the recon-derived candidates found (which may be zero or several), pick the single best candidate, or say you're not confident.

Respond with ONLY a JSON object, no other text, matching exactly one of these shapes:
{"suggested_value": "<one of the candidates, or a value clearly derived from them>", "rationale": "<short reason>"}
{"escalate_to_human": "<short reason>"}`

type fieldResponse struct {
	SuggestedValue  string `json:"suggested_value"`
	Rationale       string `json:"rationale"`
	EscalateToHuman string `json:"escalate_to_human"`
}

// ResolveField is I4's second caller: detector/field name and the raw
// candidates a doc14 Step 7 suggester left ambiguous (zero, or — for idor's
// EndpointTemplate specifically — more than one). One stateless local-tier
// call; escalates outright if the local tier isn't configured, since a
// wrong field guess costs nothing worse than a skipped detector run (doc14
// Step 7's own reasoning) and isn't worth a frontier-tier cost.
func (c *Client) ResolveField(ctx context.Context, detector, field string, candidates []string) (FieldDecision, float64, error) {
	if !c.localAvailable {
		return FieldDecision{EscalateToHuman: "no local tier available to resolve this field suggestion"}, 0, nil
	}

	user := fmt.Sprintf("Detector: %s\nField: %s\nCandidates found (%d): %s",
		detector, field, len(candidates), strings.Join(candidates, ", "))

	text, cost, err := c.complete(ctx, tierLocal, fieldSystemPrompt, user)
	if err != nil {
		return FieldDecision{}, 0, err
	}

	var resp fieldResponse
	if err := decodeJSONResponse(text, &resp); err != nil {
		return FieldDecision{}, cost, err
	}
	if resp.SuggestedValue != "" {
		return FieldDecision{SuggestedValue: resp.SuggestedValue, Rationale: resp.Rationale}, cost, nil
	}
	reason := resp.EscalateToHuman
	if reason == "" {
		reason = "model returned neither a suggested_value nor escalate_to_human"
	}
	return FieldDecision{EscalateToHuman: reason}, cost, nil
}

// ResolveFieldMiss wraps ResolveField with the fb==nil/call-failure
// handling every caller needs. Always returns a FieldDecision with either
// SuggestedValue or EscalateToHuman set. cost is always 0 today (field
// resolution is local-tier only, see ResolveField's own doc comment) but
// returned so a spend-tracking caller doesn't need a second code path.
func ResolveFieldMiss(ctx context.Context, fb *Client, fbErr error, detector, field string, candidates []string) (FieldDecision, float64) {
	if fb == nil {
		return FieldDecision{EscalateToHuman: fmt.Sprintf("LLM fallback unavailable (%v)", fbErr)}, 0
	}
	decision, cost, err := fb.ResolveField(ctx, detector, field, candidates)
	if err != nil {
		return FieldDecision{EscalateToHuman: fmt.Sprintf("LLM fallback call failed: %v", err)}, cost
	}
	return decision, cost
}
