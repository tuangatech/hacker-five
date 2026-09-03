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
// EndpointTemplate specifically — more than one). One stateless call via
// completeBestAvailable — local tier first when reachable, falling back to
// the frontier tier when the local tier is unreachable/unconfigured, or
// when it's reachable but the actual call fails (e.g. the configured model
// isn't pulled — found live, 2026-09-04: a real Ollama server answered
// its reachability probe but 404'd every completion call with "model
// 'llama3.1' not found", and the old local-tier-only design escalated
// outright instead of trying OpenRouter, even with a key configured).
// Reversed from this function's original "local tier only, never worth a
// frontier-tier cost" design (doc15 Step 2) at the user's explicit
// request — same tiered-fallback treatment ResolveLeaf/triage already
// give their own first call, for consistency and because the original
// cost argument doesn't hold once a user has no local tier at all.
func (c *Client) ResolveField(ctx context.Context, detector, field string, candidates []string) (FieldDecision, float64, error) {
	user := fmt.Sprintf("Detector: %s\nField: %s\nCandidates found (%d): %s",
		detector, field, len(candidates), strings.Join(candidates, ", "))

	text, cost, err := c.completeBestAvailable(ctx, fieldSystemPrompt, user)
	if err != nil {
		return FieldDecision{}, cost, err
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
// SuggestedValue or EscalateToHuman set. cost is 0 when the local tier
// resolves it, non-zero when ResolveField fell back to the frontier tier
// (see its own doc comment) — always returned so a spend-tracking caller
// doesn't need a second code path.
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
