package llmfallback

import (
	"context"
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/coveragegap"
	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// suggestActionKinds is the fixed allow-list Suggest validates every
// returned action against — the five kinds named in
// docs/16-implementation-plan-ph7.md Step 7's design table. An unknown kind
// is dropped, never trusted through.
var suggestActionKinds = map[string]bool{
	"draft_template":  true,
	"run_leaf":        true,
	"redo_recon":      true,
	"correlate_hosts": true,
	"triage_group":    true,
}

const suggestSystemPrompt = `You help a human security researcher decide what to do next after a HackerFive scan. You are given two inputs: a coverage-gap ledger (host/product pairs recon fingerprinted that no detector or template actually checked) and the scan's findings (id, type, severity, confidence, target, description only — never raw request/response bodies). Propose a list of concrete next actions. You never apply any action yourself — this is a printed proposal only, read by a human.

Each action's "kind" must be exactly one of: "draft_template" (a ledger row nothing covers — propose drafting a template for it), "run_leaf" (a finding suggests a specific second-pass check, e.g. a disclosed admin path or version banner), "redo_recon" (the ledger shows a thin endpoint surface — recon should be re-run with different parameters), "correlate_hosts" (the same product/version fingerprinted on multiple hosts — group them), "triage_group" (findings that belong together in a report draft). Never invent a kind outside this list, never invent a finding_id or host not present in the input.

Respond with ONLY a JSON object, no other text, matching exactly:
{"actions": [{"kind": "<kind>", "description": "<short reason>", "detail": {"<key>": "<value>"}}, ...]}`

type suggestResponse struct {
	Actions []SuggestedAction `json:"actions"`
}

// Suggest is I4's fourth caller: one stateless frontier-tier call (LT-108,
// docs/16-implementation-plan-ph7.md Step 7 rung 2) over LT-107's
// coverage-gap ledger plus a completed scan's findings. Mirrors
// TriageFindings' shape exactly: a no-op on empty input, and a
// malformed/out-of-contract model response degrades to an empty action
// list rather than a fabricated one.
func (c *Client) Suggest(ctx context.Context, ledger []coveragegap.GapRow, findings []detectors.Finding) (SuggestResult, float64, error) {
	if len(ledger) == 0 && len(findings) == 0 {
		return SuggestResult{}, 0, nil
	}

	user := buildSuggestPrompt(ledger, findings)
	text, cost, err := c.completeBestAvailable(ctx, suggestSystemPrompt, user)
	if err != nil {
		return SuggestResult{}, cost, err
	}

	var resp suggestResponse
	if err := decodeJSONResponse(text, &resp); err != nil {
		return SuggestResult{}, cost, err
	}
	return SuggestResult{Actions: validSuggestedActions(resp.Actions)}, cost, nil
}

func buildSuggestPrompt(ledger []coveragegap.GapRow, findings []detectors.Finding) string {
	var b strings.Builder
	b.WriteString("coverage gaps:\n")
	for _, row := range ledger {
		fmt.Fprintf(&b, "- host=%s product=%q reason=%s\n", row.Host, row.Product, row.Reason)
	}
	b.WriteString("findings:\n")
	for _, f := range findings {
		fmt.Fprintf(&b, "- id=%s type=%s severity=%s confidence=%s target=%s description=%q\n",
			f.ID, f.Type, f.Severity, f.Confidence, f.Target, f.Description)
	}
	return b.String()
}

// validSuggestedActions drops (never trusts through) any action whose kind
// falls outside suggestActionKinds — same "degrade, never fabricate"
// contract validateRanking enforces for TriageFindings.
func validSuggestedActions(actions []SuggestedAction) []SuggestedAction {
	var valid []SuggestedAction
	for _, a := range actions {
		if suggestActionKinds[a.Kind] {
			valid = append(valid, a)
		}
	}
	return valid
}
