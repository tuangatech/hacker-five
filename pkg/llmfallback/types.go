// Package llmfallback is the tiered, stateless LLM client
// docs/15-implementation-plan-ph6.md Step 2 (I4, doc90 Decision 5/6) calls
// on a confirmed deterministic-decision-engine miss — never as a standing
// parallel path. Every exported method is one input->output call: no
// conversation state is carried between calls, no session held open.
//
// Deliberately a plain net/http + encoding/json client, not an SDK — both
// OpenRouter and a local Ollama-style runtime expose an OpenAI-chat-
// completions-compatible REST endpoint (docs/02-architecture-and-tech-
// stack.md §8), so one small client covers both tiers without a new go.mod
// dependency (the interactsh-client lesson: verify the real footprint
// before adding weight, and here a raw REST call needs none at all).
package llmfallback

// LeafDecision is I4's first caller's result — resolving an
// agenttask.StatusUnresolved PlanTree leaf. Exactly one of the three fields
// is set.
type LeafDecision struct {
	// UseExistingTag names a real template tag/detector already present in
	// the synced corpus or registry.Capabilities — the leaf becomes
	// runnable immediately, no human promotion needed.
	UseExistingTag string `json:"use_existing_tag,omitempty"`
	// DraftTemplate is a full nuclei-compatible YAML template body for a
	// gap nothing in the corpus covers. Untrusted input: the caller must
	// run it through pkg/template/nuclei's checkDisallowedBlocks before
	// writing it to templates/proposed/, and the leaf it came from is never
	// executed by this step's executor — only a human promoting it out of
	// templates/proposed/ makes it eligible to run.
	DraftTemplate string `json:"draft_template,omitempty"`
	// EscalateToHuman means neither of the above applies — surfaced to the
	// human as-is at the elicitation step, never auto-resolved further.
	EscalateToHuman string `json:"escalate_to_human,omitempty"`
}

// FieldDecision is I4's second caller's result — resolving a doc14 Step 7
// recon-derived field-suggestion miss (currently only idor's
// EndpointTemplate: 0 or >1 candidates with no safe auto-pick). Never a
// draft_template shape — a field suggestion is a plain string slotted into
// an already-Validate()-checked scanner.Config field, not a new template.
type FieldDecision struct {
	SuggestedValue  string `json:"suggested_value,omitempty"`
	Rationale       string `json:"rationale,omitempty"`
	EscalateToHuman string `json:"escalate_to_human,omitempty"`
}

// RankedFinding is one entry in a TriageResult — never carries anything
// beyond a rank/rationale keyed by an existing Finding.ID, so this caller
// can only reorder/annotate, never mutate a Finding itself.
type RankedFinding struct {
	FindingID string `json:"finding_id"`
	Rank      int    `json:"rank"`
	Rationale string `json:"rationale"`
}

// TriageResult is I4's third caller's result — post-scan finding
// prioritization on a completed job's real Finding list.
type TriageResult struct {
	Ranked          []RankedFinding `json:"ranked,omitempty"`
	EscalateToHuman string          `json:"escalate_to_human,omitempty"`
}
