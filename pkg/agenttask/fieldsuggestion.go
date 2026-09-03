package agenttask

// FieldSuggestion is a resolved (or escalated) recon-derived config-field
// miss (docs/14-implementation-plan-ph5.md Step 7) — the second I4 caller
// (docs/15-implementation-plan-ph6.md Step 2). Unlike a PlanNode leaf, a
// field suggestion isn't part of the PlanTree's shape: it's a plain string
// destined for a scanner.Config field once approved, never a new tree node
// and never eligible to carry a drafted template.
type FieldSuggestion struct {
	Detector        string   `json:"detector"`                  // e.g. "idor"
	Field           string   `json:"field"`                     // e.g. "endpoint_template"
	SuggestedValue  string   `json:"suggested_value,omitempty"`
	Rationale       string   `json:"rationale,omitempty"`
	Candidates      []string `json:"candidates,omitempty"`       // raw recon-derived candidates, for transparency
	EscalateToHuman string   `json:"escalate_to_human,omitempty"`
}
