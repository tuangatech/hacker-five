// Package detectors defines the types shared by every detector and the reporter.
package detectors

// Finding is a single confirmed or suspected vulnerability, emitted by a detector
// and consumed by the reporter.
type Finding struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`       // "idor", "misconfig", ...
	Severity    string            `json:"severity"`   // "low" | "medium" | "high" | "critical"
	Confidence  string            `json:"confidence"` // "high" (cross-account baseline evidence) | "low" (single-account heuristic, needs manual triage)
	Target      string            `json:"target"`
	Description string            `json:"description"`
	Evidence    map[string]string `json:"evidence"`
}
