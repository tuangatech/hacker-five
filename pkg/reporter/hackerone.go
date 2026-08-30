package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// hackerOneDraftFinding is a best-effort, offline mapping of a Finding onto
// HackerOne's report_intent create-request shape (see pkg/hackerone for the
// live API client that actually creates one). No network access, no API
// token needed — usable standalone, e.g. for manual copy-paste into
// HackerOne's report form, per docs/13-implementation-plan-ph4.md Step 4.
//
// TeamHandle/WeaknessID/StructuredScopeID cannot be derived from a Finding
// alone — they're numeric, program-specific IDs HackerOne assigns per
// program (see pkg/hackerone.Client.ListWeaknesses/ListStructuredScopes) —
// so they're left zero-valued with a NeedsReview note rather than guessed.
type hackerOneDraftFinding struct {
	SourceFindingID         string   `json:"_source_finding_id"`
	NeedsReview             []string `json:"_needs_review"`
	Title                   string   `json:"title"`
	VulnerabilityInformation string  `json:"vulnerability_information"`
	SeverityRating          string   `json:"severity_rating"`
	TeamHandle              string   `json:"team_handle"`
	WeaknessID              int      `json:"weakness_id"`
	StructuredScopeID       int      `json:"structured_scope_id"`
}

// HackerOneSeverityRating maps Finding.Severity's four values directly onto
// HackerOne's severity_rating enum (none|low|medium|high|critical) — the
// two scales already agree on low/medium/high/critical, so this is a
// same-name pass-through, not a real translation table. Exported so
// cmd/hackerfive/report.go's `report create` can reuse the same mapping
// against a live finding rather than duplicating it.
func HackerOneSeverityRating(severity string) string {
	switch severity {
	case "critical", "high", "medium", "low":
		return severity
	default:
		return "none"
	}
}

// HackerOneVulnerabilityInformation renders a Finding's description and
// evidence as the free-text body HackerOne's report_intent
// vulnerability_information field expects. Exported for the same reason as
// HackerOneSeverityRating above.
func HackerOneVulnerabilityInformation(f detectors.Finding) string {
	var b strings.Builder
	if f.Description != "" {
		b.WriteString(f.Description)
		b.WriteString("\n\n")
	}
	for _, key := range sortedEvidenceKeys(f.Evidence) {
		fmt.Fprintf(&b, "## %s\n\n```\n%s\n```\n\n", key, f.Evidence[key])
	}
	return strings.TrimSpace(b.String())
}

func toHackerOneDraft(f detectors.Finding) hackerOneDraftFinding {
	return hackerOneDraftFinding{
		SourceFindingID:          f.ID,
		NeedsReview:              []string{"team_handle", "weakness_id", "structured_scope_id"},
		Title:                    fmt.Sprintf("%s: %s", f.Type, f.Target),
		VulnerabilityInformation: HackerOneVulnerabilityInformation(f),
		SeverityRating:           HackerOneSeverityRating(f.Severity),
	}
}

type hackerOneJSONExporter struct{}

// Export writes findings as a JSON array of hackerOneDraftFinding objects.
// This never talks to HackerOne's API — see pkg/hackerone for the client
// that does, and cmd/hackerfive/report.go for the CLI command that actually
// creates a live draft report_intent from one of these.
func (hackerOneJSONExporter) Export(w io.Writer, findings []detectors.Finding) error {
	drafts := make([]hackerOneDraftFinding, 0, len(findings))
	for _, f := range sortBySeverity(findings) {
		drafts = append(drafts, toHackerOneDraft(f))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(drafts); err != nil {
		return fmt.Errorf("writing findings as hackerone-json: %w", err)
	}
	return nil
}
