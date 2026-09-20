package llmfallback

import (
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// overclaimPhrases are unhedged, high-certainty exploitability assertions —
// language a model can reach for regardless of what the Finding it's
// describing actually earned through its own detector-set evidence.
// Deliberately a short, hand-curated, case-insensitive substring list so
// this never fires on ordinary hedged risk language ("could expose", "may
// allow", "worth investigating").
var overclaimPhrases = []string{
	"confirmed exploit",
	"fully exploitable",
	"definitely exploitable",
	"trivially exploitable",
	"immediately exploitable",
	"guaranteed",
	"grants full access",
	"full compromise",
	"will allow attackers to",
	"any site can access",
	"always exploitable",
}

var severityRank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
var confidenceRank = map[string]int{"low": 0, "high": 1}

func containsOverclaim(text string) bool {
	lower := strings.ToLower(text)
	for _, p := range overclaimPhrases {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func severityStrongEnough(severity string) bool {
	return severity == "high" || severity == "critical"
}

// evidenceGateText is LT-157's deterministic post-check (docs/follow-up.md):
// llmfallback's own free-text output (TriageFindings' Rationale, Suggest's
// Description) must never assert more certainty than the Finding it's about
// actually earned through its own detector-set Severity/Confidence — the
// only structurally reliable evidence-quality signal available without
// spending another LLM call to re-verify the claim. This deliberately does
// NOT attempt to semantically ground arbitrary free text against a
// Finding's Evidence map (that would need either another model call or a
// fragile per-detector keyword→Evidence-field table); tying the check to
// the two fields doc02 already guarantees are detector-set and
// agent-immutable keeps it deterministic and detector-agnostic. Motivating
// case: a misconfig-cors finding's own down-ranked (low/medium) severity
// and description already say a literal-wildcard-origin response isn't
// exploitable without a real reflected origin — a triage rationale that
// still asserts "any site can access" credentials is overclaiming beyond
// what the detector itself established.
//
// Never rewrites or drops the model's own reasoning — a caveat is prepended
// so a human reading it sees the mismatch, never silently altered text.
func evidenceGateText(f detectors.Finding, text string) string {
	if text == "" || f.ID == "" || !containsOverclaim(text) {
		return text
	}
	if f.Confidence == "high" && severityStrongEnough(f.Severity) {
		return text
	}
	return fmt.Sprintf("[unverified claim — finding %s's own confidence=%q severity=%q do not support this certainty] %s", f.ID, f.Confidence, f.Severity, text)
}

// findingRank orders findings by how much certainty their own detector-set
// fields support — Confidence first (the evidence-quality axis LT-157 cares
// about), Severity as a tiebreaker.
func findingRank(f detectors.Finding) int {
	return confidenceRank[f.Confidence]*10 + severityRank[f.Severity]
}

// weakestFinding returns the finding among refs least able to support
// unhedged certainty language — so a Suggest action naming several findings
// is gated against the one that would least survive independent scrutiny,
// not the strongest. Panics on an empty slice; every call site only invokes
// this after confirming refs is non-empty.
func weakestFinding(refs []detectors.Finding) detectors.Finding {
	weakest := refs[0]
	for _, f := range refs[1:] {
		if findingRank(f) < findingRank(weakest) {
			weakest = f
		}
	}
	return weakest
}

// findingsFromDetail resolves a Suggest action's Detail-referenced finding
// IDs ("finding_id" for a single reference, "finding_ids" for
// triage_group's list — LT-139's array shape) against the input findings
// this call actually saw. An unknown or malformed reference resolves to
// nothing rather than erroring the whole action — the same "degrade, never
// fabricate" contract validSuggestedActions already applies to Kind.
func findingsFromDetail(detail map[string]any, byID map[string]detectors.Finding) []detectors.Finding {
	var refs []detectors.Finding
	if id, ok := detail["finding_id"].(string); ok {
		if f, ok := byID[id]; ok {
			refs = append(refs, f)
		}
	}
	if raw, ok := detail["finding_ids"].([]any); ok {
		for _, v := range raw {
			id, ok := v.(string)
			if !ok {
				continue
			}
			if f, ok := byID[id]; ok {
				refs = append(refs, f)
			}
		}
	}
	return refs
}
