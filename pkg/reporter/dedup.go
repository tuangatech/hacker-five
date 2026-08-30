package reporter

import "github.com/tuangatech/hacker-five/pkg/detectors"

// Dedup drops findings whose Finding.ID has already been seen, keeping the
// first occurrence and preserving input order. Scoped to exact-ID duplicates
// only — the same detector/template run against overlapping targets, or a
// worker-pool retry, can legitimately produce the identical ID twice.
// A built-in check and a synced template flagging the same underlying issue
// under two different IDs is a harder semantic-dedup problem, deliberately
// not attempted here (see docs/13-implementation-plan-ph4.md Step 4).
func Dedup(findings []detectors.Finding) []detectors.Finding {
	if len(findings) == 0 {
		return findings
	}
	seen := make(map[string]bool, len(findings))
	out := make([]detectors.Finding, 0, len(findings))
	for _, f := range findings {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out
}
