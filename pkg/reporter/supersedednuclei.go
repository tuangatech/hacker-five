package reporter

import (
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// supersededNucleiTemplates maps a nuclei template ID to the native
// Finding.ID that already grades the identical signal (LT-6 tail,
// docs/follow-up.md). Unlike the `http-missing-security-headers` aggregate
// (SplitAggregates), each of these is already a single, distinct nuclei
// finding — no split is needed, the nuclei duplicate is just dropped for any
// target where the native counterpart also fired (native wins: real
// severity + request/response evidence). Add an entry here, not a new
// SplitAggregates case, for any future 1:1 native/nuclei pair that isn't an
// aggregate.
var supersededNucleiTemplates = map[string]string{
	"weak-hsts-detect": "misconfig-weak-hsts-max-age", // LT-47
}

// DropSupersededNucleiFindings drops a nuclei finding whose template is
// listed in supersededNucleiTemplates when the same target already carries
// the corresponding native finding. Order-preserving; run it (like
// SplitAggregates) before Dedup, since it matches on a template-ID prefix,
// not an exact duplicate ID.
func DropSupersededNucleiFindings(findings []detectors.Finding) []detectors.Finding {
	nativeSeen := make(map[string]map[string]bool, len(findings)) // target -> native Finding.IDs present
	for _, f := range findings {
		if nativeSeen[f.Target] == nil {
			nativeSeen[f.Target] = make(map[string]bool)
		}
		nativeSeen[f.Target][f.ID] = true
	}

	out := make([]detectors.Finding, 0, len(findings))
	for _, f := range findings {
		if superseded(f, nativeSeen[f.Target]) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func superseded(f detectors.Finding, nativeIDs map[string]bool) bool {
	for tmplID, nativeID := range supersededNucleiTemplates {
		prefix := "nuclei-" + tmplID
		if f.ID == prefix || strings.HasPrefix(f.ID, prefix+"-") {
			return nativeIDs[nativeID]
		}
	}
	return false
}
