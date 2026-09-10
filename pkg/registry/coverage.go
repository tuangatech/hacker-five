package registry

import "github.com/tuangatech/hacker-five/pkg/templatesync"

// CoverageStatus reports, for a fingerprinted tech name, the same two match
// signals resolveTechFact already computes when building a PlanTree —
// whether any native-detector rule and/or loaded template tag would match it
// — standalone for pkg/coveragegap's end-of-scan gap ledger (LT-107,
// docs/16-implementation-plan-ph7.md Step 7). Never reimplements
// matchTechRules/matchTemplateTags; a nonActionableTech entry legitimately
// produces no leaf at all and must not be reported as an uncovered gap.
func CoverageStatus(techName string, templateIndex []templatesync.Entry) (hasNative, hasTemplate, nonActionable bool) {
	if nonActionableTech[NormalizeTechName(techName)] {
		return false, false, true
	}
	return len(matchTechRules(techName)) > 0, len(matchTemplateTags(techName, templateIndex)) > 0, false
}
