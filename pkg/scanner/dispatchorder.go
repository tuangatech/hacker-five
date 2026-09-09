package scanner

import (
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// sortNucleiByDispatchPriority reorders ts in place so that, when a
// --max-target-duration budget or a thinly-shared --rate-limit only lets a
// fraction of the corpus run, the fraction that runs is the useful one.
//
// The loader hands templates back in filepath.WalkDir order, which is
// lexical by path: http/cves/** sorts first and http/misconfiguration/**,
// http/exposures/**, http/default-logins/** sort last. Against an arbitrary
// unauthenticated target that ordering is close to worst-case — it spends
// the whole budget on version-specific CVEs for products the host does not
// run and never reaches a generic misconfiguration/exposure check that
// applies to any host (docs/follow-up.md LT-98 / LT-114).
//
// The nuclei.Template struct carries no per-file path, so priority is keyed
// off what it does carry: info.severity (a budget should spend on
// critical/high before info) and info.tags (a CVE for an unknown stack is
// overwhelmingly a miss, so it goes last within its severity band). The
// sort is stable, so load order is the final tie-break and a corpus with no
// severity/tag signal is left exactly as it arrived.
func sortNucleiByDispatchPriority(ts []*nuclei.Template) {
	sort.SliceStable(ts, func(i, j int) bool {
		return dispatchPrio(ts[i]) < dispatchPrio(ts[j])
	})
}

// dispatchPrio is the sort key: lower dispatches earlier. It is the
// severity band with a +1 nudge for a CVE/vuln-specific template so it
// trails the generic checks in the same band.
func dispatchPrio(t *nuclei.Template) int {
	base := severityBand(t.Info.Severity) * 2
	if isCVEish(t) {
		base++
	}
	return base
}

// severityBand maps a nuclei severity string to a rank. Unknown/empty sorts
// with "info" rather than ahead of it — an unrated template is not a
// high-value one by default.
func severityBand(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info", "":
		return 4
	default: // "unknown" and anything unexpected
		return 5
	}
}

// isCVEish reports whether a template is a specific published-CVE check —
// by an explicit "cve" tag or a CVE-YYYY-N id. These are the templates most
// likely to be dead weight against a target whose stack they do not match,
// so within a severity band they dispatch after the generic checks.
func isCVEish(t *nuclei.Template) bool {
	if id := strings.ToUpper(t.ID); strings.HasPrefix(id, "CVE-") && len(id) > 4 && id[4] >= '0' && id[4] <= '9' {
		return true // the real CVE-YYYY-N id shape, not merely a name beginning "cve-"
	}
	for _, tag := range strings.Split(t.Info.Tags, ",") {
		if strings.EqualFold(strings.TrimSpace(tag), "cve") {
			return true
		}
	}
	return false
}
