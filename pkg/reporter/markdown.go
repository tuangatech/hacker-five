package reporter

import (
	"fmt"
	"io"
	"sort"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// severityOrder ranks severities for both the summary table and per-finding
// ordering, most severe first — "critical"/"high"/"medium"/"low" are the
// only values any detector emits (see detectors.Finding's doc comment);
// anything else (a future/unexpected value) sorts last rather than panicking.
var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func severityRank(s string) int {
	if r, ok := severityOrder[s]; ok {
		return r
	}
	return len(severityOrder)
}

// sortBySeverity returns a copy of findings ordered most-to-least severe,
// stable on ties so same-severity findings keep their original order.
func sortBySeverity(findings []detectors.Finding) []detectors.Finding {
	sorted := make([]detectors.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})
	return sorted
}

// severityCounts tallies findings by severity, for both exporters' summary
// sections.
func severityCounts(findings []detectors.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

type markdownExporter struct{}

// Export renders findings as a Markdown report: a summary table by
// severity, then one section per finding (most severe first) with its
// description and evidence in fenced code blocks. Finding.Evidence values
// are written as-is — already redacted at construction time by
// detectors.FormatRequest/FormatResponse (see that package's doc comment on
// redactedHeaders), not re-redacted here.
func (markdownExporter) Export(w io.Writer, findings []detectors.Finding) error {
	if _, err := fmt.Fprintf(w, "# HackerFive Scan Report\n\n%d finding(s)\n\n", len(findings)); err != nil {
		return err
	}
	if len(findings) == 0 {
		return nil
	}

	if _, err := fmt.Fprintln(w, "| Severity | Count |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "|---|---|"); err != nil {
		return err
	}
	counts := severityCounts(findings)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			if _, err := fmt.Fprintf(w, "| %s | %d |\n", sev, n); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	for _, f := range sortBySeverity(findings) {
		if err := writeMarkdownFinding(w, f); err != nil {
			return err
		}
	}
	return nil
}

func writeMarkdownFinding(w io.Writer, f detectors.Finding) error {
	if _, err := fmt.Fprintf(w, "## [%s] %s — %s\n\n", f.Severity, f.Type, f.Target); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "- **ID**: `%s`\n- **Confidence**: %s\n\n", f.ID, f.Confidence); err != nil {
		return err
	}
	if f.Description != "" {
		if _, err := fmt.Fprintf(w, "%s\n\n", f.Description); err != nil {
			return err
		}
	}
	for _, key := range sortedEvidenceKeys(f.Evidence) {
		if _, err := fmt.Fprintf(w, "**%s**\n\n```\n%s\n```\n\n", key, f.Evidence[key]); err != nil {
			return err
		}
	}
	return nil
}

// sortedEvidenceKeys gives deterministic evidence ordering — map iteration
// order isn't, and this output is meant to be diffed/pasted into reports.
func sortedEvidenceKeys(evidence map[string]string) []string {
	keys := make([]string, 0, len(evidence))
	for k := range evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
