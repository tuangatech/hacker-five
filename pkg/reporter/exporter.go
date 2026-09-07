package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// ValidateCitations rejects any citedIDs that name no finding in findings —
// the C3 evidence-linked-claim gate (doc16 Phase 7 Step 3). Agent-drafted
// report text (via findings.export, or any future report-drafting surface)
// may only cite a Finding.ID that actually exists in the job's finding set;
// enforcing it here, at the exporter boundary, makes it a hard guarantee
// rather than prompt discipline. An empty citedIDs is always valid — a
// caller that claims nothing cites nothing.
func ValidateCitations(citedIDs []string, findings []detectors.Finding) error {
	if len(citedIDs) == 0 {
		return nil
	}
	present := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		present[f.ID] = struct{}{}
	}
	var missing []string
	for _, id := range citedIDs {
		if _, ok := present[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("evidence-linked-claim check: cited finding ID(s) not present in the finding set: %s", strings.Join(missing, ", "))
	}
	return nil
}

// Exporter renders a full set of findings to w in one particular output
// format.
type Exporter interface {
	Export(w io.Writer, findings []detectors.Finding) error
}

// jsonExporter adapts the existing, independently-tested WriteJSON to the
// Exporter interface without changing its signature or risking its existing
// tests.
type jsonExporter struct{}

func (jsonExporter) Export(w io.Writer, findings []detectors.Finding) error {
	return WriteJSON(w, findings)
}

// ExporterFor resolves a --format value to its Exporter. "json" is the
// default (scanner.Config.OutputFormat's existing default) and always
// recognized even though it predates this file.
func ExporterFor(format string) (Exporter, error) {
	switch format {
	case "", "json":
		return jsonExporter{}, nil
	case "markdown":
		return markdownExporter{}, nil
	case "html":
		return htmlExporter{}, nil
	case "hackerone-json":
		return hackerOneJSONExporter{}, nil
	default:
		return nil, fmt.Errorf(`unknown output format %q (want "json", "markdown", "html", or "hackerone-json")`, format)
	}
}
