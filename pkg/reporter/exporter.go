package reporter

import (
	"fmt"
	"io"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

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
