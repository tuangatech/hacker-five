// Package reporter formats and writes findings.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// WriteJSON writes findings to w as a JSON array. An empty/nil slice is
// written as "[]", not "null", so downstream JSON consumers never have to
// special-case a no-findings scan.
func WriteJSON(w io.Writer, findings []detectors.Finding) error {
	if findings == nil {
		findings = []detectors.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("writing findings as JSON: %w", err)
	}
	return nil
}
