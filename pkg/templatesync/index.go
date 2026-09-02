package templatesync

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// IndexFile is the on-disk shape of templates/index.json (doc14 Step 3's
// R9) — a thin, timestamped wrapper around List's own already-flattened
// Entry shape. Written by `hackerfive templates index`, read by `hackerfive
// plan`, pkg/webui's plan-preview page, and pkg/mcpserver's
// tools.search/templates.search (doc15 Step 1) — extracted here once a
// third consumer needed the same read logic two independent copies
// (cmd/hackerfive/templates.go, pkg/webui/handlers_plan.go) had each
// duplicated.
type IndexFile struct {
	GeneratedAt time.Time `json:"generated_at"`
	Templates   []Entry   `json:"templates"`
}

// WriteIndex marshals entries into an IndexFile stamped with the current
// time and writes it to path.
func WriteIndex(path string, entries []Entry) error {
	data, err := json.MarshalIndent(IndexFile{GeneratedAt: time.Now().UTC(), Templates: entries}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling template index: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// LoadIndex reads an IndexFile written by WriteIndex, returning its
// flattened Entry list. Callers that can proceed without a template index
// (e.g. `plan`, plan-preview, tools.search) should treat a missing file as
// a soft degrade, not a hard error — mirroring pkg/recon's own "missing
// binary -> warning, not failure" posture.
func LoadIndex(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f IndexFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return f.Templates, nil
}
