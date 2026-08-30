package unit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/reporter"
)

// hackerOneDraftFinding mirrors pkg/reporter's unexported type just enough
// to decode the exporter's output for assertions — this test is
// intentionally black-box (package unit), matching every other exporter
// test in this file/directory.
type hackerOneDraftFinding struct {
	SourceFindingID          string   `json:"_source_finding_id"`
	NeedsReview              []string `json:"_needs_review"`
	Title                    string   `json:"title"`
	VulnerabilityInformation string   `json:"vulnerability_information"`
	SeverityRating           string   `json:"severity_rating"`
	TeamHandle               string   `json:"team_handle"`
	WeaknessID               int      `json:"weakness_id"`
	StructuredScopeID        int      `json:"structured_scope_id"`
}

func TestHackerOneJSONExporter_MapsSeverityAndFlagsFieldsNeedingReview(t *testing.T) {
	exp, err := reporter.ExporterFor("hackerone-json")
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, exp.Export(&buf, sampleFindings()))

	var drafts []hackerOneDraftFinding
	require.NoError(t, json.Unmarshal(buf.Bytes(), &drafts))
	require.Len(t, drafts, 2)

	// sampleFindings' high-severity finding sorts first.
	assert.Equal(t, "ssrf-scheme-based-url-file", drafts[0].SourceFindingID)
	assert.Equal(t, "high", drafts[0].SeverityRating)
	assert.Contains(t, drafts[0].VulnerabilityInformation, "file:///etc/passwd")
	assert.Contains(t, drafts[0].NeedsReview, "weakness_id")
	assert.Contains(t, drafts[0].NeedsReview, "structured_scope_id")
	assert.Contains(t, drafts[0].NeedsReview, "team_handle")
	assert.Equal(t, 0, drafts[0].WeaknessID)
}

func TestHackerOneJSONExporter_EmptyFindingsWritesEmptyArray(t *testing.T) {
	exp, err := reporter.ExporterFor("hackerone-json")
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, exp.Export(&buf, nil))
	assert.JSONEq(t, "[]", buf.String())
}
