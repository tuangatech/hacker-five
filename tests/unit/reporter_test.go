package unit

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

func TestWriteJSON_NilSliceWritesEmptyArray(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, reporter.WriteJSON(&buf, nil))
	assert.JSONEq(t, "[]", buf.String())
}

func TestWriteJSON_PopulatedSliceRoundTrips(t *testing.T) {
	findings := []detectors.Finding{{
		ID:         "misconfig-exposed-path-.env",
		Type:       "misconfig",
		Severity:   "high",
		Confidence: "high",
		Target:     "http://example.com/.env",
		Evidence:   map[string]string{"status": "200"},
	}}

	var buf bytes.Buffer
	require.NoError(t, reporter.WriteJSON(&buf, findings))
	assert.Contains(t, buf.String(), `"id": "misconfig-exposed-path-.env"`)
	assert.Contains(t, buf.String(), `"status": "200"`)
}
