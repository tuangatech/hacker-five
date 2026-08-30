package unit

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

func sampleFindings() []detectors.Finding {
	return []detectors.Finding{
		{
			ID:          "ssrf-scheme-based-url-file",
			Type:        "ssrf",
			Severity:    "high",
			Confidence:  "high",
			Target:      "http://example.com/serversurfer?url=file:///etc/passwd",
			Description: "The target fetched a file:// URL, disclosing local file contents.",
			Evidence: map[string]string{
				"request":  "GET /serversurfer?url=file:///etc/passwd HTTP/1.1",
				"response": "HTTP 200\n\nroot:x:0:0",
			},
		},
		{
			ID:         "misconfig-exposed-path-.env",
			Type:       "misconfig",
			Severity:   "medium",
			Confidence: "high",
			Target:     "http://example.com/.env",
			Evidence:   map[string]string{"status": "200"},
		},
	}
}

func TestMarkdownExporter_ContainsSeverityCountsAndFindingSections(t *testing.T) {
	exporter, err := reporter.ExporterFor("markdown")
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, exporter.Export(&buf, sampleFindings()))
	out := buf.String()

	assert.Contains(t, out, "2 finding(s)")
	assert.Contains(t, out, "| high | 1 |")
	assert.Contains(t, out, "| medium | 1 |")
	assert.Contains(t, out, "ssrf-scheme-based-url-file")
	assert.Contains(t, out, "file:///etc/passwd")
}

func TestMarkdownExporter_EmptyFindingsStillProducesHeader(t *testing.T) {
	exporter, err := reporter.ExporterFor("markdown")
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, exporter.Export(&buf, nil))
	assert.Contains(t, buf.String(), "0 finding(s)")
}

func TestExporterFor_UnknownFormatErrors(t *testing.T) {
	_, err := reporter.ExporterFor("pdf")
	require.Error(t, err)
}
