package unit

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

func TestHTMLExporter_EscapesEvidenceContainingHTML(t *testing.T) {
	exporter, err := reporter.ExporterFor("html")
	require.NoError(t, err)

	findings := []detectors.Finding{{
		ID:       "xss-reflected",
		Type:     "xss",
		Severity: "high",
		Target:   "http://example.com/search?q=<script>alert(1)</script>",
		Evidence: map[string]string{
			"response": "<script>alert(1)</script>",
		},
	}}

	var buf bytes.Buffer
	require.NoError(t, exporter.Export(&buf, findings))
	out := buf.String()

	assert.NotContains(t, out, "<script>alert(1)</script>")
	assert.Contains(t, out, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestHTMLExporter_ProducesValidWrapperEvenWithNoFindings(t *testing.T) {
	exporter, err := reporter.ExporterFor("html")
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, exporter.Export(&buf, nil))
	out := buf.String()

	assert.Contains(t, out, "<!doctype html>")
	assert.Contains(t, out, "0 finding(s)")
}
