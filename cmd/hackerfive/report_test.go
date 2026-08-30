package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

func writeFindingsFile(t *testing.T, findings []detectors.Finding) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.json")
	data, err := json.Marshal(findings)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))
	return path
}

func TestFindingByID_ReturnsMatchingFinding(t *testing.T) {
	path := writeFindingsFile(t, []detectors.Finding{
		{ID: "a", Target: "http://one.example.com"},
		{ID: "b", Target: "http://two.example.com"},
	})

	f, err := findingByID(path, "b")
	require.NoError(t, err)
	assert.Equal(t, "http://two.example.com", f.Target)
}

func TestFindingByID_ErrorsWhenNotFound(t *testing.T) {
	path := writeFindingsFile(t, []detectors.Finding{{ID: "a"}})
	_, err := findingByID(path, "missing")
	require.Error(t, err)
}

func TestReportSubmit_RefusesWithoutYesFlag(t *testing.T) {
	cmd := newReportSubmitCmd()
	cmd.SetArgs([]string{"--intent-id", "999"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--yes")
}

func TestReportCreate_NeverCallsSubmitEndpoint(t *testing.T) {
	submitCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/report_intents" && r.Method == http.MethodPost {
			_, _ = w.Write([]byte(`{"data":{"id":"999","type":"report-intent","attributes":{"state":"pending"}}}`))
			return
		}
		if r.Method == http.MethodPost {
			// Any other POST during "report create" (in particular a
			// .../submit path) would mean create silently escalated into
			// submission — exactly what CLAUDE.md's HackerOne invariant
			// forbids.
			submitCalled = true
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("HACKERONE_API_USERNAME", "id")
	t.Setenv("HACKERONE_API_TOKEN", "secret")
	t.Setenv("HACKERONE_API_BASE_URL", srv.URL)

	findingsPath := writeFindingsFile(t, []detectors.Finding{{
		ID: "ssrf-1", Type: "ssrf", Target: "http://example.com", Severity: "high",
		Description: "test finding",
	}})

	cmd := newReportCreateCmd()
	cmd.SetArgs([]string{
		"--findings", findingsPath,
		"--finding-id", "ssrf-1",
		"--team", "acme",
		"--weakness-id", "66",
		"--scope-id", "123",
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	require.NoError(t, cmd.Execute())

	assert.False(t, submitCalled, "report create must never call the submit endpoint")
	assert.Contains(t, out.String(), "999")
	assert.Contains(t, out.String(), "report submit --intent-id 999 --yes")
}
