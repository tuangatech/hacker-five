package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

func runTriage(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newTriageCmd(&rootFlags{})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func TestTriageCmd_RequiresFindingsPath(t *testing.T) {
	_, _, err := runTriage(t, "--llm-assist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--findings")
}

func TestTriageCmd_RequiresLLMAssist(t *testing.T) {
	f := filepath.Join(t.TempDir(), "findings.json")
	require.NoError(t, os.WriteFile(f, []byte("[]"), 0o644))
	_, _, err := runTriage(t, "--findings", f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--llm-assist")
}

func TestTriageCmd_EmptyFindingsFile_NoError(t *testing.T) {
	f := filepath.Join(t.TempDir(), "findings.json")
	require.NoError(t, os.WriteFile(f, []byte("[]"), 0o644))
	_, errOut, err := runTriage(t, "--findings", f, "--llm-assist")
	require.NoError(t, err, "an empty finding list is a no-op, not an error (must not reach a paid LLM call)")
	assert.Contains(t, errOut, "nothing to rank")
}

func TestTriageCmd_MalformedFindingsFile_Errors(t *testing.T) {
	f := filepath.Join(t.TempDir(), "findings.json")
	require.NoError(t, os.WriteFile(f, []byte("{not json"), 0o644))
	_, _, err := runTriage(t, "--findings", f, "--llm-assist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing --findings")
}

func TestWriteTriageTable_OrdersByRankAndJoinsSeverity(t *testing.T) {
	findings := []detectors.Finding{
		{ID: "a", Severity: "low", Type: "misconfig"},
		{ID: "b", Severity: "high", Type: "idor"},
	}
	ranked := []llmfallback.RankedFinding{
		{FindingID: "a", Rank: 2, Rationale: "informational"},
		{FindingID: "b", Rank: 1, Rationale: "direct object access"},
	}
	var buf bytes.Buffer
	require.NoError(t, writeTriageTable(&buf, findings, ranked))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 3) // header + 2 rows
	assert.Contains(t, lines[1], "b")
	assert.Contains(t, lines[1], "high")
	assert.Contains(t, lines[1], "direct object access")
	assert.Contains(t, lines[2], "a")
	assert.Contains(t, lines[2], "low")
}
