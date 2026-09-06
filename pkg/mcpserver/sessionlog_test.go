package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

// runLocalMisconfigScan drives a real scan tool call against a local
// httptest target — reused by the session-log tests that need at least one
// recorded call. Returns the target URL so a test can assert on it.
func runLocalMisconfigScan(t *testing.T, session *mcp.ClientSession, reason string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	args := map[string]any{
		"targets":    []string{srv.URL},
		"scope":      []string{"127.0.0.1"},
		"detector":   "misconfig",
		"auth_token": "SECRET-should-not-be-logged",
	}
	if reason != "" {
		args["reason"] = reason
	}
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "scan", Arguments: args})
	require.NoError(t, err)
	require.False(t, res.IsError, "scan should succeed: %s", textContent(t, res))
	return srv.URL
}

func querySessionLog(t *testing.T, session *mcp.ClientSession, args map[string]any) sessionLogOutput {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "session.log", Arguments: args})
	require.NoError(t, err)
	require.False(t, res.IsError, "session.log should not error: %s", textContent(t, res))

	var out sessionLogOutput
	require.NoError(t, json.Unmarshal([]byte(textContent(t, res)), &out))
	return out
}

// TestSessionLogTool_RecordsScanCallWithReason_OmitsSecrets is C1's core
// (doc15 Step 5): every action tool call lands in the session log with the
// caller's stated reason and a parameter summary that carries no secret.
func TestSessionLogTool_RecordsScanCallWithReason_OmitsSecrets(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	ctx := context.Background()
	session, err := connect(ctx, New())
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	target := runLocalMisconfigScan(t, session, "probe the staging host for exposed config")

	out := querySessionLog(t, session, nil)
	require.Len(t, out.Entries, 1)
	e := out.Entries[0]
	assert.Equal(t, "scan", e.Tool)
	assert.Equal(t, "probe the staging host for exposed config", e.Reason)
	assert.Contains(t, e.Result, "finding(s)")
	assert.Equal(t, 1, out.Total)

	params := string(e.Params)
	assert.Contains(t, params, "misconfig")
	assert.Contains(t, params, target)
	assert.NotContains(t, params, "SECRET-should-not-be-logged", "auth_token must never reach the session log")
	assert.NotContains(t, params, "auth_token")
}

// TestSessionLogTool_FilterAndLimit exercises the tool's query params over a
// mix of recorded calls.
func TestSessionLogTool_FilterAndLimit(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	ctx := context.Background()
	session, err := connect(ctx, New())
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	runLocalMisconfigScan(t, session, "first")
	runLocalMisconfigScan(t, session, "second")

	// An export call, so the log holds more than one tool name.
	_, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "findings.export",
		Arguments: map[string]any{"format": "json", "findings": []any{}, "reason": "render nothing"},
	})
	require.NoError(t, err)

	all := querySessionLog(t, session, nil)
	assert.Len(t, all.Entries, 3)
	assert.Equal(t, 3, all.Total)

	scans := querySessionLog(t, session, map[string]any{"tool_filter": "scan"})
	assert.Len(t, scans.Entries, 2)
	assert.Equal(t, 3, scans.Total, "Total is the unfiltered count")

	lastOnly := querySessionLog(t, session, map[string]any{"limit": 1})
	require.Len(t, lastOnly.Entries, 1)
	assert.Equal(t, "findings.export", lastOnly.Entries[0].Tool)

	lastScan := querySessionLog(t, session, map[string]any{"tool_filter": "scan", "limit": 1})
	require.Len(t, lastScan.Entries, 1)
	assert.Equal(t, "second", lastScan.Entries[0].Reason)
}

// TestSessionLog_NewResetsTheLog guards the package-var lifecycle: a freshly
// built server starts with an empty log even though a prior server in the
// same process recorded calls.
func TestSessionLog_NewResetsTheLog(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	ctx := context.Background()

	s1, err := connect(ctx, New())
	require.NoError(t, err)
	runLocalMisconfigScan(t, s1, "on the first server")
	_ = s1.Close()
	require.Len(t, sessionLog.Entries(), 1)

	s2, err := connect(ctx, New())
	require.NoError(t, err)
	defer func() { _ = s2.Close() }()
	assert.Empty(t, sessionLog.Entries(), "New() must reset the session log")

	out := querySessionLog(t, s2, nil)
	assert.Empty(t, out.Entries)
}

// TestSessionLog_JSONLSinkFromEnv confirms HACKERFIVE_SESSION_LOG makes the
// server persist each call as a JSON line.
func TestSessionLog_JSONLSinkFromEnv(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	sinkPath := filepath.Join(t.TempDir(), "session.jsonl")
	t.Setenv(sessionLogEnv, sinkPath)

	ctx := context.Background()
	session, err := connect(ctx, New())
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	runLocalMisconfigScan(t, session, "persisted call")

	raw, err := os.ReadFile(sinkPath)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	require.Len(t, lines, 1)

	var entry agenttask.SessionLogEntry
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &entry))
	assert.Equal(t, "scan", entry.Tool)
	assert.Equal(t, "persisted call", entry.Reason)
	assert.NotContains(t, string(entry.Params), "SECRET-should-not-be-logged")
}
