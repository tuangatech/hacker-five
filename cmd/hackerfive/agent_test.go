package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/orchestrator"
)

// TestAgentEventWriter_StreamsFindingsBeforeResult exercises the LT-163
// item 3 fix directly: a "finding" event must already be a complete,
// independently-parseable JSON line the instant it's written, not something
// that only becomes valid once a later "result" event completes it — that's
// what lets a killed `hackerfive agent` process's partial stdout still be
// read as real findings.
func TestAgentEventWriter_StreamsFindingsBeforeResult(t *testing.T) {
	var buf bytes.Buffer
	w := newAgentEventWriter(&buf)

	f := detectors.Finding{ID: "idor-1", Type: "idor", Severity: "high", Target: "https://example.test/report"}
	w.writeFinding(f)

	res := orchestrator.Result{Findings: []detectors.Finding{f}, Iterations: 3, SpendUSD: 0.01}
	w.writeResult(res, nil)

	lines := splitNonEmptyLines(t, buf.String())
	require.Len(t, lines, 2)

	var findingEvent agentStreamEvent
	require.NoError(t, json.Unmarshal(lines[0], &findingEvent))
	require.Equal(t, "finding", findingEvent.Type)
	require.NotNil(t, findingEvent.Finding)
	require.Equal(t, "idor-1", findingEvent.Finding.ID)
	require.Nil(t, findingEvent.Result)

	var resultEvent agentStreamEvent
	require.NoError(t, json.Unmarshal(lines[1], &resultEvent))
	require.Equal(t, "result", resultEvent.Type)
	require.NotNil(t, resultEvent.Result)
	require.Len(t, resultEvent.Result.Findings, 1)
	require.Equal(t, 3, resultEvent.Result.Iterations)
	require.Empty(t, resultEvent.Err)
}

// TestAgentEventWriter_ResultCarriesRunError covers the "NextAction failed"
// path (orchestrator.Run returns a non-nil error alongside a still-useful
// partial Result) — the CLI must still emit that partial Result rather than
// emit nothing just because Run itself errored.
func TestAgentEventWriter_ResultCarriesRunError(t *testing.T) {
	var buf bytes.Buffer
	w := newAgentEventWriter(&buf)

	w.writeResult(orchestrator.Result{Iterations: 1}, errors.New("orchestrator: NextAction: boom"))

	lines := splitNonEmptyLines(t, buf.String())
	require.Len(t, lines, 1)

	var ev agentStreamEvent
	require.NoError(t, json.Unmarshal(lines[0], &ev))
	require.Equal(t, "result", ev.Type)
	require.Contains(t, ev.Err, "boom")
}

// TestAgentEventWriter_ConcurrentFindingsStayWellFormed guards against
// interleaved writes: a leaf's scanner engine can report more than one
// Finding from separate worker goroutines (pkg/planexec.ExecOptions.
// OnFinding's own doc comment only promises "synchronous", not
// single-goroutine), so agentEventWriter must serialize its own writes or
// concurrent Encode calls could interleave into a line that fails to parse.
func TestAgentEventWriter_ConcurrentFindingsStayWellFormed(t *testing.T) {
	var buf bytes.Buffer
	w := newAgentEventWriter(&buf)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			w.writeFinding(detectors.Finding{ID: "finding-x", Type: "idor", Severity: "low"})
		}(i)
	}
	wg.Wait()

	lines := splitNonEmptyLines(t, buf.String())
	require.Len(t, lines, n)
	for _, line := range lines {
		var ev agentStreamEvent
		require.NoError(t, json.Unmarshal(line, &ev), "line: %s", line)
		require.Equal(t, "finding", ev.Type)
	}
}

func splitNonEmptyLines(t *testing.T, s string) [][]byte {
	t.Helper()
	var lines [][]byte
	sc := bufio.NewScanner(bytes.NewReader([]byte(s)))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		lines = append(lines, cp)
	}
	require.NoError(t, sc.Err())
	return lines
}

func TestReconAuthHeader(t *testing.T) {
	origin, h, err := reconAuthHeader("app.example.com:8443", "tok", "", "")
	require.NoError(t, err)
	require.Equal(t, "https://app.example.com:8443", origin, "a scheme-less target gets https, as recon does")
	require.Equal(t, map[string]string{"Authorization": "Bearer tok"}, h)

	origin, h, err = reconAuthHeader("http://127.0.0.1:8888", "tok", "X-Api-Key", "{token}")
	require.NoError(t, err)
	require.Equal(t, "http://127.0.0.1:8888", origin)
	require.Equal(t, map[string]string{"X-Api-Key": "tok"}, h)

	_, _, err = reconAuthHeader("http://x", "", "", "")
	require.ErrorContains(t, err, "--recon-auth needs an owner token")
	_, _, err = reconAuthHeader("http://x", "tok", "", "Bearer")
	require.ErrorContains(t, err, "{token}")
}

// --recon-auth is opt-in and must fail before any network call when there is no
// token to send, rather than silently running an unauthenticated recon.
func TestAgentCmd_ReconAuthWithoutTokenFailsEarly(t *testing.T) {
	t.Setenv("HACKERFIVE_AUTH_TOKEN", "")
	cmd := newAgentCmd(&rootFlags{})
	var stderr bytes.Buffer
	cmd.SetErr(&stderr)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--targets", "http://127.0.0.1:1", "--allow-no-scope", "--no-model", "--recon-auth"})
	err := cmd.Execute()
	require.ErrorContains(t, err, "--recon-auth needs an owner token")
}
