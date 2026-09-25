package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/detectors/ssrf"
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
	require.ErrorContains(t, err, "--recon-auth: recon authentication needs an owner token")
}

// LT-187: doc94 measured --recon-auth changes findings, not just coverage
// (crAPI 4/7 -> 5/7 known vulnerabilities), so it now defaults on whenever a
// token is available and the flag wasn't given explicitly — an operator who
// already supplies --auth-token no longer has to separately remember
// --recon-auth. Table-driven against the pure function directly rather than
// through cmd.Execute(): a real recon run against the closed port here took
// 40-100s per case even at --recon-depth passive in this environment, which
// resolveReconAuthDefault's own extraction exists to avoid depending on.
func TestResolveReconAuthDefault(t *testing.T) {
	cases := []struct {
		name          string
		explicitlySet bool
		current       bool
		authToken     string
		want          bool
	}{
		{"token present, flag not given -> turns on", false, false, "test-token", true},
		{"token present, flag explicitly false -> stays off", true, false, "test-token", false},
		{"token present, flag explicitly true -> stays on", true, true, "test-token", true},
		{"no token, flag not given -> stays off", false, false, "", false},
		{"no token, flag explicitly true -> stays on (caller already validates the token exists)", true, true, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveReconAuthDefault(tc.explicitlySet, tc.current, tc.authToken))
		})
	}
}

// LT-189: every doc94 ablation result that found more than the misconfig
// baseline ran at --recon-depth full (vAPI's BOLA, Juice Shop's full
// recall); "active" silently skips the crawl/JS-analysis/docs/seeding wave
// that produces those leaves. Made the default 2026-09-24.
func TestAgentCmd_ReconDepthDefaultsFull(t *testing.T) {
	cmd := newAgentCmd(&rootFlags{})
	flag := cmd.Flags().Lookup("recon-depth")
	require.NotNil(t, flag, "--recon-depth must be registered")
	assert.Equal(t, "full", flag.DefValue)
}

// agent mirrors scan's blind-SSRF default (LT-188 b, the user's explicit choice on
// 2026-09-21): two public Interactsh servers unless --no-oob. Before this the agent
// passed no server at all, so its ssrf leaves could never prove a blind SSRF.
func TestAgentCmd_OOBDefaultMirrorsScan(t *testing.T) {
	agent := newAgentCmd(&rootFlags{})
	scan := newScanCmd(&rootFlags{})

	oob := agent.Flags().Lookup("oob-server")
	require.NotNil(t, oob, "--oob-server must be registered on agent")
	assert.Equal(t, scan.Flags().Lookup("oob-server").DefValue, oob.DefValue, "the same default as scan")
	assert.Equal(t, "[https://oast.pro,https://oast.live]", oob.DefValue)
	assert.Equal(t, []string{"https://oast.pro", "https://oast.live"}, ssrf.DefaultOOBServers)

	off := agent.Flags().Lookup("no-oob")
	require.NotNil(t, off, "--no-oob must be the way out on agent, as on scan")
	assert.Equal(t, "false", off.DefValue)
}

// LT-188 (a): --allow-ssrf-body-fill is off by default, same convention as
// --allow-writes/--allow-mutating-bfla — filling an endpoint's other required
// body fields can complete its real action, so it must never run unasked.
func TestAgentCmd_AllowSSRFBodyFillDefaultsOff(t *testing.T) {
	cmd := newAgentCmd(&rootFlags{})
	flag := cmd.Flags().Lookup("allow-ssrf-body-fill")
	require.NotNil(t, flag, "--allow-ssrf-body-fill must be registered")
	assert.Equal(t, "false", flag.DefValue)
}
