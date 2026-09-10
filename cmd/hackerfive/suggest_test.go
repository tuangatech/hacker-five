package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runSuggest(t *testing.T, root *rootFlags, args ...string) (string, string, error) {
	t.Helper()
	if root == nil {
		root = &rootFlags{}
	}
	cmd := newSuggestCmd(root)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func writeScanOutput(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "scan.json")
	body := `[
		{"id": "coverage-gap-gateway-example-com-webmin-2-111", "type": "info", "severity": "info", "confidence": "high", "target": "gateway.example.com", "evidence": {"product": "Webmin 2.111", "reason": "no-coverage"}},
		{"id": "idor-1", "type": "idor", "severity": "high", "confidence": "high", "target": "https://example.com/orders/1"}
	]`
	require.NoError(t, os.WriteFile(f, []byte(body), 0o644))
	return f
}

func TestSuggestCmd_NoFlag_PrintsLedgerOnly_NoModelCall(t *testing.T) {
	out, errOut, err := runSuggest(t, nil, writeScanOutput(t))
	require.NoError(t, err)
	assert.Contains(t, errOut, "1 coverage gap(s), 1 other finding(s)")

	var res suggestOutput
	require.NoError(t, json.Unmarshal([]byte(out), &res))
	require.Len(t, res.CoverageGaps, 1)
	assert.Equal(t, "gateway.example.com", res.CoverageGaps[0].Host)
	assert.Equal(t, "Webmin 2.111", res.CoverageGaps[0].Product)
	assert.Empty(t, res.Actions, "no --llm-assist -> no model call, no actions")
}

func TestSuggestCmd_LLMAssist_NoTierConfigured_DegradesToLedgerOnly(t *testing.T) {
	forceNoLLMTier(t)
	out, errOut, err := runSuggest(t, nil, writeScanOutput(t), "--llm-assist")
	require.NoError(t, err, "a missing LLM tier must degrade, not fail the command — the ledger is still valid output")
	assert.Contains(t, errOut, "no LLM tier is configured")

	var res suggestOutput
	require.NoError(t, json.Unmarshal([]byte(out), &res))
	require.Len(t, res.CoverageGaps, 1)
	assert.Empty(t, res.Actions)
}

func TestSuggestCmd_MissingArg_Errors(t *testing.T) {
	_, _, err := runSuggest(t, nil)
	require.Error(t, err)
}

func TestSuggestCmd_MalformedScanOutput_Errors(t *testing.T) {
	f := filepath.Join(t.TempDir(), "scan.json")
	require.NoError(t, os.WriteFile(f, []byte("{not json"), 0o644))
	_, _, err := runSuggest(t, nil, f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing scan output")
}

func TestSuggestCmd_OutputFlag_WritesToFile(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "suggest.json")
	_, _, err := runSuggest(t, &rootFlags{output: outPath}, writeScanOutput(t))
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var res suggestOutput
	require.NoError(t, json.Unmarshal(data, &res))
	require.Len(t, res.CoverageGaps, 1)
}
