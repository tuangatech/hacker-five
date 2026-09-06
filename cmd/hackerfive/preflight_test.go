package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolicyRequestHeaders_ResolvedFromScopeSibling: with no --policy-file,
// the header list is read from a policy.yaml sitting next to the --scope file
// (LT-36) — the same resolution resolvePolicyPath already does for the D2
// verdict check.
func TestPolicyRequestHeaders_ResolvedFromScopeSibling(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	require.NoError(t, os.WriteFile(scopePath, []byte("example.com\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(
		"request_headers:\n  - \"X-Hackerone: tonytran\"\n"), 0o644))

	got, err := policyRequestHeaders("", scopePath)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"X-Hackerone": "tonytran"}, got)
}

func TestPolicyRequestHeaders_NoFile_ReturnsNil(t *testing.T) {
	got, err := policyRequestHeaders("", filepath.Join(t.TempDir(), "scope.txt"))
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestMergeHeaders_FlagOverridesPolicyCaseInsensitively(t *testing.T) {
	merged, fromPolicy := mergeHeaders(
		map[string]string{"X-Hackerone": "policy-user", "X-Keep": "1"},
		map[string]string{"x-hackerone": "flag-user", "X-New": "2"},
	)
	assert.Equal(t, map[string]string{
		"X-Hackerone": "flag-user", // flag wins, policy's spelling of the name kept
		"X-Keep":      "1",
		"X-New":       "2",
	}, merged)
	assert.Equal(t, []string{"X-Hackerone", "X-Keep"}, fromPolicy)
}

func TestMergeHeaders_NoPolicy_JustFlags(t *testing.T) {
	merged, fromPolicy := mergeHeaders(nil, map[string]string{"X-New": "2"})
	assert.Equal(t, map[string]string{"X-New": "2"}, merged)
	assert.Empty(t, fromPolicy)
}
