package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWarnUnstructuredPolicy_MdWithoutYaml covers LT-42: a policy.md next to
// --scope with no policy.yaml produces a warning; adding a policy.yaml
// silences it, and an explicit --policy-file suppresses it too.
func TestWarnUnstructuredPolicy_MdWithoutYaml(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	require.NoError(t, os.WriteFile(scopePath, []byte("example.com\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.md"), []byte("# prose only\n"), 0o644))

	var buf bytes.Buffer
	warnUnstructuredPolicy("", scopePath, &buf)
	assert.Contains(t, buf.String(), "policy.md")
	assert.Contains(t, buf.String(), "LT-42")

	// a machine-readable policy.yaml alongside it → no warning
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("targets: []\n"), 0o644))
	buf.Reset()
	warnUnstructuredPolicy("", scopePath, &buf)
	assert.Empty(t, buf.String())

	// an explicit --policy-file → no warning regardless
	buf.Reset()
	warnUnstructuredPolicy(filepath.Join(dir, "policy.yaml"), scopePath, &buf)
	assert.Empty(t, buf.String())
}

func TestWarnUnstructuredPolicy_NoPolicyFilesAtAll(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	require.NoError(t, os.WriteFile(scopePath, []byte("example.com\n"), 0o644))
	var buf bytes.Buffer
	warnUnstructuredPolicy("", scopePath, &buf)
	assert.Empty(t, buf.String(), "no policy.* at all is the documented no-op, not a warning")
}

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
