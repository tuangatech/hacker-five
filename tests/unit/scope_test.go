package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

func writeScopeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestScopeParse_ExactDomain(t *testing.T) {
	path := writeScopeFile(t, "example.com\n")
	sc, err := scope.Parse(path)
	require.NoError(t, err)

	assert.True(t, sc.Allowed("https://example.com/path"))
	assert.False(t, sc.Allowed("https://sub.example.com/"))
	assert.False(t, sc.Allowed("https://notexample.com/"))
}

func TestScopeParse_WildcardDomain(t *testing.T) {
	path := writeScopeFile(t, "*.example.com\n")
	sc, err := scope.Parse(path)
	require.NoError(t, err)

	assert.True(t, sc.Allowed("https://sub.example.com/"))
	assert.True(t, sc.Allowed("https://deep.sub.example.com/"))
	assert.True(t, sc.Allowed("https://example.com/"), "the wildcard's own base domain should also match")
	assert.False(t, sc.Allowed("https://notexample.com/"))
}

func TestScopeParse_CIDR(t *testing.T) {
	path := writeScopeFile(t, "10.0.0.0/8\n")
	sc, err := scope.Parse(path)
	require.NoError(t, err)

	assert.True(t, sc.Allowed("http://10.1.2.3:8080/"))
	assert.False(t, sc.Allowed("http://192.168.1.1/"))
	assert.False(t, sc.Allowed("http://example.com/"), "a domain target must not match a CIDR-only scope")
}

func TestScopeParse_CommentsAndBlankLinesIgnored(t *testing.T) {
	path := writeScopeFile(t, "# comment\n\nexample.com\n  # indented comment\n")
	sc, err := scope.Parse(path)
	require.NoError(t, err)

	assert.True(t, sc.Allowed("https://example.com/"))
}

func TestScopeParse_MissingFile(t *testing.T) {
	_, err := scope.Parse(filepath.Join(t.TempDir(), "does-not-exist.txt"))
	assert.Error(t, err)
}

func TestScopeAllowed_UnmatchedTargetDefaultDenies(t *testing.T) {
	path := writeScopeFile(t, "example.com\n")
	sc, err := scope.Parse(path)
	require.NoError(t, err)

	assert.False(t, sc.Allowed("https://evil.example.org/"))
	assert.False(t, sc.Allowed("not a url"))
}
