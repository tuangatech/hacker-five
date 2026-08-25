package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveTargets_Empty(t *testing.T) {
	targets, err := resolveTargets("")
	require.NoError(t, err)
	assert.Nil(t, targets)
}

func TestResolveTargets_LiteralURL(t *testing.T) {
	targets, err := resolveTargets("http://example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"http://example.com"}, targets)
}

func TestResolveTargets_FileWithMultipleTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "targets.txt")
	require.NoError(t, os.WriteFile(path, []byte("http://a.example\n\nhttp://b.example\n"), 0o644))

	targets, err := resolveTargets(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"http://a.example", "http://b.example"}, targets, "blank lines must be skipped")
}

func TestParseTags_Empty(t *testing.T) {
	assert.Nil(t, parseTags(""))
}

func TestParseTags_SplitsAndTrims(t *testing.T) {
	assert.Equal(t, []string{"wordpress", "grafana"}, parseTags(" wordpress, grafana "))
}

func TestParseTags_DropsEmptyEntries(t *testing.T) {
	assert.Equal(t, []string{"wordpress"}, parseTags("wordpress,,  "))
}
