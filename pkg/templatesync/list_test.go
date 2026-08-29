package templatesync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

// TestList_LoadsBothFormatsAndLabelsSource confirms List loads both
// nuclei-compatible and native templates from each dir and tags every entry
// with the caller-supplied source label for that dir. rejected counts both
// loaders' cross-format rejections (a nuclei-format file has no requests:
// block native.LoadDir needs, and vice versa) — the same "2 rejected from
// one file of each format" behavior tests/unit/engine_test.go's
// TestEngineRun_TemplatesRunAlongsideDetector already establishes for
// scanner.Engine.loadTemplates, which List's rejected count must match.
func TestList_LoadsBothFormatsAndLabelsSource(t *testing.T) {
	bundledDir := t.TempDir()
	writeFile(t, bundledDir, "nuclei.yaml", `
id: bundled-nuclei-check
info:
  name: Bundled nuclei check
  severity: info
  tags: exposed-panels,tech
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["ok"]
`)

	syncedDir := t.TempDir()
	writeFile(t, syncedDir, "native.yaml", `
id: synced-native-check
info:
  name: Synced native check
  severity: low
tags:
  - custom
requests:
  - path: "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["ok"]
`)

	entries, rejected, err := List([]string{bundledDir, syncedDir}, []string{"bundled", "synced"}, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, rejected, "each dir's one file must be cross-rejected once by the other format's loader")

	require.Len(t, entries, 2)
	var haveBundledNuclei, haveSyncedNative bool
	for _, e := range entries {
		switch e.ID {
		case "bundled-nuclei-check":
			haveBundledNuclei = true
			assert.Equal(t, "nuclei", e.Format)
			assert.Equal(t, "bundled", e.Source)
			assert.ElementsMatch(t, []string{"exposed-panels", "tech"}, e.Tags, "comma-separated nuclei tags must be split")
		case "synced-native-check":
			haveSyncedNative = true
			assert.Equal(t, "native", e.Format)
			assert.Equal(t, "synced", e.Source)
			assert.Equal(t, []string{"custom"}, e.Tags)
		}
	}
	assert.True(t, haveBundledNuclei)
	assert.True(t, haveSyncedNative)
}

// TestList_FiltersByTags mirrors scanner.Engine's OR-match --tags semantics:
// an entry is kept if it carries at least one requested tag, matched
// case-insensitively.
func TestList_FiltersByTags(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "wanted.yaml", `
id: wanted-check
info:
  name: Wanted check
  severity: info
  tags: wordpress
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["ok"]
`)
	writeFile(t, dir, "unwanted.yaml", `
id: unwanted-check
info:
  name: Unwanted check
  severity: info
  tags: grafana
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["ok"]
`)

	entries, rejected, err := List([]string{dir}, []string{"bundled"}, []string{"WordPress"})
	require.NoError(t, err)
	assert.Equal(t, 2, rejected, "both nuclei-format files must be cross-rejected once by native.LoadDir")
	require.Len(t, entries, 1)
	assert.Equal(t, "wanted-check", entries[0].ID)
}

// TestList_MismatchedLengths confirms a caller bug (dirs/sourceLabels out of
// sync) fails loudly rather than silently mislabeling or panicking.
func TestList_MismatchedLengths(t *testing.T) {
	_, _, err := List([]string{t.TempDir(), t.TempDir()}, []string{"only-one-label"}, nil)
	require.Error(t, err)
}

// TestList_EmptyDirSkipped confirms an empty-string dir entry (the shape
// scanner.Engine.loadTemplates already tolerates) is a no-op, not an error.
func TestList_EmptyDirSkipped(t *testing.T) {
	entries, rejected, err := List([]string{""}, []string{"bundled"}, nil)
	require.NoError(t, err)
	assert.Empty(t, entries)
	assert.Equal(t, 0, rejected)
}
