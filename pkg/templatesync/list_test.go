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
// with the caller-supplied source label for that dir. rejected must stay 0
// here: each file is valid in its own format, so despite each also being
// rejected by the *other* format's loader (a nuclei-format file has no
// requests: block native.LoadDirDetailed needs, and vice versa), neither is
// a genuine parse failure — see countRejectedByBothFormats, which only
// counts a path rejected by both loaders. A prior version of this function
// summed both loaders' raw error counts unconditionally, which flagged
// every legitimately-loaded template as "also rejected" (this exact test
// used to assert rejected == 2 here) — a real, user-visible confusion in
// the Web UI's template count, not a cosmetic nit.
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
	assert.Equal(t, 0, rejected, "a file valid in its own format must not count as rejected just because the other format's loader can't parse it")

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
	assert.Equal(t, 0, rejected, "both files are valid nuclei templates — neither is a genuine parse failure")
	require.Len(t, entries, 1)
	assert.Equal(t, "wanted-check", entries[0].ID)
}

// TestList_GenuinelyMalformedFile_CountsAsRejected is
// countRejectedByBothFormats' own positive case: a file that fails to
// parse as *either* format (missing required fields for both) must still
// be counted, distinguishing a real problem from the cross-format
// non-issue TestList_LoadsBothFormatsAndLabelsSource/TestList_FiltersByTags
// exercise above.
func TestList_GenuinelyMalformedFile_CountsAsRejected(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "valid.yaml", `
id: valid-check
info:
  name: Valid check
  severity: info
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["ok"]
`)
	writeFile(t, dir, "broken.yaml", "not: [valid yaml at all\n")

	entries, rejected, err := List([]string{dir}, []string{"bundled"}, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, rejected, "broken.yaml fails both loaders and must count as a genuine rejection")
	require.Len(t, entries, 1)
	assert.Equal(t, "valid-check", entries[0].ID)
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
