package unit

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/native"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// nuclei.LoadFiles / native.LoadFiles / nuclei.PeekDirIDs back pkg/scanner's
// LT-106 parse cache: parse only the handful of files a still-valid cache
// names, instead of walking and parsing the whole corpus.

func TestNucleiLoadFiles_ParsesOnlyNamedFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		writeTemplate(t, dir, fmt.Sprintf("t%02d.yaml", i), tmplBody(fmt.Sprintf("tmpl-%02d", i)))
	}
	writePayloadFile(t, dir, filepath.Join("nested", "deep.yaml"), tmplBody("deep-one"))

	got, errs := nuclei.LoadFiles(dir, []string{"t05.yaml", "nested/deep.yaml"})
	require.Empty(t, errs)
	require.Len(t, got, 2)

	ids := map[string]bool{}
	for _, tm := range got {
		ids[tm.ID] = true
	}
	assert.Equal(t, map[string]bool{"tmpl-05": true, "deep-one": true}, ids)

	// Equivalence with the full-parse path for the same two.
	all, _ := nuclei.LoadDirDetailed(dir)
	var slow int
	for _, tm := range all {
		if tm.ID == "tmpl-05" || tm.ID == "deep-one" {
			slow++
		}
	}
	assert.Equal(t, slow, len(got))
}

func TestNucleiLoadFiles_MissingOrBadFileCollectedNotFatal(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "good.yaml", tmplBody("good-one"))
	writeTemplate(t, dir, "bad.yaml", "id: bad-one\ninfo:\n  name: bad\n") // no http: -> parse error

	got, errs := nuclei.LoadFiles(dir, []string{"good.yaml", "ghost.yaml", "bad.yaml"})
	require.Len(t, got, 1)
	assert.Equal(t, "good-one", got[0].ID)
	assert.Len(t, errs, 2, "the missing file and the invalid file are both reported, neither aborts the rest")
}

func TestNucleiPeekDirIDs_MapsIDToRelPath(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "a.yaml", tmplBody("alpha"))
	writePayloadFile(t, dir, filepath.Join("http", "vendor", "b.yaml"), tmplBody("bravo"))
	// A native-format file uses the same column-0 id: convention.
	writeNativeTemplate(t, dir, "n.yaml", `id: november
info:
  name: n
tags: [x]
requests:
  - path: "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["x"]
`)

	ids, err := nuclei.PeekDirIDs(dir)
	require.NoError(t, err)
	assert.Equal(t, "a.yaml", ids["alpha"])
	assert.Equal(t, "http/vendor/b.yaml", ids["bravo"], "relative path is forward-slash, corpus-root-relative")
	assert.Equal(t, "n.yaml", ids["november"], "native files are peeked too")
}

func TestNativeLoadFiles_ParsesOnlyNamedFiles(t *testing.T) {
	dir := t.TempDir()
	body := func(id string) string {
		return fmt.Sprintf(`id: %s
info:
  name: %s
tags: [example]
requests:
  - path: "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["x"]
`, id, id)
	}
	writeNativeTemplate(t, dir, "one.yaml", body("native-one"))
	writeNativeTemplate(t, dir, "two.yaml", body("native-two"))
	writeNativeTemplate(t, dir, "three.yaml", body("native-three"))

	got, errs := native.LoadFiles(dir, []string{"one.yaml", "three.yaml"})
	require.Empty(t, errs)
	ids := map[string]bool{}
	for _, tm := range got {
		ids[tm.ID] = true
	}
	assert.Equal(t, map[string]bool{"native-one": true, "native-three": true}, ids)
}
