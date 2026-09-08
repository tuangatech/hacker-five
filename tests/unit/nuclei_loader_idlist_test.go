package unit

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// tmplBody is a minimal valid nuclei template with the given id.
func tmplBody(id string) string {
	return fmt.Sprintf(`
id: %s
info:
  name: %s
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`, id, id)
}

// TestLoadDirByIDs_ParsesOnlyRequested is F4's core guarantee (LT-71): given
// a large directory, LoadDirByIDs returns exactly the requested templates
// and its result matches a full LoadDirDetailed + exact-id filter.
func TestLoadDirByIDs_ParsesOnlyRequested(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 200; i++ {
		writeTemplate(t, dir, fmt.Sprintf("t%03d.yaml", i), tmplBody(fmt.Sprintf("tmpl-%03d", i)))
	}

	got, errs := nuclei.LoadDirByIDs(dir, map[string]bool{"tmpl-042": true, "tmpl-100": true})
	require.Empty(t, errs)
	require.Len(t, got, 2)

	ids := map[string]bool{}
	for _, tm := range got {
		ids[tm.ID] = true
	}
	assert.Equal(t, map[string]bool{"tmpl-042": true, "tmpl-100": true}, ids)

	// Equivalence with the slow path.
	all, _ := nuclei.LoadDirDetailed(dir)
	var slowMatch int
	for _, tm := range all {
		if tm.ID == "tmpl-042" || tm.ID == "tmpl-100" {
			slowMatch++
		}
	}
	assert.Equal(t, slowMatch, len(got))
}

// TestLoadDirByIDs_EmptyWant returns nothing without walking anything.
func TestLoadDirByIDs_EmptyWant(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "a.yaml", tmplBody("a"))
	got, errs := nuclei.LoadDirByIDs(dir, nil)
	assert.Empty(t, got)
	assert.Empty(t, errs)
}

// TestLoadDirByIDs_MissingIDNoError: a requested id that isn't on disk just
// isn't in the result (the caller detects the shortfall and falls back).
func TestLoadDirByIDs_MissingID(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "a.yaml", tmplBody("real-one"))
	got, errs := nuclei.LoadDirByIDs(dir, map[string]bool{"real-one": true, "ghost": true})
	require.Empty(t, errs)
	require.Len(t, got, 1)
	assert.Equal(t, "real-one", got[0].ID)
}

// TestLoadDirByIDs_NestedDirs: the walk still recurses vendor subdirectories
// the same way LoadDirDetailed does.
func TestLoadDirByIDs_NestedDirs(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "http", "exposures", "vendor")
	writePayloadFile(t, dir, filepath.Join("http", "exposures", "vendor", "deep.yaml"), tmplBody("deep-template"))
	_ = sub
	got, errs := nuclei.LoadDirByIDs(dir, map[string]bool{"deep-template": true})
	require.Empty(t, errs)
	require.Len(t, got, 1)
	assert.Equal(t, "deep-template", got[0].ID)
}
