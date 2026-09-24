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

// TestLoadDirByIDsWithIndex_ReturnsFullIndexAsAByproduct is LT-197's core
// guarantee (docs/follow-up.md): the same single walk LoadDirByIDs already
// does also yields allIDs, the id->path of *every* template file observed —
// not only the wanted ones — with no extra I/O pass over the directory.
func TestLoadDirByIDsWithIndex_ReturnsFullIndexAsAByproduct(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		writeTemplate(t, dir, fmt.Sprintf("t%03d.yaml", i), tmplBody(fmt.Sprintf("tmpl-%03d", i)))
	}

	got, allIDs, errs := nuclei.LoadDirByIDsWithIndex(dir, map[string]bool{"tmpl-007": true})
	require.Empty(t, errs)
	require.Len(t, got, 1)
	assert.Equal(t, "tmpl-007", got[0].ID)

	require.Len(t, allIDs, 50, "the index must cover every template the walk observed, not only the one wanted")
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("tmpl-%03d", i)
		path, ok := allIDs[id]
		require.True(t, ok, "%s missing from the index", id)
		assert.Equal(t, fmt.Sprintf("t%03d.yaml", i), path)
	}
}

// TestLoadDirByIDsWithIndex_EmptyWant matches LoadDirByIDs' own contract:
// nothing requested, nothing walked, no index either.
func TestLoadDirByIDsWithIndex_EmptyWant(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "a.yaml", tmplBody("a"))
	got, allIDs, errs := nuclei.LoadDirByIDsWithIndex(dir, nil)
	assert.Empty(t, got)
	assert.Empty(t, allIDs)
	assert.Empty(t, errs)
}
