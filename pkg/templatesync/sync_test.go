package templatesync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSyncDir_EndsInHackerfiveNucleiTemplates(t *testing.T) {
	dir, err := DefaultSyncDir()
	require.NoError(t, err)
	assert.Contains(t, dir, "hackerfive")
	assert.Contains(t, dir, "nuclei-templates")
}

// TestSync_GitNotFound confirms Sync returns the distinguishable
// ErrGitNotFound (not a raw exec.LookPath error) when git isn't on PATH —
// the signal docs/12-implementation-plan-ph3.md requires every caller (CLI
// today, a future web handler) be able to errors.Is() and render its own
// friendly message from.
func TestSync_GitNotFound(t *testing.T) {
	t.Setenv("PATH", "")

	_, err := Sync(context.Background(), t.TempDir())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrGitNotFound), "Sync must return an error wrapping/matching ErrGitNotFound, got: %v", err)
}

// TestCategoryCounts_CountsWithoutRequiringAnInProcessSync confirms
// CategoryCounts can recompute the same per-category numbers Sync's own
// Result carries, against a directory synced by an earlier, separate
// process — what pkg/webui's Templates page relies on to show counts for a
// corpus synced via the CLI before `hackerfive serve` ever started.
func TestCategoryCounts_CountsWithoutRequiringAnInProcessSync(t *testing.T) {
	dir := t.TempDir()
	// A real post-sync tree has every category directory present (even if
	// empty) — sparse-checkout materializes all of them — so create all of
	// Categories here too, not just the one under test.
	for _, category := range Categories {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, category), 0o755))
	}

	populated := Categories[0]
	require.NoError(t, os.WriteFile(filepath.Join(dir, populated, "a.yaml"), []byte("id: a"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, populated, "b.yml"), []byte("id: b"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, populated, "readme.md"), []byte("not a template"), 0o644))

	counts, err := CategoryCounts(dir)
	require.NoError(t, err)
	assert.Equal(t, 2, counts[populated])
	for _, other := range Categories[1:] {
		assert.Equal(t, 0, counts[other])
	}
}
