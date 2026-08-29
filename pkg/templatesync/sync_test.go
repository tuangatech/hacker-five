package templatesync

import (
	"context"
	"errors"
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
