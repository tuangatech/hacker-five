package templatesync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCountTemplateFiles_CountsOnlyYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.yml"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("x"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "c.yaml"), []byte("x"), 0o644))

	n, err := CountTemplateFiles(dir)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
}

func TestCountTemplateFiles_MissingDirReturnsError(t *testing.T) {
	_, err := CountTemplateFiles(filepath.Join(t.TempDir(), "does-not-exist"))
	assert.Error(t, err)
}

func TestIndexDriftWarning_EmptyIndexNeverWarns(t *testing.T) {
	assert.Equal(t, "", IndexDriftWarning(0, 0))
}

func TestIndexDriftWarning_EmptyDiskWithNonEmptyIndexWarns(t *testing.T) {
	w := IndexDriftWarning(7716, 0)
	assert.Contains(t, w, "7716 templates")
	assert.Contains(t, w, "none on disk")
}

func TestIndexDriftWarning_WildlyStaleWarns(t *testing.T) {
	w := IndexDriftWarning(1000, 10) // 100x — well past indexDriftRatio
	assert.Contains(t, w, "1000 templates")
	assert.Contains(t, w, "10 template files")
}

func TestIndexDriftWarning_CloseEnoughDoesNotWarn(t *testing.T) {
	assert.Equal(t, "", IndexDriftWarning(100, 90))
}
