package toolsync

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultInstallDir_EndsInHackerfiveBin(t *testing.T) {
	dir, err := DefaultInstallDir()
	require.NoError(t, err)
	assert.Equal(t, "bin", filepath.Base(dir))
	assert.Equal(t, "hackerfive", filepath.Base(filepath.Dir(dir)))
}

func TestBinaryFilename(t *testing.T) {
	got := binaryFilename("httpx")
	if runtime.GOOS == "windows" {
		assert.Equal(t, "httpx.exe", got)
	} else {
		assert.Equal(t, "httpx", got)
	}
}

func TestStatus_NothingInstalled(t *testing.T) {
	dir := t.TempDir()
	statuses := Status(dir)
	require.Len(t, statuses, len(Tools))
	for _, s := range statuses {
		assert.False(t, s.Installed, s.Name)
		assert.Empty(t, s.Version, s.Name)
	}
}

func TestStatus_ManuallyPlacedBinaryCountsAsInstalled(t *testing.T) {
	dir := t.TempDir()
	// A binary someone dropped there by hand (no manifest entry) must still
	// count as installed — Status's ground truth is the file, not the
	// manifest (see toolsync.go's own doc comment on manifestEntry).
	require.NoError(t, os.WriteFile(filepath.Join(dir, binaryFilename("httpx")), []byte("stub"), 0o755))

	statuses := Status(dir)
	found := false
	for _, s := range statuses {
		if s.Name != "httpx" {
			continue
		}
		found = true
		assert.True(t, s.Installed)
		assert.Empty(t, s.Version, "no manifest entry -> unknown version, not an error")
	}
	assert.True(t, found)
}

func TestManifestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)
	m := map[string]manifestEntry{
		"httpx": {Version: "1.11.0", InstalledAt: now},
	}
	require.NoError(t, writeManifest(dir, m))

	got := readManifest(dir)
	require.NotNil(t, got)
	assert.Equal(t, "1.11.0", got["httpx"].Version)
	assert.True(t, got["httpx"].InstalledAt.Equal(now))
}

func TestReadManifest_MissingFile_ReturnsNilNotError(t *testing.T) {
	dir := t.TempDir()
	assert.Nil(t, readManifest(dir))
}

func TestStatus_ReflectsManifestVersionWhenBinaryPresent(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, binaryFilename("naabu")), []byte("stub"), 0o755))
	require.NoError(t, writeManifest(dir, map[string]manifestEntry{
		"naabu": {Version: "2.6.1", InstalledAt: time.Now()},
	}))

	statuses := Status(dir)
	for _, s := range statuses {
		if s.Name == "naabu" {
			assert.True(t, s.Installed)
			assert.Equal(t, "2.6.1", s.Version)
		}
	}
}
