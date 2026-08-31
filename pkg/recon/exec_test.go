package recon

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/toolsync"
)

// isolateInstallDir points toolsync.DefaultInstallDir() at a temp dir for
// the duration of the test, same HOME+XDG_CONFIG_HOME override
// pkg/webui/handlers_scan_test.go's newTestServer already uses to isolate
// os.UserConfigDir() from this machine's real state on every platform
// (os.UserConfigDir() only honors XDG_CONFIG_HOME on Linux; Darwin always
// reads HOME).
func isolateInstallDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", tmp)
	dir, err := toolsync.DefaultInstallDir()
	require.NoError(t, err)
	return dir
}

func TestResolveBinaryPath_FallsBackToInstallDir(t *testing.T) {
	dir := isolateInstallDir(t)
	require.NoError(t, os.MkdirAll(dir, 0o755))

	const fakeTool = "hackerfive-recon-test-fixture-tool"
	path := toolsync.InstalledPath(dir, fakeTool)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	got, err := resolveBinaryPath(fakeTool)
	require.NoError(t, err)
	assert.Equal(t, path, got)
}

func TestResolveBinaryPath_MissingEverywhere_ReturnsBinaryMissing(t *testing.T) {
	isolateInstallDir(t) // empty install dir, nothing placed in it

	_, err := resolveBinaryPath("hackerfive-recon-test-fixture-tool-does-not-exist")
	require.Error(t, err)
	assert.True(t, isBinaryMissing(err))
}
