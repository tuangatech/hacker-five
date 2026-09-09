package recon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlaywrightChrome guards LT-99's Chrome-reuse path: the newest
// Playwright-managed full-browser Chromium under $PLAYWRIGHT_BROWSERS_PATH is
// returned (so katana reuses it instead of downloading its own), the
// headless-shell dirs are skipped, and an empty/absent cache is ok=false.
func TestPlaywrightChrome(t *testing.T) {
	t.Run("picks the highest-revision full browser", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("PLAYWRIGHT_BROWSERS_PATH", root)

		// An older full browser, a headless-shell (must be ignored), and the
		// newest full browser.
		mkfile(t, filepath.Join(root, "chromium-1000", "chrome-linux64", "chrome"))
		mkfile(t, filepath.Join(root, "chromium_headless_shell-1223", "chrome-linux", "headless_shell"))
		newest := filepath.Join(root, "chromium-1223", "chrome-linux64", "chrome")
		mkfile(t, newest)

		got, ok := playwrightChrome()
		require.True(t, ok)
		assert.Equal(t, newest, got, "the highest chromium-<rev> dir wins")
	})

	t.Run("older chrome-linux layout still resolves", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("PLAYWRIGHT_BROWSERS_PATH", root)
		old := filepath.Join(root, "chromium-980", "chrome-linux", "chrome")
		mkfile(t, old)

		got, ok := playwrightChrome()
		require.True(t, ok)
		assert.Equal(t, old, got)
	})

	t.Run("empty cache is not found", func(t *testing.T) {
		t.Setenv("PLAYWRIGHT_BROWSERS_PATH", t.TempDir())
		_, ok := playwrightChrome()
		assert.False(t, ok)
	})
}

// TestResolveHeadlessChrome_FallsBackToSelfProvision: with nothing on $PATH
// and no Playwright cache, the resolver reports ok=false so the caller warns
// about the one-time katana Chromium download rather than passing a bogus
// -system-chrome-path.
func TestResolveHeadlessChrome_FallsBackToSelfProvision(t *testing.T) {
	t.Setenv("PATH", "")
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", t.TempDir())
	_, ok := resolveHeadlessChrome()
	assert.False(t, ok)
}

func mkfile(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755))
}
