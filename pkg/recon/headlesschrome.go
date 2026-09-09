package recon

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// headlessChromeCandidates are PATH names to try for an already-installed
// Chrome/Chromium, in preference order. A hit is passed to katana as
// -system-chrome-path so it reuses that binary instead of downloading its
// own (~150 MB, one-time, into ~/.cache/rod) on the first headless run.
var headlessChromeCandidates = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"chrome",
}

// resolveHeadlessChrome finds a local Chrome/Chromium for katana's headless
// mode. It returns the binary path and ok=true when one is found; ok=false
// means none was located and katana will self-provision a Chromium on first
// use (the caller logs the one-time cost). It checks $PATH first, then the
// Playwright cache (already present in this project's WSL dev env —
// CLAUDE.md), which katana does not consult on its own.
func resolveHeadlessChrome() (path string, ok bool) {
	for _, name := range headlessChromeCandidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	if p, ok := playwrightChrome(); ok {
		return p, true
	}
	return "", false
}

// playwrightChrome returns the newest Playwright-managed Chromium binary
// under $PLAYWRIGHT_BROWSERS_PATH or ~/.cache/ms-playwright, or ok=false.
// Playwright lays it out as <root>/chromium-<rev>/chrome-linux64/chrome (the
// full browser) or chrome-linux/chrome on older revisions; the
// chromium_headless_shell-<rev> dirs are skipped — katana drives a full
// browser, not the shell.
func playwrightChrome() (path string, ok bool) {
	root := os.Getenv("PLAYWRIGHT_BROWSERS_PATH")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		root = filepath.Join(home, ".cache", "ms-playwright")
	}
	dirs, err := filepath.Glob(filepath.Join(root, "chromium-*"))
	if err != nil || len(dirs) == 0 {
		return "", false
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dirs))) // highest revision first
	for _, d := range dirs {
		for _, rel := range []string{
			filepath.Join("chrome-linux64", "chrome"),
			filepath.Join("chrome-linux", "chrome"),
		} {
			cand := filepath.Join(d, rel)
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				return cand, true
			}
		}
	}
	return "", false
}
