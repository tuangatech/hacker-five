package webui

import (
	"fmt"
	"os/exec"
	"runtime"
)

// OpenBrowser best-effort opens url in the default browser — no new
// dependency, just the OS-native "open a URL" command per platform. Callers
// should treat a non-nil error as informational (log it), not fatal: the
// URL is always printed separately too, for cases this can't reach at all
// (SSH, a sandboxed/headless shell — see docs/12-implementation-plan-ph3.md's
// "Running it, release-to-release" note).
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("opening browser: %w", err)
	}
	return nil
}
