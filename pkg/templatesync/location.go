package templatesync

import (
	"fmt"
	"os"
	"path/filepath"
)

// DefaultSyncDir returns the persistent OS user-config directory synced
// templates should live in — outside the extracted release folder entirely,
// so a binary upgrade never requires copying anything forward. Matches
// upstream Nuclei's own ~/.config/nuclei-templates convention, via Go's
// stdlib os.UserConfigDir() (already XDG-aware on Linux, ~/Library/Application
// Support on macOS, %AppData% on Windows — no new dependency). See
// docs/12-implementation-plan-ph3.md's "Template sync command" §3.
func DefaultSyncDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving user config directory: %w", err)
	}
	return filepath.Join(configDir, "hackerfive", "nuclei-templates"), nil
}
