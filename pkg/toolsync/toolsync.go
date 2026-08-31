// Package toolsync installs the 6 external ProjectDiscovery CLI binaries
// pkg/recon shells out to (subfinder/tlsx/dnsx/naabu/httpx/katana) — the
// same kind of concern pkg/templatesync already solves for the nuclei
// template corpus, applied to a different payload. See
// docs/04-environment-and-testing.md's "Recon binaries" section for the
// manual `go install` alternative this package replaces for end users who
// never have a Go toolchain.
package toolsync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Tool is one ProjectDiscovery binary pkg/recon depends on.
type Tool struct {
	Name string // the binary's own name, and pkg/recon's exec.CommandContext argument
	Repo string // "projectdiscovery/<name>" — GitHub API path
}

// Tools lists the 6 binaries, same order pkg/recon's own doc comments use
// (docs/14-implementation-plan-ph5.md's Dependencies section: Wave 1
// subfinder/tlsx, Wave 2 dnsx/naabu/httpx, Wave 3 katana).
var Tools = []Tool{
	{Name: "subfinder", Repo: "projectdiscovery/subfinder"},
	{Name: "tlsx", Repo: "projectdiscovery/tlsx"},
	{Name: "dnsx", Repo: "projectdiscovery/dnsx"},
	{Name: "naabu", Repo: "projectdiscovery/naabu"},
	{Name: "httpx", Repo: "projectdiscovery/httpx"},
	{Name: "katana", Repo: "projectdiscovery/katana"},
}

// DefaultInstallDir returns the persistent OS user-config directory these
// binaries install into — sibling to templatesync.DefaultSyncDir(), same
// os.UserConfigDir() base, so a released-binary upgrade never needs to
// carry either forward manually.
func DefaultInstallDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "hackerfive", "bin"), nil
}

// binaryFilename returns name with the platform-appropriate executable
// suffix (".exe" on Windows, none elsewhere) — shared by Status and Install.
func binaryFilename(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// InstalledPath returns where Install would place (or has placed) name
// under dir — the one exported way to compute this, so pkg/recon's own
// install-dir fallback lookup never has to duplicate binaryFilename's
// platform-suffix rule.
func InstalledPath(dir, name string) string {
	return filepath.Join(dir, binaryFilename(name))
}

// manifestEntry records what Install last wrote for one tool — display-only
// enrichment, never the source of truth for "is it installed" (Status
// checks the file itself for that, so a binary a user placed there by hand
// still counts).
type manifestEntry struct {
	Version     string    `json:"version"`
	InstalledAt time.Time `json:"installed_at"`
}

const manifestFilename = "versions.json"

func readManifest(dir string) map[string]manifestEntry {
	data, err := os.ReadFile(filepath.Join(dir, manifestFilename))
	if err != nil {
		return nil
	}
	var m map[string]manifestEntry
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m
}

// writeManifest overwrites the manifest with m — called once per Install
// run after every tool has been attempted, not per-tool, so a partial
// failure never leaves a half-written JSON file.
func writeManifest(dir string, m map[string]manifestEntry) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, manifestFilename+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, manifestFilename))
}

// ToolStatus is one Tool's current local install state.
type ToolStatus struct {
	Name        string
	Installed   bool
	Path        string // empty if not installed
	Version     string // "" if unknown (manifest missing/stale) — never blocks Installed
	InstalledAt time.Time
}

// Status reports each Tool's install state under dir — ground truth is the
// binary file's existence, not the manifest (see manifestEntry's own
// comment): no subprocess call, no network, safe to call on every serve/
// recon/plan startup and every Web UI page render.
func Status(dir string) []ToolStatus {
	manifest := readManifest(dir)
	statuses := make([]ToolStatus, 0, len(Tools))
	for _, t := range Tools {
		path := filepath.Join(dir, binaryFilename(t.Name))
		st := ToolStatus{Name: t.Name}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			st.Installed = true
			st.Path = path
			if entry, ok := manifest[t.Name]; ok {
				st.Version = entry.Version
				st.InstalledAt = entry.InstalledAt
			}
		}
		statuses = append(statuses, st)
	}
	return statuses
}
