// Package templatesync is a Go port of scripts/sync-nuclei-templates.sh —
// see docs/12-implementation-plan-ph3.md's "Template sync command" section
// for the design this implements. It exists to fix two real gaps the shell
// script has: it needs WSL/bash to run at all (no native Windows path), and
// its output lands inside the dev checkout rather than a location that
// survives a released binary being upgraded.
package templatesync

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
)

// PinnedCommit and Categories are kept in sync manually with
// scripts/sync-nuclei-templates.sh's own COMMIT/CATEGORIES — deliberately
// duplicated rather than shared from a config file both read. Re-pinning is
// a rare, deliberate, human-reviewed action (bump both, note it in the
// commit that changes them), not a runtime toggle; a shared-source
// abstraction for two call sites would be premature. See
// docs/12-implementation-plan-ph3.md's "Template sync command" §2 note.
const PinnedCommit = "0aa256a344d5b53648575163c61517ac67f57961"

// Categories mirrors scripts/sync-nuclei-templates.sh's CATEGORIES array —
// keep both in sync when either changes.
var Categories = []string{
	"http/exposed-panels",
	"http/misconfiguration",
	"http/technologies",
	"http/vulnerabilities/generic",
}

const upstreamRepo = "https://github.com/projectdiscovery/nuclei-templates.git"

// ErrGitNotFound is returned when the system git binary isn't on PATH.
// Exported so every caller — the CLI today, a future web handler later
// (docs/12-implementation-plan-ph3.md's "git not found" note) — can
// errors.Is(err, ErrGitNotFound) and render its own friendly message from
// the same underlying signal, instead of each having to pattern-match a raw
// error string.
var ErrGitNotFound = errors.New("git not found on PATH — required for template sync")

// Result summarizes a completed Sync.
type Result struct {
	Commit         string
	CategoryCounts map[string]int // category -> number of .yaml/.yml files under it
}

// Sync clones the pinned commit's Categories (sparse-checkout, partial
// clone — same mechanism as scripts/sync-nuclei-templates.sh) into destDir,
// replacing any existing contents there first. Returns a clear,
// distinguishable error (ErrGitNotFound) if git isn't available, rather
// than a raw exec.LookPath failure.
func Sync(ctx context.Context, destDir string) (*Result, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, ErrGitNotFound
	}

	if err := os.RemoveAll(destDir); err != nil {
		return nil, fmt.Errorf("removing existing %s: %w", destDir, err)
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", destDir, err)
	}

	steps := [][]string{
		{"clone", "--filter=blob:none", "--no-checkout", upstreamRepo, "."},
		{"sparse-checkout", "init", "--cone"},
		append([]string{"sparse-checkout", "set"}, Categories...),
		{"checkout", PinnedCommit},
	}
	for _, args := range steps {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = destDir
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git %v: %w\n%s", args, err, out)
		}
	}

	counts := make(map[string]int, len(Categories))
	for _, category := range Categories {
		n, err := countTemplateFiles(filepath.Join(destDir, category))
		if err != nil {
			return nil, fmt.Errorf("counting templates in %s: %w", category, err)
		}
		counts[category] = n
	}

	return &Result{Commit: PinnedCommit, CategoryCounts: counts}, nil
}

// countTemplateFiles counts .yaml/.yml files recursively under dir — same
// recursive shape as nuclei.LoadDir's own walk, and equivalent to the shell
// script's `find dir -name '*.yaml' -o -name '*.yml'`.
func countTemplateFiles(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(path)
		if ext == ".yaml" || ext == ".yml" {
			count++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}
