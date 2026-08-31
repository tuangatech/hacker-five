package recon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/toolsync"
)

// errBinaryMissing wraps a tool name so callers can turn "not installed"
// into a logged Warnings entry instead of a hard failure — every wave that
// shells out degrades this way, never a fatal error (docs/91-research-
// recon-phase.md §5 / docs/14-implementation-plan-ph5.md Step 3's Files
// note: "a missing binary degrades that wave to a logged warning").
type errBinaryMissing struct {
	name string
}

func (e *errBinaryMissing) Error() string {
	return fmt.Sprintf("%s: binary not found on PATH", e.name)
}

// runFunc executes name with args and returns its stdout. stdin, if
// non-empty, is piped to the process — several ProjectDiscovery tools
// accept a target list via "-l -" (read stdin) rather than one argument per
// target, the standard way these tools chain together. Injectable via
// withRun (test-only Option) so unit tests can simulate binary output — or
// a missing binary — deterministically without the real tools installed.
type runFunc func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)

// resolveBinaryPath finds name either on PATH (which wins, so a user's own
// manual install/override is always respected) or, failing that, in
// toolsync.DefaultInstallDir() — where `hackerfive recon setup` places
// these binaries for anyone without a Go toolchain to `go install` them
// manually (docs/04-environment-and-testing.md §2). Returns errBinaryMissing
// if neither has it, same as a bare exec.LookPath failure did before.
func resolveBinaryPath(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	if dir, err := toolsync.DefaultInstallDir(); err == nil {
		p := toolsync.InstalledPath(dir, name)
		if info, statErr := os.Stat(p); statErr == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", &errBinaryMissing{name: name}
}

// defaultRun is runFunc's real implementation: resolveBinaryPath first (so
// a missing binary is reported as errBinaryMissing, not a generic "exec:
// unrecognized" error a caller would have to string-match), then run it and
// return stdout. A non-zero exit with no stdout is treated as this wave
// simply finding nothing, not a hard failure — every one of these binaries
// (subfinder/tlsx/dnsx/naabu/httpx/katana) can legitimately exit non-zero
// for "no results," which callers already treat as an empty result set.
func defaultRun(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	path, err := resolveBinaryPath(name)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return out, nil
		}
		return nil, fmt.Errorf("recon: running %s: %w", name, err)
	}
	return out, nil
}

// isBinaryMissing reports whether err is (or wraps) errBinaryMissing.
func isBinaryMissing(err error) bool {
	var missing *errBinaryMissing
	return errors.As(err, &missing)
}
