package recon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

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

// errWaveTimeout marks a wave binary that was killed by its per-wave context
// deadline (r.waveTimeout) rather than exiting on its own. defaultRun still
// returns the stdout captured up to the kill alongside this error, so a
// caller logs "results may be partial" and parses what it got instead of
// silently treating a truncated run as "found nothing" (docs/follow-up.md
// LT-38: runNaabu's top-100-port scan across every in-scope host routinely
// hits the cap past ~6 hosts, and the partial port list was used with no
// visible trace it had been cut off).
//
// cap records the wave timeout that was in effect, for the operator-facing
// message. defaultRun cannot know it (it only sees a ctx deadline), so it
// leaves cap zero and (*Recon).run re-stamps it with r.waveTimeout (LT-111).
type errWaveTimeout struct{ cap time.Duration }

// Error carries no tool name — every caller already prefixes the wave and
// tool ("wave2: naabu: %v"), so naming it here only doubled it.
func (e *errWaveTimeout) Error() string {
	cap := e.cap
	if cap <= 0 {
		cap = DefaultWaveTimeout
	}
	return fmt.Sprintf("hit the %s wave time cap — results may be partial", cap)
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
		// A per-wave deadline (r.waveTimeout) SIGKILLs the process; its stdout
		// so far is still worth returning, but flagged as errWaveTimeout so a
		// caller doesn't read a truncated run as an empty result set (LT-38).
		// cap is left zero here — (*Recon).run stamps in the configured
		// timeout for the operator-facing message (LT-111). Checked before the
		// ExitError branch — a killed process also surfaces as an
		// *exec.ExitError.
		if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return out, &errWaveTimeout{}
		}
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

// isWaveTimeout reports whether err is (or wraps) errWaveTimeout — a wave
// binary the per-wave deadline killed, whose partial stdout is still usable.
func isWaveTimeout(err error) bool {
	var timeout *errWaveTimeout
	return errors.As(err, &timeout)
}
