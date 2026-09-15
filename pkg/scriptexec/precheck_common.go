package scriptexec

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// ScratchDir is the one writable path inside the sandbox container
// (sandbox.go mounts a size-capped tmpfs here) — both language precheckers
// flag any filesystem access whose literal path falls outside it, and
// sandbox.go's container args must agree on this exact path so a script
// that only ever touches ScratchDir behaves identically whether or not the
// precheck ran.
const ScratchDir = "/scratch"

// urlLiteralPattern matches a string literal shaped like an absolute URL —
// checked against req.Scope so a script can't hardcode a request to a host
// the scan itself isn't authorized to touch.
var urlLiteralPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://`)

// bareHostLiteralPattern matches a string literal shaped like a bare
// hostname (at least one dot, no path/scheme, no spaces) — the case a
// script builds a request manually (e.g. f"https://{host}/path" split
// across a separate host literal and an f-string) rather than one single
// URL literal. Deliberately conservative: requires a dot and alphanumeric
// labels only, so it doesn't flag arbitrary dotted strings like version
// numbers with letters or file names with two dots — the precheck already
// scopes its purpose to disallowed host literals, not name validation.
var bareHostLiteralPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,}$`)

// hostLiteralsOutOfScope checks every literal that looks like a URL or bare
// hostname against sc and returns one reason string per literal that fails.
// A nil sc means no scope was supplied — the sandbox's network topology
// (egressproxy) still enforces scope at the network layer for the actual
// run, so this only skips the earlier, defense-in-depth static check rather
// than blocking everything with no scope to check against.
func hostLiteralsOutOfScope(literals []string, sc *scope.Scope) []string {
	if sc == nil {
		return nil
	}
	var reasons []string
	for _, lit := range literals {
		var target string
		switch {
		case urlLiteralPattern.MatchString(lit):
			target = lit
		case bareHostLiteralPattern.MatchString(lit):
			target = "https://" + lit
		default:
			continue
		}
		if !sc.Allowed(target) {
			reasons = append(reasons, fmt.Sprintf("string literal %q names a host outside the authorized scope", lit))
		}
	}
	return reasons
}

// pathOutsideScratch reports whether path looks like a filesystem path
// (absolute, or a "../" escape) that falls outside ScratchDir — the
// precheck's filesystem-escape signal. Deliberately over-broad: a false
// positive here just means a human sees an extra (wrong) block reason, but
// a false negative would let a script write somewhere durable outside the
// sandbox's own read-only-rootfs defense, so this errs toward flagging.
func pathOutsideScratch(path string) bool {
	if path == "" {
		return false
	}
	if strings.Contains(path, "..") {
		return true
	}
	if strings.HasPrefix(path, "/") {
		return !strings.HasPrefix(path, ScratchDir+"/") && path != ScratchDir
	}
	return false
}
