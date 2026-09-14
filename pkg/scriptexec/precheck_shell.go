package scriptexec

import (
	"fmt"
	"path"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
	"mvdan.cc/sh/v3/syntax"
)

// shellBlockedCommands are command names whose mere presence, run as the
// first word of a call, means the script intends further interpreter/
// subprocess spawning, a raw network connection outside the egress proxy,
// or privilege escalation — checked against the call's base name (a literal
// leading path like /bin/bash is stripped first) since the sandbox's own
// PATH can't be trusted to be absent these binaries.
var shellBlockedCommands = map[string]string{
	"nc":      "netcat can open arbitrary raw connections (bypasses the egress proxy)",
	"ncat":    "netcat can open arbitrary raw connections (bypasses the egress proxy)",
	"socat":   "can open arbitrary raw connections (bypasses the egress proxy)",
	"ssh":     "further remote command execution",
	"telnet":  "raw socket connection (bypasses the egress proxy)",
	"bash":    "further interpreter spawning",
	"sh":      "further interpreter spawning",
	"zsh":     "further interpreter spawning",
	"dash":    "further interpreter spawning",
	"ksh":     "further interpreter spawning",
	"python":  "further interpreter spawning",
	"python2": "further interpreter spawning",
	"python3": "further interpreter spawning",
	"perl":    "further interpreter spawning",
	"ruby":    "further interpreter spawning",
	"node":    "further interpreter spawning",
	"php":     "further interpreter spawning",
	"lua":     "further interpreter spawning",
	"mkfifo":  "named-pipe creation (commonly used to build a reverse shell)",
	"sudo":    "privilege escalation",
	"su":      "privilege escalation",
	"doas":    "privilege escalation",
	"chroot":  "sandbox escape attempt",
}

func precheckShell(source string, sc *scope.Scope) (PrecheckResult, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(source), "")
	if err != nil {
		return PrecheckResult{Blocked: true, Reasons: []string{"shell syntax error: " + err.Error()}}, nil
	}

	var reasons []string
	var literals []string

	syntax.Walk(f, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			if len(n.Args) > 0 {
				if cmd, ok := literalWord(n.Args[0]); ok {
					base := path.Base(cmd)
					if reason, blocked := shellBlockedCommands[base]; blocked {
						reasons = append(reasons, fmt.Sprintf("command %q: %s", cmd, reason))
					}
				}
			}
			for _, arg := range n.Args {
				if lit, ok := literalWord(arg); ok {
					literals = append(literals, lit)
					if pathOutsideScratch(lit) {
						reasons = append(reasons, fmt.Sprintf("filesystem access to %q falls outside the sandbox scratch dir %s", lit, ScratchDir))
					}
				}
			}
		case *syntax.Redirect:
			if lit, ok := literalWord(n.Word); ok {
				switch {
				case strings.HasPrefix(lit, "/dev/tcp/") || strings.HasPrefix(lit, "/dev/udp/"):
					reasons = append(reasons, fmt.Sprintf("redirect to %q: raw socket via a shell network device (bypasses the egress proxy)", lit))
				case pathOutsideScratch(lit):
					reasons = append(reasons, fmt.Sprintf("redirect to %q falls outside the sandbox scratch dir %s", lit, ScratchDir))
				}
				literals = append(literals, lit)
			}
		}
		return true
	})

	reasons = append(reasons, hostLiteralsOutOfScope(literals, sc)...)

	return PrecheckResult{Blocked: len(reasons) > 0, Reasons: reasons}, nil
}

// literalWord returns the concatenated literal value of w if every part of
// it is a plain literal or a single/double-quoted string with no variable
// expansion, command substitution, or arithmetic — the only shape this
// heuristic check can evaluate with confidence (unlike syntax.Word.Lit(),
// which only covers bare, unquoted literals). A word built from anything
// dynamic returns ok=false and is simply not checked here: the sandbox's
// network/filesystem layers are the backstop for whatever this static,
// best-effort check can't resolve.
func literalWord(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, dp := range p.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}
