// Package scriptexec is the sandboxed Python/shell script tool
// docs/93-implementation-plan-agent-orchestrator.md M1 (and docs/92-
// research-llm-orchestrator.md §5b) introduce as a single, scoped carve-out
// of doc90 Decision 2 ("no shell/exec-shaped tool, anywhere"): exploration a
// fixed detector/template genuinely cannot do (non-numeric ID-space
// decoding, custom signing-scheme reverse-engineering, JWT algorithm
// confusion, ...). Used only inside the opt-in `hackerfive agent` mode
// behind --allow-agent-scripts, and gated by a human approval on every
// single call — never a batch/blanket approval.
//
// Three independent layers stand between an LLM-authored script and doing
// real damage, each closing a gap the others don't:
//
//  1. Precheck (precheck_python.go / precheck_shell.go): a real AST walk
//     rejecting further subprocess/interpreter spawning, raw socket/ssl use,
//     filesystem access outside the sandbox's scratch dir, and out-of-scope
//     host literals. It runs BEFORE a human ever sees the script — a
//     rejected script never reaches the approval prompt.
//  2. HITL approval (the caller's ApprovalGate): a human is shown the exact
//     script text and the precheck result and must explicitly approve. No
//     batch/blanket approval — one prompt per script, every time.
//  3. The sandbox itself (sandbox.go): a Docker container with a read-only
//     root filesystem, no Linux capabilities, resource/time limits, and
//     network access routed only through the egress-allowlisting proxy
//     (egressproxy) — even a script that evaded layers 1 and 2 cannot reach
//     anything out of scope or write anything durable.
//
// No layer here ever produces a Finding on its own. A script's stdout/exit
// code is evidence for the human approving it, never evidence a Finding
// ships on by itself — pkg/orchestrator must independently re-issue any
// discovered request through the normal pkg/scanner/httpclient path before
// packaging it as Finding.Evidence (docs/follow-up.md LT-157).
package scriptexec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// Language is a script's source language — the only two scripting runtimes
// baked into the sandbox image (sandbox.go); anything else is rejected by
// Precheck before any container ever starts.
type Language string

const (
	LangPython Language = "python"
	LangShell  Language = "shell"
)

// ApprovalGate is the human-in-the-loop check every ScriptRequest must carry
// (Execute refuses to run without one): given the request and its Precheck
// result, the caller shows a human the exact script text and blocks until
// they explicitly approve or reject. There is no batch/blanket-approval
// shape in this API — one call per script, every time.
type ApprovalGate func(ctx context.Context, req ScriptRequest, pre PrecheckResult) (approved bool, err error)

// ScriptRequest is one script the orchestrator (pkg/orchestrator) proposes
// running. Scope, when non-nil, bounds both the precheck's host-literal
// check and the sandbox's egress proxy to the same authorized target list a
// scan already runs under — a script can never reach further than the scan
// itself is allowed to.
type ScriptRequest struct {
	Language     Language
	Source       string
	Scope        *scope.Scope
	Timeout      time.Duration
	ApprovalGate ApprovalGate
}

// PrecheckResult is Precheck's verdict. A Blocked result is never shown to
// ApprovalGate — Execute returns ErrPrecheckBlocked immediately, so a
// rejected script never reaches a human's approval prompt at all.
type PrecheckResult struct {
	Blocked bool
	Reasons []string
}

// ScriptResult is one sandboxed run's raw output. Truncated is set when
// Stdout/Stderr were cut off at the sandbox's output size cap, so a caller
// doesn't mistake a truncated capture for the script's complete output.
type ScriptResult struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

var (
	// ErrUnsupportedLanguage is returned by Precheck/Execute for any
	// Language other than LangPython/LangShell.
	ErrUnsupportedLanguage = errors.New("scriptexec: unsupported language")
	// ErrPrecheckBlocked means the static AST check rejected the script
	// before a human ever saw it. The reasons are embedded in the error text.
	ErrPrecheckBlocked = errors.New("scriptexec: static precheck blocked this script")
	// ErrNoApprovalGate means the caller built a ScriptRequest with no
	// ApprovalGate — Execute refuses to run a script unattended rather than
	// defaulting to either approve or reject.
	ErrNoApprovalGate = errors.New("scriptexec: no ApprovalGate configured — refusing to execute unattended")
	// ErrNotApproved means a human (or the caller's ApprovalGate) declined
	// to approve the script.
	ErrNotApproved = errors.New("scriptexec: script was not approved for execution")
)

// Precheck runs the static AST-based check for req.Language against
// req.Source (and, when req.Scope is set, checks string literals that look
// like hostnames/URLs against it). It never executes the script.
func Precheck(req ScriptRequest) (PrecheckResult, error) {
	switch req.Language {
	case LangPython:
		return precheckPython(req.Source, req.Scope)
	case LangShell:
		return precheckShell(req.Source, req.Scope)
	default:
		return PrecheckResult{}, fmt.Errorf("%w: %q", ErrUnsupportedLanguage, req.Language)
	}
}

// Execute runs req's script through, in order: Precheck (reject-on-match
// never reaches the reviewer), req.ApprovalGate (the human gate — required,
// never skipped), then the sandboxed container run (sandbox.go). Any failure
// at an earlier stage short-circuits — a blocked precheck or a declined
// approval never starts a container.
func Execute(ctx context.Context, req ScriptRequest) (ScriptResult, error) {
	pre, err := Precheck(req)
	if err != nil {
		return ScriptResult{}, err
	}
	if pre.Blocked {
		return ScriptResult{}, fmt.Errorf("%w: %s", ErrPrecheckBlocked, strings.Join(pre.Reasons, "; "))
	}
	if req.ApprovalGate == nil {
		return ScriptResult{}, ErrNoApprovalGate
	}
	approved, err := req.ApprovalGate(ctx, req, pre)
	if err != nil {
		return ScriptResult{}, fmt.Errorf("scriptexec: approval gate: %w", err)
	}
	if !approved {
		return ScriptResult{}, ErrNotApproved
	}
	return runSandboxed(ctx, req)
}
