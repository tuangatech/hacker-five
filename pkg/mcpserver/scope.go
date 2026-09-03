package mcpserver

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// requireScope builds a *scope.Scope from entries and hard-fails if entries
// is empty — doc15 Step 1's D3, pulled forward from Step 3. The CLI's own
// "warn, don't silently proceed" default for a missing --scope (doc02 §3)
// is the right behavior for a human who typed the command and can read the
// warning; nobody reads a warning behind an agent-initiated MCP tool call,
// so every agent-initiated scan/recon/plan call rejects outright here,
// before an Engine/recon.Run is ever constructed. This is the one hard
// safety gate this package's tool handlers cannot be called without.
func requireScope(entries []string) (*scope.Scope, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("scope is required: pass at least one domain/*.domain/CIDR allow-list entry — an agent-initiated call is never allowed to run unscoped, unlike a human-typed CLI command")
	}
	sc, err := scope.New(entries)
	if err != nil {
		return nil, fmt.Errorf("parsing scope: %w", err)
	}
	return sc, nil
}

// clientSupportsElicitation mirrors the SDK's own ServerSession.Elicit gate
// (mcp/server.go) — checked here, before plan/findings.triage ever return
// InputRequests, so a client that never declared elicitation capability
// gets a clean "returned unexecuted" result instead of an error surfacing
// from deep inside the multi-round-trip machinery. Real gap found and fixed
// 2026-09-02: the original design (Step 2 kickoff) called for exactly this
// degrade, but it was lost when ServerSession.Elicit turned out not to be
// callable synchronously mid-request (see tools_plan.go's Done-note-linked
// comments) — this restores the intended behavior against the corrected
// SEP-2322 mechanism.
func clientSupportsElicitation(session *mcp.ServerSession) bool {
	iparams := session.InitializeParams()
	return iparams != nil && iparams.Capabilities != nil && iparams.Capabilities.Elicitation != nil
}
