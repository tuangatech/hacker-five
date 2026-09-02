package mcpserver

import (
	"fmt"

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
