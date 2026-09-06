// Package mcpserver exposes HackerFive's existing scan/recon/template/
// reporting machinery as MCP tools (docs/15-implementation-plan-ph6.md Step
// 1, docs/90-research-hackerbot.md's Decision 3). Every tool calls straight
// into pkg/scanner/pkg/recon/pkg/template/pkg/reporter/pkg/registry — the
// same boundary doc12 already drew for pkg/webui (a second frontend on the
// unchanged core, not a second implementation of it). Deliberately excludes
// anything shell/exec-shaped (Decision 2): every path to a Finding still
// runs through the existing deterministic matcher/extractor engine.
package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// version is the MCP server's own Implementation.Version — bumped
// alongside the CLI's own version string (cmd/hackerfive), not tied to it
// mechanically since this package has no import path back to cmd/hackerfive.
const version = "0.6.0-dev"

// New builds a fully-registered MCP server: scan, templates.list,
// templates.sync, findings.export, findings.triage, recon, tools.search,
// templates.search, plan — the last now elicitation-gated and executing
// on approval (Phase 6 Step 2, tools_plan.go), not just inspectable as it
// was in Step 1 — and session.log, the read-only view over this session's
// append-only agent-call log (Phase 6 Step 5's C1).
func New() *mcp.Server {
	// Reset (and, if HACKERFIVE_SESSION_LOG is set, re-open) this process's
	// agent session log before registering tools — see sessionlog.go.
	initSessionLog()

	s := mcp.NewServer(&mcp.Implementation{Name: "hackerfive", Version: version}, nil)

	addScanTool(s)
	addReconTool(s)
	addTemplatesListTool(s)
	addTemplatesSyncTool(s)
	addFindingsExportTool(s)
	addFindingsTriageTool(s)
	addToolsSearchTool(s)
	addTemplatesSearchTool(s)
	addPlanTool(s)
	addSessionLogTool(s)

	return s
}

// Serve runs server over stdio until ctx is cancelled or the transport
// closes — the same "one process, one long-lived connection" shape every
// comparable Go MCP server uses by default.
func Serve(ctx context.Context, server *mcp.Server) error {
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("mcpserver: %w", err)
	}
	return nil
}
