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

// Agency is the least-agency level a server process is launched at (doc16
// Phase 7 Step 1's A5, OWASP "least agency"). pkg/mcpserver runs over stdio —
// one client per process — so this is fixed at launch by `hackerfive
// mcp-serve --agency`, not negotiated per session. The zero value is
// AgencyFull, so an un-updated caller of New() is unaffected.
type Agency string

const (
	// AgencyFull registers every tool — the default and the only level that
	// can fire detector traffic at a target (scan), execute an approved plan
	// (plan), or rewrite the local synced corpus (templates.sync).
	AgencyFull Agency = "full"
	// AgencyReadOnly is a "recon + triage" session: passive recon, template
	// and capability metadata, the two elicitation-gated findings tools
	// (neither issues target traffic), and the session-log view. scan, plan
	// and templates.sync are not registered, so the client's tools/list never
	// shows them.
	AgencyReadOnly Agency = "readonly"
)

// New builds a fully-registered (AgencyFull) MCP server — the back-compatible
// convenience form. See NewWithAgency for the tool set at each level.
func New() *mcp.Server {
	return NewWithAgency(AgencyFull)
}

// NewWithAgency builds an MCP server whose registered tool set is filtered to
// agency. AgencyReadOnly omits scan, plan and templates.sync entirely (not a
// runtime refusal inside each handler — the tools simply aren't there);
// every other level, including the AgencyFull default and any unrecognized
// value, registers the whole set: recon, scan, templates.list,
// templates.sync, findings.export, findings.triage, tools.search,
// templates.search, plan (elicitation-gated, executing on approval — Phase 6
// Step 2), and session.log (Phase 6 Step 5's C1).
func NewWithAgency(agency Agency) *mcp.Server {
	// Reset (and, if HACKERFIVE_SESSION_LOG is set, re-open) this process's
	// agent session log before registering tools — see sessionlog.go.
	initSessionLog()

	s := mcp.NewServer(&mcp.Implementation{Name: "hackerfive", Version: version}, nil)

	// Always available: read-only enumeration, metadata/search, the two
	// elicitation-gated findings tools, and the session-log view.
	addReconTool(s)
	addTemplatesListTool(s)
	addFindingsExportTool(s)
	addFindingsTriageTool(s)
	addToolsSearchTool(s)
	addTemplatesSearchTool(s)
	addSessionLogTool(s)

	// AgencyFull only: the tools that reach a live target with detector
	// traffic, execute an approved plan, or mutate the local corpus.
	if agency != AgencyReadOnly {
		addScanTool(s)
		addTemplatesSyncTool(s)
		addPlanTool(s)
	}

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
