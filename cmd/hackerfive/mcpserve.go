package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/mcpserver"
)

// newMCPServeCmd is `hackerfive mcp-serve` — runs pkg/mcpserver over stdio
// (docs/15-implementation-plan-ph6.md Step 1). A second frontend on the
// same unchanged scanner/recon/template/reporter core `serve` (the Web UI)
// already uses, not a second implementation of it.
//
// --agency (doc16 Phase 7 Step 1's A5) fixes the least-agency level for this
// server process at launch: stdio is one client per process, so there is no
// per-session negotiation — an operator wanting a read-only assistant and a
// full one configures two MCP server entries with different --agency values.
func newMCPServeCmd() *cobra.Command {
	var agency string

	cmd := &cobra.Command{
		Use:   "mcp-serve",
		Short: "Run HackerFive as an MCP server over stdio (for Claude Desktop, Claude Code, or any MCP client)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if agency == "" {
				agency = os.Getenv("HACKERFIVE_MCP_AGENCY")
			}
			resolved, err := resolveAgency(agency)
			if err != nil {
				return err
			}
			if resolved == mcpserver.AgencyReadOnly {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "mcp-serve: agency=readonly — scan, plan and templates.sync are not registered for this session")
			}
			return mcpserver.Serve(cmd.Context(), mcpserver.NewWithAgency(resolved))
		},
	}

	cmd.Flags().StringVar(&agency, "agency", "", `least-agency level for this server process: "full" (default — every tool) or "readonly" (recon + template/capability metadata + findings triage/export + session log only; no scan/plan/templates.sync). Also read from HACKERFIVE_MCP_AGENCY.`)

	return cmd
}

// resolveAgency maps the --agency flag / HACKERFIVE_MCP_AGENCY value to a
// mcpserver.Agency. An empty value is the full default; anything else must be
// an exact, lower-cased match so a typo fails loudly rather than silently
// granting more agency than intended.
func resolveAgency(v string) (mcpserver.Agency, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "full":
		return mcpserver.AgencyFull, nil
	case "readonly", "read-only":
		return mcpserver.AgencyReadOnly, nil
	default:
		return "", fmt.Errorf("--agency must be \"full\" or \"readonly\", got %q", v)
	}
}
