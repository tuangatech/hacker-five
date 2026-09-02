package main

import (
	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/mcpserver"
)

// newMCPServeCmd is `hackerfive mcp-serve` — runs pkg/mcpserver over stdio
// (docs/15-implementation-plan-ph6.md Step 1). A second frontend on the
// same unchanged scanner/recon/template/reporter core `serve` (the Web UI)
// already uses, not a second implementation of it.
func newMCPServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp-serve",
		Short: "Run HackerFive as an MCP server over stdio (for Claude Desktop, Claude Code, or any MCP client)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcpserver.Serve(cmd.Context(), mcpserver.New())
		},
	}
}
