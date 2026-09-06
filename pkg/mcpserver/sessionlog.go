package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

// sessionLogEnv names an optional file the session log is also appended to,
// one JSON object per line (JSONL) — so a run driven through `hackerfive
// mcp-serve` leaves an inspectable artifact without a live Web UI view
// (doc15 Step 5's C1: "inspectable via a CLI dump or the MCP server's own
// job.log equivalent"). Unset means in-memory only, queryable via the
// session.log tool for the life of the connection.
const sessionLogEnv = "HACKERFIVE_SESSION_LOG"

// sessionLog is this server process's one append-only agent-session log.
// mcpserver holds no Job concept (unlike pkg/webui) — one long-lived stdio
// connection is one session, so a single process-wide log is the natural
// scope. Reset by New() so each freshly-built server (and each test) starts
// clean and re-reads sessionLogEnv.
var sessionLog = agenttask.NewSessionLog(nil)

// initSessionLog resets sessionLog, wiring in the JSONL sink named by
// sessionLogEnv when it's set and openable. A sink that can't be opened is
// a logged warning, not a startup failure — the in-memory log still works.
func initSessionLog() {
	path, ok := os.LookupEnv(sessionLogEnv)
	if !ok || path == "" {
		sessionLog = agenttask.NewSessionLog(nil)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcpserver: session log sink %q could not be opened (%v) — continuing in-memory only\n", path, err)
		sessionLog = agenttask.NewSessionLog(nil)
		return
	}
	sessionLog = agenttask.NewSessionLog(f)
}

// sessionLogInput queries the session log. Both fields are optional: no
// tool filter returns every recorded call; no limit returns all of them.
type sessionLogInput struct {
	ToolFilter string `json:"tool_filter,omitempty" jsonschema:"only return calls to this tool (exact name, e.g. \"scan\"); empty returns all"`
	Limit      int    `json:"limit,omitempty" jsonschema:"return only the most recent N entries; 0 or unset returns all"`
}

type sessionLogOutput struct {
	Entries []agenttask.SessionLogEntry `json:"entries"`
	Total   int                         `json:"total"`
}

// sessionLogOutputSchema — same reason plan uses an explicit one
// (tools_plan.go): SessionLogEntry.Params is a json.RawMessage carrying an
// arbitrary object, which the SDK's reflection infers as a byte array and
// then rejects at runtime when it serializes as a JSON object.
var sessionLogOutputSchema = json.RawMessage(`{"type":"object"}`)

func addSessionLogTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:         "session.log",
		Description:  "Return this MCP session's append-only log of prior tool calls — name, the caller's stated reason, a redacted parameter summary, timing, and outcome. Read-only; runs no scan and sends no request.",
		OutputSchema: sessionLogOutputSchema,
	}, func(_ context.Context, _ *mcp.CallToolRequest, in sessionLogInput) (*mcp.CallToolResult, sessionLogOutput, error) {
		entries := sessionLog.Query(in.ToolFilter, in.Limit)
		return nil, sessionLogOutput{Entries: entries, Total: len(sessionLog.Entries())}, nil
	})
}
