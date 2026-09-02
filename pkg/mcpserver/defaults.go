package mcpserver

import "time"

// defaultRateLimit/defaultConcurrency/defaultTimeout mirror
// cmd/hackerfive/scan.go's own CLI flag defaults (pkg/webui/handlers_scan.go
// does the same) — an MCP tool call doesn't expose every CLI flag as a tool
// argument, so these are the values used when a caller doesn't need to
// override them.
const (
	defaultRateLimit   = 50
	defaultConcurrency = 25
	defaultTimeout     = 30 * time.Second
)

// defaultTemplateIndexPath mirrors cmd/hackerfive/templates.go's `templates
// index` default output path and pkg/webui's own constant of the same name
// — the file `hackerfive templates index` produces and templates.search/
// plan read, degrading gracefully (not a hard failure) if it doesn't exist
// yet, same posture as cmd/hackerfive/plan.go.
const defaultTemplateIndexPath = "templates/index.json"
