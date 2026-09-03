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

// llmFallbackResolutionConcurrency caps how many I4 fallback calls
// (leaf/field resolution) run at once while the plan tool builds a proposal
// — the real budget-burn-during-resolution concern doc15 Step 2's I4
// section names (many parallel frontier calls burn spend before H5's
// ceiling gets a chance to trip). Small and fixed, not derived from
// defaultConcurrency.
const llmFallbackResolutionConcurrency = 3

// llmAssistedExecConcurrency caps how many leaves whose Detector was chosen
// by the LLM fallback (use_existing_tag), rather than deterministically by
// R8, run concurrently once a plan is approved — a smaller blast radius on
// a live target for a detector assignment that wasn't deterministically
// validated, mirroring pkg/scanner/engine.go's own
// promptInjectionSafeConcurrency precedent for capping a specific riskier
// category lower than the general pool.
const llmAssistedExecConcurrency = 3

// defaultTemplateIndexPath mirrors cmd/hackerfive/templates.go's `templates
// index` default output path and pkg/webui's own constant of the same name
// — the file `hackerfive templates index` produces and templates.search/
// plan read, degrading gracefully (not a hard failure) if it doesn't exist
// yet, same posture as cmd/hackerfive/plan.go.
const defaultTemplateIndexPath = "templates/index.json"
