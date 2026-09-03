package mcpserver

import (
	"context"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// toolsSearchInput/Output — the answer to "should every detector/recon-
// tool/template be its own MCP tool": no (doc15 Step 1's own Design
// section). A thin query wrapper over pkg/registry's static Capabilities
// list.
type toolsSearchInput struct {
	Query string `json:"query" jsonschema:"keyword to match against capability name/description/when-to-use"`
}

type toolsSearchOutput struct {
	Capabilities []registry.Capability `json:"capabilities"`
}

func addToolsSearchTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "tools.search",
		Description: "Search HackerFive's capability registry (detectors, recon tools, template categories) by keyword.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in toolsSearchInput) (*mcp.CallToolResult, toolsSearchOutput, error) {
		return nil, toolsSearchOutput{Capabilities: registry.Search(in.Query)}, nil
	})
}

type templatesSearchInput struct {
	Query string `json:"query" jsonschema:"keyword to match against a template's name/tags"`
}

type templatesSearchOutput struct {
	Templates []templatesync.Entry `json:"templates"`
}

func addTemplatesSearchTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "templates.search",
		Description: "Search templates/index.json by keyword against a template's name/tags. Empty result if the index hasn't been generated yet (run templates.sync then 'hackerfive templates index').",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in templatesSearchInput) (*mcp.CallToolResult, templatesSearchOutput, error) {
		index, err := templatesync.LoadIndex(defaultTemplateIndexPath)
		if err != nil {
			return nil, templatesSearchOutput{}, nil // graceful degrade, same posture as plan/plan-preview
		}
		return nil, templatesSearchOutput{Templates: searchTemplateEntries(in.Query, index)}, nil
	})
}

// searchTemplateEntries is a case-insensitive substring match against
// Name/Tags — deliberately no scoring/ranking, same reasoning as
// registry.Search: a few thousand entries at most, a linear scan is
// instant.
func searchTemplateEntries(query string, entries []templatesync.Entry) []templatesync.Entry {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	var matches []templatesync.Entry
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Name), q) {
			matches = append(matches, e)
			continue
		}
		for _, tag := range e.Tags {
			if strings.Contains(strings.ToLower(tag), q) {
				matches = append(matches, e)
				break
			}
		}
	}
	return matches
}

// addPlanTool/planInput/planOutput moved to tools_plan.go in Phase 6 Step
// 2, once the tool grew elicitation/I4-fallback/execution beyond Step 1's
// minimal recon->registry.Resolve pipeline.
