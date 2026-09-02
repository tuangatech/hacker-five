package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
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

// planInput/Output — the minimal plan tool (doc15 Step 1). Mirrors
// cmd/hackerfive/plan.go's exact pipeline: recon -> registry.Resolve. No
// elicitation/approval here — Step 2 adds that on top of this same
// handler; this step's tree is inspectable but not yet actionable.
type planInput struct {
	Target string   `json:"target" jsonschema:"target URL/domain to run recon against, then plan"`
	Scope  []string `json:"scope" jsonschema:"required allow-list (domain, *.domain, or CIDR entries); the call is refused if empty"`
	Depth  string   `json:"depth,omitempty" jsonschema:"one of passive, active, full (default: active — Wave 2's httpx tech signals are what the decision engine matches against)"`
}

type planOutput struct {
	Tree *agenttask.PlanTree `json:"tree"`
}

// planOutputSchema is supplied explicitly rather than left for AddTool to
// infer: agenttask.PlanNode is self-referential (Children []*PlanNode), and
// jsonschema-go's reflection-based ForType cannot represent a recursive Go
// type (confirmed live — AddTool panics with "cycle detected for type
// agenttask.PlanNode" without this override). A permissive object schema
// means the wire-level PlanTree JSON isn't schema-validated on the way out,
// which is fine here: PlanTree's own real structure is already enforced at
// construction time by registry.Resolve/agenttask.PlanTree, not by this
// tool's output schema.
var planOutputSchema = json.RawMessage(`{"type":"object"}`)

func addPlanTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:         "plan",
		Description:  "Run recon against a target, then resolve it to a PlanTree via the deterministic decision engine. Step 1: inspectable only, no approval gate yet. Refuses to run without an explicit scope allow-list.",
		OutputSchema: planOutputSchema,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in planInput) (*mcp.CallToolResult, planOutput, error) {
		sc, err := requireScope(in.Scope)
		if err != nil {
			return nil, planOutput{}, err
		}

		depth := recon.Depth(in.Depth)
		switch depth {
		case "":
			depth = recon.DepthActive
		case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
		default:
			return nil, planOutput{}, fmt.Errorf(`depth must be "passive", "active", or "full", got %q`, in.Depth)
		}

		index, _ := templatesync.LoadIndex(defaultTemplateIndexPath) // nil index degrades to skipping template-tag matching, not a hard failure

		client := httpclient.New(httpclient.Config{
			Timeout:             defaultTimeout,
			MaxRedirects:        5,
			MaxIdleConnsPerHost: defaultConcurrency,
		}, httpclient.WithRateLimit(ratelimit.New(defaultRateLimit)))

		r := recon.New(client, recon.WithScope(sc), recon.WithRateLimit(defaultRateLimit), recon.WithConcurrency(defaultConcurrency))
		result, err := r.Run(ctx, in.Target, depth)
		if err != nil {
			return nil, planOutput{}, err
		}

		return nil, planOutput{Tree: registry.Resolve(result, index)}, nil
	})
}
