package mcpserver

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// scanInput is the scan tool's schema. Scope is required (D3, doc15 Step
// 1) — a call with no entries is refused by requireScope before an Engine
// is ever constructed, never a silent CLI-style warning.
type scanInput struct {
	Targets          []string          `json:"targets" jsonschema:"target URLs to scan"`
	Scope            []string          `json:"scope" jsonschema:"required allow-list (domain, *.domain, or CIDR entries) every target must fall within; the call is refused if empty"`
	Detector         string            `json:"detector" jsonschema:"one of idor, misconfig, authbypass, ssrf, businesslogic"`
	Tags             []string          `json:"tags,omitempty" jsonschema:"only fire loaded templates carrying at least one of these tags (OR match); empty means no filtering"`
	EndpointTemplate string            `json:"endpoint_template,omitempty" jsonschema:"required for detector=idor, e.g. /api/report?id={{id}}"`
	ProtectedPaths   []string          `json:"protected_paths,omitempty" jsonschema:"required for detector=authbypass"`
	AuthToken        string            `json:"auth_token,omitempty" jsonschema:"owner-account auth token; also read from HACKERFIVE_AUTH_TOKEN if unset"`
	OtherAuthToken   string            `json:"other_auth_token,omitempty" jsonschema:"second-account auth token, for idor's baseline comparison"`
	AllowWrites      bool              `json:"allow_writes,omitempty" jsonschema:"required for detector=businesslogic's mutating checks; skipped with a warning otherwise"`
	ExtraHeaders     map[string]string `json:"extra_headers,omitempty"`
	TechStack        []recon.TechFact  `json:"tech_stack,omitempty" jsonschema:"optional — a prior recon tool call's result.tech_stack; adds this stack's product-specific template tags on top of the detector-category floor (LT-16/LT-17, doc15 Step 6a)"`
	AllTemplates     bool              `json:"all_templates,omitempty" jsonschema:"load the full ~9.5k synced corpus, bypassing the default per-detector template scoping (doc15 Step 6a); no effect when tags is set"`
}

// scanOutput is the scan tool's result: every Finding the run produced,
// plus the same warning/error log lines a CLI run prints to stderr —
// nothing here bypasses the deterministic matcher/extractor engine
// (Decision 2); the agent selects targets/detector, it never crafts a raw
// request.
type scanOutput struct {
	Findings []detectors.Finding `json:"findings"`
	Logs     []string            `json:"logs,omitempty"`
}

func addScanTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "scan",
		Description: "Run a HackerFive detector (plus the loaded template corpus) against one or more targets. Refuses to run without an explicit scope allow-list.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in scanInput) (*mcp.CallToolResult, scanOutput, error) {
		sc, err := requireScope(in.Scope)
		if err != nil {
			return nil, scanOutput{}, err
		}

		authToken := in.AuthToken
		if authToken == "" {
			authToken = os.Getenv("HACKERFIVE_AUTH_TOKEN")
		}

		cfg := scanner.Config{
			Targets:          in.Targets,
			TemplatePaths:    defaultTemplateDirs(),
			Tags:             in.Tags,
			Detector:         in.Detector,
			Concurrency:      defaultConcurrency,
			RateLimit:        defaultRateLimit,
			Timeout:          defaultTimeout,
			OutputFormat:     "json",
			AuthToken:        authToken,
			OtherAuthToken:   in.OtherAuthToken,
			EndpointTemplate: in.EndpointTemplate,
			ProtectedPaths:   in.ProtectedPaths,
			AllowWrites:      in.AllowWrites,
			ExtraHeaders:     in.ExtraHeaders,
			Scope:            sc,
		}

		var out scanOutput
		// doc15 Step 6a: template scoping is on by default. An explicit Tags
		// wins untouched; all_templates forces the full synced corpus;
		// otherwise the scan is scoped to its detector's category floor
		// (registry.DetectorTemplateTags) plus — when a prior recon tool
		// call's tech_stack is passed along — that stack's product-specific
		// tags (registry.TechStackTags). Degrades to floor-only, then to the
		// full corpus, with a logged note rather than an error.
		if len(in.Tags) == 0 && !in.AllTemplates {
			floor := registry.DetectorTemplateTags(in.Detector)
			var extras []string
			if len(in.TechStack) > 0 {
				if index, idxErr := templatesync.LoadIndex(defaultTemplateIndexPath); idxErr == nil {
					extras = registry.TechStackTags(in.TechStack, index)
				} else {
					out.Logs = append(out.Logs, fmt.Sprintf("warn: template scope: could not load template index (%v) — scoping by detector category only", idxErr))
				}
			}
			cfg.DerivedTags = unionScanTags(floor, extras)
			switch {
			case len(cfg.DerivedTags) == 0:
				out.Logs = append(out.Logs, fmt.Sprintf("info: template scope: %s has no category floor and no tech match — running the full corpus", in.Detector))
			case len(extras) > 0:
				out.Logs = append(out.Logs, fmt.Sprintf("info: template scope: %d tag(s) = %d %s-category floor + %d tech-matched: %s", len(cfg.DerivedTags), len(floor), in.Detector, len(extras), strings.Join(cfg.DerivedTags, ", ")))
			default:
				out.Logs = append(out.Logs, fmt.Sprintf("info: template scope: %d %s-category tag(s) (pass a recon tech_stack for tech-matched CVEs, or all_templates for everything): %s", len(cfg.DerivedTags), in.Detector, strings.Join(cfg.DerivedTags, ", ")))
			}
		}

		if err := cfg.Validate(); err != nil {
			return nil, scanOutput{}, err
		}
		token := req.Params.GetProgressToken()
		notify := func(message string) {
			if token == nil {
				return
			}
			_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
				ProgressToken: token,
				Message:       message,
			})
		}

		engine := scanner.New(cfg).
			WithFindingCallback(func(f detectors.Finding) {
				out.Findings = append(out.Findings, f)
				notify("finding: " + f.Type + " on " + f.Target)
			}).
			WithLogCallback(func(level, msg string) {
				out.Logs = append(out.Logs, level+": "+msg)
				notify(msg)
			})

		if _, err := engine.Run(ctx); err != nil {
			return nil, out, err
		}
		return nil, out, nil
	})
}

// defaultTemplateDirs is defaultTemplateDirsWithLabels (tools_templates.go)
// without the labels — scan's TemplatePaths doesn't need per-source labels,
// only the directory list.
func defaultTemplateDirs() []string {
	dirs, _ := defaultTemplateDirsWithLabels()
	return dirs
}

// unionScanTags is the detector-category floor ∪ tech-matched extras
// composition for the scan tool's doc15 Step 6a default template scoping —
// order-stable, de-duplicated, lower-cased (mirrors cmd/hackerfive's
// unionTags and pkg/webui's unionLaunchTags; each package keeps its own
// copy rather than a shared util for one small helper).
func unionScanTags(floor, extras []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]string{floor, extras} {
		for _, t := range group {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
