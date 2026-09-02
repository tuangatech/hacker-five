package mcpserver

import (
	"context"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner"
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
		if err := cfg.Validate(); err != nil {
			return nil, scanOutput{}, err
		}

		var out scanOutput
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
