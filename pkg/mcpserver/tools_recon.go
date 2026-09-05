package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
)

// reconInput is the recon tool's schema — schema-validated arguments, not a
// free-form command (doc91 §5's design constraint). Scope is required, same
// D3 treatment as scan.
type reconInput struct {
	Target string   `json:"target" jsonschema:"target URL/domain to run recon against"`
	Scope  []string `json:"scope" jsonschema:"required allow-list (domain, *.domain, or CIDR entries); the call is refused if empty"`
	Depth  string   `json:"depth,omitempty" jsonschema:"one of passive, active, full (default: passive)"`
}

type reconOutput struct {
	Result *recon.ReconResult `json:"result"`
}

func addReconTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "recon",
		Description: "Run HackerFive's recon phase against a target, escalating through fixed waves (subfinder/tlsx/dnsx/naabu/httpx/katana). Refuses to run without an explicit scope allow-list.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in reconInput) (*mcp.CallToolResult, reconOutput, error) {
		sc, err := requireScope(in.Scope)
		if err != nil {
			return nil, reconOutput{}, err
		}

		depth := recon.Depth(in.Depth)
		switch depth {
		case "":
			depth = recon.DepthPassive
		case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
		default:
			return nil, reconOutput{}, fmt.Errorf(`depth must be "passive", "active", or "full", got %q`, in.Depth)
		}

		// recon.ClientConfig forces InsecureSkipVerify true (LT-4,
		// docs/follow-up.md) — matches katana/httpx's own hardcoded TLS
		// posture; this client is never shared with scan's own detector
		// requests.
		client := httpclient.New(recon.ClientConfig(httpclient.Config{
			Timeout:             defaultTimeout,
			MaxRedirects:        5,
			MaxIdleConnsPerHost: defaultConcurrency,
		}), httpclient.WithRateLimit(ratelimit.New(defaultRateLimit)))

		token := req.Params.GetProgressToken()
		r := recon.New(client,
			recon.WithScope(sc),
			recon.WithRateLimit(defaultRateLimit),
			recon.WithConcurrency(defaultConcurrency),
			recon.WithProgressCallback(func(wave, status string) {
				if token == nil {
					return
				}
				_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
					ProgressToken: token,
					Message:       wave + ": " + status,
				})
			}),
		)

		result, err := r.Run(ctx, in.Target, depth)
		if err != nil {
			return nil, reconOutput{}, err
		}
		return nil, reconOutput{Result: result}, nil
	})
}
