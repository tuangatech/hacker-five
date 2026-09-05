package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// newPlanCmd wires pkg/recon and pkg/registry together end to end (doc14
// Step 3's R8): runs recon against target, then the deterministic decision
// engine, and prints the resulting PlanTree — the concrete, standalone,
// no-agent-required proof that a live ReconResult resolves to real
// PlanTree leaves with zero LLM calls (Decision 6).
func newPlanCmd(root *rootFlags) *cobra.Command {
	var (
		target        string
		depth         string
		scopeFile     string
		allowNoScope  bool
		rateLimit     int
		concurrency   int
		templateIndex string
		llmAssist     bool
	)

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Run recon against a target, then resolve it to a PlanTree via the deterministic decision engine (no agent/LLM involved)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--targets is required")
			}
			d := recon.Depth(depth)
			switch d {
			case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
			default:
				return fmt.Errorf(`--recon-depth must be "passive", "active", or "full", got %q`, depth)
			}

			s, err := requireScopeOrOptOut(scopeFile, allowNoScope, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			// A missing template index degrades to skipping template-tag
			// matching, not a hard failure — the same "missing optional
			// input, warn and continue" posture pkg/recon already uses for
			// a missing binary.
			var index []templatesync.Entry
			if entries, err := loadTemplateIndex(templateIndex); err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not load %s (%v) — template-tag matching skipped; run 'hackerfive templates index' first\n", templateIndex, err)
			} else {
				index = entries
				warnIndexDrift(cmd.ErrOrStderr(), index)
			}

			client := httpclient.New(recon.ClientConfig(httpclient.Config{
				Timeout:             root.timeout,
				MaxRedirects:        5,
				MaxIdleConnsPerHost: concurrency,
				ProxyURL:            root.proxy,
			}), httpclient.WithRateLimit(ratelimit.New(rateLimit)))

			opts := []recon.Option{recon.WithRateLimit(rateLimit), recon.WithConcurrency(concurrency)}
			if s != nil {
				opts = append(opts, recon.WithScope(s))
			}
			r := recon.New(client, opts...)

			ctx, cancel := context.WithTimeout(cmd.Context(), reconRunTimeout)
			defer cancel()

			result, err := r.Run(ctx, target, d)
			if err != nil {
				return fmt.Errorf("running recon: %w", err)
			}

			tree, leafContexts := registry.Resolve(result, index)

			// P2-4 (docs/follow-up.md): opt-in, since it's a real, metered
			// LLM call and today's default CLI behavior (zero LLM calls,
			// Decision 6's own standalone proof) should stay the default.
			// Mirrors the MCP plan tool's own ResolveTreeLeaves call, minus
			// the elicitation approval gate — that gate is deliberately kept
			// as MCP-only, not reproduced here (see docs/follow-up.md's P2-6
			// discussion for why plan's own approve-before-execute step
			// stays as-is). llmfallback.New() degrades to fbErr rather than
			// hard-failing when no tier is configured — ResolveTreeLeaves
			// already treats that as "every unresolved leaf escalates," the
			// same graceful-degrade posture every other caller of New() uses.
			if llmAssist {
				fb, fbErr := llmfallback.New()
				ceiling := llmfallback.PerCallDefaultSpendCeilingUSD()
				tree.SpendCeilingUSD = ceiling
				escalations := llmfallback.ResolveTreeLeaves(cmd.Context(), fb, fbErr, tree, registry.Capabilities, index, leafContexts)
				for _, e := range escalations {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "llm-assist: %s\n", e)
				}

				// P2-1: one extra recon-wide call, on top of ResolveTreeLeaves'
				// per-leaf calls — proposes additional leaves a per-fact rule
				// table might miss. Skipped once fb is nil (no tier
				// configured) or the spend ceiling ResolveTreeLeaves already
				// spent against is exhausted, same "don't spend past the
				// ceiling" posture as every other I4 call.
				if fb != nil && !(tree.SpendCeilingUSD > 0 && tree.SpendSoFar() >= tree.SpendCeilingUSD) {
					proposals, cost, err := fb.PlanFromRecon(cmd.Context(), result, registry.Capabilities)
					tree.AddSpend(cost)
					if err != nil {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "llm-assist: recon-wide proposal call failed: %v\n", err)
					} else {
						knownTemplateIDs := make(map[string]bool, len(index))
						for _, e := range index {
							knownTemplateIDs[e.ID] = true
						}
						if n := llmfallback.MergeLLMProposals(tree, proposals, registry.Capabilities, knownTemplateIDs); n > 0 {
							_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "llm-assist: merged %d recon-wide proposal(s)\n", n)
						}
					}
				}
			}

			out := cmd.OutOrStdout()
			if root.output != "" {
				f, err := os.Create(root.output)
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer func() { _ = f.Close() }()
				out = f
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(tree)
		},
	}

	cmd.Flags().StringVarP(&target, "targets", "t", "", "target URL to run recon against, then plan (required)")
	cmd.Flags().StringVar(&depth, "recon-depth", "active", `how far recon escalates before planning: "passive", "active" (default — Wave 2's httpx tech signals are what the decision engine matches against), "full"`)
	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to a target allow-list file (same format as scan's --scope; see .engagements/*/scope.txt for real examples) — required unless --allow-no-scope is set")
	cmd.Flags().BoolVar(&allowNoScope, "allow-no-scope", false, "proceed with no --scope boundary — every host recon discovers is treated as in-scope, including unrelated infrastructure (e.g. a shared CDN/vendor domain); lab/local use only, never a real engagement")
	cmd.Flags().IntVar(&rateLimit, "rate-limit", recon.DefaultRateLimit, "requests/sec passed to each external recon binary's own native rate-limit flag")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", recon.DefaultConcurrency, "concurrency passed to each external recon binary's own native concurrency flag")
	cmd.Flags().StringVar(&templateIndex, "template-index", "templates/index.json", "path to the index generated by 'hackerfive templates index' — missing file degrades to skipping template-tag matching, not a hard failure")
	cmd.Flags().BoolVar(&llmAssist, "llm-assist", false, "resolve any StatusUnresolved leaf via the tiered LLM fallback (I4) before printing the tree — off by default (zero LLM calls is 'plan's own no-agent-required proof); requires OPENROUTER_API_KEY and/or a local runtime (see pkg/llmfallback)")

	return cmd
}
