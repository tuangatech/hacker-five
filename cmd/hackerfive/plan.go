package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
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
		target              string
		depth               string
		scopeFile           string
		allowNoScope        bool
		rateLimit           int
		concurrency         int
		templateIndex       string
		llmAssist           bool
		verbose             bool
		policyFile          string
		allowPolicyOverride bool
		reconFile           string
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
			// D2 pre-flight: block early (before spending recon time) on a
			// policy.yaml disallowed verdict; the security.txt/robots.txt
			// advisory signals are re-checked after recon below.
			if err := runPreflight([]string{target}, policyFile, scopeFile, allowPolicyOverride, nil, cmd.ErrOrStderr()); err != nil {
				return err
			}

			// LT-36: a program that mandates an identifying request header
			// (policy.yaml request_headers:) must have it on plan's recon
			// traffic too, not just scan's.
			policyHeaders, err := policyRequestHeaders(policyFile, scopeFile)
			if err != nil {
				return err
			}
			if reconFile == "" {
				_, fromPolicy := mergeHeaders(policyHeaders, nil)
				for _, name := range fromPolicy {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "plan: applying policy-mandated request header %q to recon probes (LT-36)\n", name)
				}
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

			// LT-34 (docs/follow-up.md): reuse a prior `hackerfive recon
			// --output <path>` result instead of re-running an identical
			// wave0…wave3 (measured: recon 2m15s, then plan re-ran the same
			// for another ~2m15s). --scope/preflight above still apply; the
			// recon client is never built when a file is supplied.
			var result *recon.ReconResult
			if reconFile != "" {
				data, err := os.ReadFile(reconFile)
				if err != nil {
					return fmt.Errorf("reading --recon-file: %w", err)
				}
				var rr recon.ReconResult
				if err := json.Unmarshal(data, &rr); err != nil {
					return fmt.Errorf("parsing --recon-file: %w", err)
				}
				result = &rr
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "plan: using recon result from %s (%d host(s), %d endpoint(s), %d tech fact(s)) — skipping the recon run\n",
					reconFile, len(rr.Hosts), len(rr.Endpoints), len(rr.TechStack))
			} else {
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
				if verbose {
					opts = append(opts, recon.WithProgressCallback(verboseProgress(cmd.ErrOrStderr())))
				}
				if len(policyHeaders) > 0 {
					opts = append(opts, recon.WithHeaders(policyHeaders))
				}
				r := recon.New(client, opts...)

				ctx, cancel := context.WithTimeout(cmd.Context(), reconRunTimeout)
				defer cancel()

				result, err = r.Run(ctx, target, d)
				if err != nil {
					return fmt.Errorf("running recon: %w", err)
				}
			}
			for _, w := range signalWarningsFromRecon(result) {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "preflight: "+w)
			}

			tree, leafContexts := registry.Resolve(result, index)

			// A6 (doc16 Phase 7 Step 1): recon-derived field suggestions,
			// previously computed only inside the MCP plan tool. The
			// deterministic auto-fills need no LLM; a genuine miss is only
			// I4-resolved under --llm-assist (else surfaced as an advisory
			// note). Filled in both branches below.
			var fieldSuggestions []agenttask.FieldSuggestion

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

				// LT-37 (docs/follow-up.md): the LLM phase used to run for
				// minutes with a single line of output only at the very end
				// and no $ visibility. Log what it's about to do, then the
				// real spend against the ceiling when it's done.
				unresolved := 0
				for _, leaf := range agenttask.Leaves(tree.Root) {
					if leaf.Status == agenttask.StatusUnresolved {
						unresolved++
					}
				}
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "llm-assist: resolving %d unresolved leaf/leaves + one recon-wide proposal call (per-plan ceiling $%.2f)\n", unresolved, ceiling)

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

				// C7b (doc16 Phase 7 Step 3, docs/follow-up.md LT-49): one
				// plausibility pass over the confident (StatusPending) leaves
				// — the per-fact rule table structurally can't notice its own
				// premise is an artifact (SPA catch-all APISpec, CDN-brand
				// tech). Opt-in via --llm-assist, ceiling-respecting, and it
				// can only demote/drop with a logged reason, never add a leaf.
				for _, n := range llmfallback.VetoImplausibleLeaves(cmd.Context(), fb, fbErr, tree) {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "llm-assist: plausibility: %s\n", n)
				}

				// A6: recon-derived field suggestions, resolving any genuine
				// miss via I4 now that a tier is in hand. Its spend is added
				// to tree.SpendSoFar, so the summary below reflects it.
				fieldSuggestions = planFieldSuggestions(cmd.Context(), result, tree, true, fb, fbErr, cmd.ErrOrStderr())

				// LT-37: end-of-phase spend summary + a warn line naming the
				// model when this one plan ran past the (low, env-tunable)
				// warn threshold — catches an accidental switch to an
				// expensive HACKERFIVE_OPENROUTER_MODEL while still under the
				// hard ceiling.
				spent := tree.SpendSoFar()
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "llm-assist: spent $%.4f of $%.2f per-plan ceiling\n", spent, ceiling)
				if warn := llmfallback.CostWarnThresholdUSD(); fb != nil && warn > 0 && spent > warn {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "llm-assist: WARNING: $%.4f exceeds the $%.2f warn threshold (model %s) — check HACKERFIVE_OPENROUTER_MODEL / HACKERFIVE_LLM_COST_WARN_USD\n", spent, warn, fb.ModelLabel())
				}
			} else {
				fieldSuggestions = planFieldSuggestions(cmd.Context(), result, tree, false, nil, nil, cmd.ErrOrStderr())
			}

			// LT-68 (docs/follow-up.md): recon's one-line "is there a live app
			// here" verdict, before anything else — a decommissioned or fully
			// walled asset otherwise still prints a multi-leaf plan.
			appSurfaceDiagnostic(cmd.ErrOrStderr(), result)

			// D6 / LT-62 (docs/follow-up.md): if recon classified the target as
			// a uniform response wall, say so before the tree — the plan is
			// technically valid but a scan from this vantage will not reach the
			// application.
			uniformWallDiagnostic(cmd.ErrOrStderr(), result)

			// LT-60 (docs/follow-up.md): an empty plan (`{"tree":{"root":…}}`,
			// exit 0) otherwise looks identical to a bug. Say what recon
			// produced and why none of it became a leaf.
			emptyPlanDiagnostic(cmd.ErrOrStderr(), tree, result)

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
			return enc.Encode(planCmdOutput{Tree: tree, FieldSuggestions: fieldSuggestions})
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
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print wave-by-wave recon progress to stderr (LT-11, docs/follow-up.md) — off by default so scripted invocations see no output change")
	cmd.Flags().StringVar(&reconFile, "recon-file", "", "path to a prior 'hackerfive recon --output <path>' JSON result — when given, plan resolves that instead of re-running recon (LT-34, docs/follow-up.md); --recon-depth is then ignored")
	cmd.Flags().StringVar(&policyFile, "policy-file", "", "path to a program-policy declaration (see policy.yaml.example) for the D2 pre-flight check; default: the --scope file's sibling policy.yaml, else .engagements/policy.yaml if present (doc15 Step 3)")
	cmd.Flags().BoolVar(&allowPolicyOverride, "allow-policy-override", false, "downgrade a policy.yaml automated_scanning: disallowed verdict from a hard block to a warning — only for an operator holding out-of-band authorization that contradicts a stale file (doc15 Step 3)")

	return cmd
}

// emptyPlanDiagnostic prints one stderr line when registry.Resolve produced a
// tree with no host nodes at all — every recon tech fact was non-actionable
// (a transport/posture fact like HSTS or HTTP/3, dropped by
// registry.nonActionableTech) and every observed endpoint was a WAF/auth block
// or carried no vuln-shaped signal, so there is nothing to scan. Without it an
// empty plan (`{"tree":{"root":…}}`, exit 0) is indistinguishable from a bug
// (LT-60, docs/follow-up.md — hit live on www.valmo.in behind an Akamai WAF
// that 403s every path). No-op the moment the tree has any host node.
func emptyPlanDiagnostic(w io.Writer, tree *agenttask.PlanTree, result *recon.ReconResult) {
	if tree == nil || tree.Root == nil || len(tree.Root.Children) > 0 || result == nil {
		return
	}
	blocked := 0
	for _, ep := range result.Endpoints {
		switch ep.StatusCode {
		case 401, 403, 429:
			blocked++
		}
	}
	detail := fmt.Sprintf("%d tech fact(s)", len(result.TechStack))
	if len(result.TechStack) > 0 {
		names := make([]string, 0, len(result.TechStack))
		for _, f := range result.TechStack {
			names = append(names, f.Name)
		}
		detail = fmt.Sprintf("%d non-actionable tech fact(s) [%s]", len(names), strings.Join(names, ", "))
	}
	_, _ = fmt.Fprintf(w, "plan: empty plan — %s, %d/%d endpoint(s) WAF/auth-blocked, 0 actionable leaves; nothing to scan from this vantage\n",
		detail, blocked, len(result.Endpoints))
}

// appSurfaceDiagnostic prints recon's LT-68 live-application-surface verdict
// to stderr. Always printed (not just on "none") so an operator sees at a
// glance whether the plan below is worth acting on; a "none" verdict is
// flagged loudly because a plan still resolves (LT-57's baseline leaf) and
// would otherwise read as normal work.
func appSurfaceDiagnostic(w io.Writer, result *recon.ReconResult) {
	if result == nil || result.AppSurface == nil {
		return
	}
	s := result.AppSurface
	prefix := "plan: recon verdict"
	if s.Verdict == "none" {
		prefix = "plan: WARNING — recon verdict"
	}
	_, _ = fmt.Fprintf(w, "%s: live application surface: %s (%s)\n", prefix, s.Verdict, s.Reason)
}

// uniformWallDiagnostic prints one stderr line when recon classified the
// target as a uniform response wall (Phase 7 Step 4 D6 / docs/follow-up.md
// LT-59, LT-62) — a WAF/bot/auth block layer or a SPA/bucket catch-all that
// answers every path with one page. The plan still resolves (LT-57's
// baseline misconfig leaf keeps it non-empty), but a scan from this vantage
// will not reach the application, so `scan` will short-circuit the corpus.
func uniformWallDiagnostic(w io.Writer, result *recon.ReconResult) {
	if result == nil || result.UniformResponse == nil {
		return
	}
	u := result.UniformResponse
	what := "returns one generic catch-all page for every path"
	if u.Kind == "waf-block" {
		what = "sits behind a WAF/bot/auth block wall that intercepts every request"
	}
	_, _ = fmt.Fprintf(w, "plan: %s %s (canary status %d, %.0f%% of recon probes blocked) — a scan from this vantage will short-circuit the template corpus (D6); consider an in-region/residential egress or the target's non-web surface\n",
		u.Host, what, u.CanaryStatus, u.BlockedRatio*100)
}
