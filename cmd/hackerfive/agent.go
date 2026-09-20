package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/orchestrator"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scriptexec"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// agentStreamEvent is one line of `hackerfive agent`'s stdout/--output
// stream. A run that dies before Run returns (a real Ctrl-C, OOM, host
// reboot, or a harness/supervisor's own timeout kill — none of which any
// code here gets a chance to react to) still leaves every "finding" event
// already written on disk or in the consuming process's captured pipe,
// since each Encode call below is an immediate, unbuffered write — unlike
// the previous behavior of only ever emitting one full Result document
// after a clean return, which a killed run produced zero bytes of
// (docs/follow-up.md LT-163 item 3). A clean run's final "result" event
// still carries the complete Findings/Iterations/SpendUSD for a consumer
// that only wants to look at one line.
type agentStreamEvent struct {
	Type    string               `json:"type"`
	Finding *detectors.Finding   `json:"finding,omitempty"`
	Result  *orchestrator.Result `json:"result,omitempty"`
	Err     string               `json:"error,omitempty"`
}

// agentEventWriter serializes agentStreamEvent writes to w — concurrency-safe
// since planexec's OnFinding (docs comment on pkg/planexec.ExecOptions.
// OnFinding) is called "synchronously" per leaf but a leaf's own scanner
// engine may run several template matches on its own worker goroutines, so
// more than one finding can arrive at once.
type agentEventWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newAgentEventWriter(w io.Writer) *agentEventWriter {
	return &agentEventWriter{enc: json.NewEncoder(w)}
}

func (w *agentEventWriter) writeFinding(f detectors.Finding) {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.enc.Encode(agentStreamEvent{Type: "finding", Finding: &f})
}

func (w *agentEventWriter) writeResult(res orchestrator.Result, runErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ev := agentStreamEvent{Type: "result", Result: &res}
	if runErr != nil {
		ev.Err = runErr.Error()
	}
	_ = w.enc.Encode(ev)
}

// newAgentCmd is docs/93-implementation-plan-agent-orchestrator.md's M3: the
// CLI entrypoint for pkg/orchestrator's LLM-driven loop. Unlike `plan`/`scan`,
// this always makes real, metered LLM calls (there is no --llm-assist-style
// opt-out — the whole command is the opt-in) and, with
// --allow-agent-scripts, can run a model-authored script inside
// pkg/scriptexec's sandbox after an interactive approval. `hackerfive
// scan`/`plan`/`triage`/`suggest` are unchanged; this is a separate, opt-in
// mode, not a replacement.
func newAgentCmd(root *rootFlags) *cobra.Command {
	var (
		target              string
		depth               string
		scopeFile           string
		allowNoScope        bool
		rateLimit           int
		concurrency         int
		templatesPaths      []string
		templateIndex       string
		authToken           string
		otherAuthToken      string
		authHeaderName      string
		authHeaderFormat    string
		insecure            bool
		headers             []string
		allowWrites         bool
		budget              float64
		maxIterations       int
		minIterations       int
		allowAgentScripts   bool
		scriptTimeout       time.Duration
		verbose             bool
		policyFile          string
		allowPolicyOverride bool
	)

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run the LLM-orchestrated scan loop against a target (docs/93-implementation-plan-agent-orchestrator.md) — opt-in, budget/iteration-capped; a proposed script.explore action never runs without --allow-agent-scripts and a fresh interactive approval",
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
			if authToken == "" {
				authToken = os.Getenv("HACKERFIVE_AUTH_TOKEN")
			}
			if otherAuthToken == "" {
				otherAuthToken = os.Getenv("HACKERFIVE_OTHER_AUTH_TOKEN")
			}

			s, err := requireScopeOrOptOut(scopeFile, allowNoScope, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			// D2 pre-flight (doc15 Step 3): hard-blocks only on a policy.yaml
			// automated_scanning: disallowed verdict, same as plan/scan.
			if err := runPreflight([]string{target}, policyFile, scopeFile, allowPolicyOverride, nil, cmd.ErrOrStderr()); err != nil {
				return err
			}

			policyHeaders, err := policyRequestHeaders(policyFile, scopeFile)
			if err != nil {
				return err
			}
			flagHeaders, err := parseHeaders(headers)
			if err != nil {
				return fmt.Errorf("parsing --header: %w", err)
			}
			extraHeaders, fromPolicy := mergeHeaders(policyHeaders, flagHeaders)
			for _, name := range fromPolicy {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "agent: applying policy-mandated request header %q\n", name)
			}

			// Same "left at its default -> auto-append the synced corpus"
			// convention as scan.go, since scan.leaf dispatches load
			// templates the same way `hackerfive scan` does.
			if !cmd.Flags().Changed("templates") {
				if syncedDir, err := templatesync.DefaultSyncDir(); err == nil {
					if _, statErr := os.Stat(syncedDir); statErr == nil {
						templatesPaths = append(templatesPaths, syncedDir)
					}
				}
			}

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

			reconOpts := []recon.Option{recon.WithRateLimit(rateLimit), recon.WithConcurrency(concurrency)}
			if s != nil {
				reconOpts = append(reconOpts, recon.WithScope(s))
			}
			if len(extraHeaders) > 0 {
				reconOpts = append(reconOpts, recon.WithHeaders(extraHeaders))
			}
			if verbose {
				reconOpts = append(reconOpts, recon.WithProgressCallback(verboseProgress(cmd.ErrOrStderr())))
			}
			r := recon.New(client, reconOpts...)

			// Unlike plan.go's --llm-assist (which degrades to escalating
			// every unresolved leaf when no tier is configured), the agent
			// loop has no non-LLM fallback path at all — pkg/orchestrator.Run
			// hard-requires a Client, so a missing tier is a hard failure
			// here, surfaced before any recon spend rather than after.
			fb, fbErr := llmfallback.New(llmfallback.WithLogCallback(func(level, msg string) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "agent: llm: %s\n", msg)
			}))
			if fbErr != nil {
				return fmt.Errorf("agent requires a configured LLM tier (OPENROUTER_API_KEY and/or a reachable local runtime): %w", fbErr)
			}

			var approvalGate scriptexec.ApprovalGate
			if allowAgentScripts {
				approvalGate = stdinScriptApprovalGate(cmd.InOrStdin(), cmd.ErrOrStderr())
			} else {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "agent: --allow-agent-scripts not set — a proposed script.explore action will be skipped (its leaf marked unresolved) rather than run")
			}

			orchCfg := orchestrator.Config{
				Target:        target,
				ReconDepth:    d,
				Recon:         r,
				TemplateIndex: index,
				BaseScanConfig: scanner.Config{
					TemplatePaths:    templatesPaths,
					Concurrency:      concurrency,
					RateLimit:        rateLimit,
					Timeout:          root.timeout,
					ProxyURL:         root.proxy,
					Insecure:         insecure,
					AuthToken:        authToken,
					OtherAuthToken:   otherAuthToken,
					AuthHeaderName:   authHeaderName,
					AuthHeaderFormat: authHeaderFormat,
					Scope:            s,
					ExtraHeaders:     extraHeaders,
					AllowWrites:      allowWrites,
				},
				Client:            fb,
				SessionLog:        agenttask.NewSessionLog(nil),
				Budget:            budget,
				MaxIterations:     maxIterations,
				MinIterations:     minIterations,
				AllowAgentScripts: allowAgentScripts,
				ScriptTimeout:     scriptTimeout,
				ApprovalGate:      approvalGate,
			}

			// LT-163 item 3 (docs/follow-up.md): out is opened and streamed to
			// up front, one compact JSON line per event, instead of building a
			// single pretty-printed Result document only written after Run
			// returns cleanly — a killed run (this process's own context
			// deadline, a supervising harness's timeout, Ctrl-C, OOM) previously
			// discarded every finding it had already made. os.Create/os.Stdout
			// are both unbuffered at the Go level, so a completed Write() call
			// is durable in the OS pipe/file before this process could be
			// killed for anything happening after it.
			out := cmd.OutOrStdout()
			if root.output != "" {
				f, err := os.Create(root.output)
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer func() { _ = f.Close() }()
				out = f
			}
			events := newAgentEventWriter(out)

			orchCfg.OnFinding = func(f detectors.Finding) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "agent: finding: [%s/%s] %s (%s)\n", f.Type, f.Severity, f.Description, f.Target)
				events.writeFinding(f)
			}
			orchCfg.OnLog = func(level, msg string) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "agent: [%s] %s\n", level, msg)
			}

			res, runErr := orchestrator.Run(cmd.Context(), orchCfg)
			events.writeResult(res, runErr)
			if runErr != nil {
				return fmt.Errorf("running agent: %w", runErr)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "agent: spent $%.4f of $%.2f budget, %d iteration(s)\n", res.SpendUSD, orchCfg.Budget, res.Iterations)
			return nil
		},
	}

	cmd.Flags().StringVarP(&target, "targets", "t", "", "target URL to run the agent loop against (required)")
	cmd.Flags().StringVar(&depth, "recon-depth", "active", `how far the initial recon escalates before building the plan tree: "passive", "active" (default), "full"`)
	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to a target allow-list file (same format as scan's --scope) — required unless --allow-no-scope is set; also bounds a script.explore sandbox's network access")
	cmd.Flags().BoolVar(&allowNoScope, "allow-no-scope", false, "proceed with no --scope boundary — every host recon discovers is treated as in-scope; lab/local use only, never a real engagement")
	cmd.Flags().IntVar(&rateLimit, "rate-limit", 10, "requests/sec used by both the initial recon and every scan.leaf dispatch")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 10, "concurrency used by both the initial recon and every scan.leaf dispatch")
	cmd.Flags().StringArrayVar(&templatesPaths, "templates", []string{templatesync.DefaultBundledDir}, "template directory (repeatable) for scan.leaf dispatches; left at its default, the synced directory from 'hackerfive templates sync' is auto-appended if present")
	cmd.Flags().StringVar(&templateIndex, "template-index", "templates/index.json", "path to the index generated by 'hackerfive templates index' — missing file degrades to skipping template-tag matching, not a hard failure")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "owner/primary account token for scan.leaf dispatches (env: HACKERFIVE_AUTH_TOKEN)")
	cmd.Flags().StringVar(&otherAuthToken, "other-auth-token", "", "second account token for scan.leaf dispatches (env: HACKERFIVE_OTHER_AUTH_TOKEN)")
	cmd.Flags().StringVar(&authHeaderName, "auth-header-name", "", `HTTP header name for the auth token (default "Authorization")`)
	cmd.Flags().StringVar(&authHeaderFormat, "auth-header-format", "", `header value template for the auth token, must contain "{token}" (default "Bearer {token}")`)
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification — lab targets only, never the default")
	cmd.Flags().StringArrayVar(&headers, "header", nil, `static "Name: Value" header added to every scan.leaf request (repeatable)`)
	cmd.Flags().BoolVar(&allowWrites, "allow-writes", false, "allow the businesslogic detector's mutating checks to run during a scan.leaf dispatch — the same independently-scoped exception as scan's --allow-writes; omitted, those checks are skipped with a warning")
	cmd.Flags().Float64Var(&budget, "budget", orchestrator.DefaultBudgetUSD, "hard cap, in USD, on cumulative LLM cost across the whole run")
	cmd.Flags().IntVar(&maxIterations, "max-iterations", orchestrator.DefaultMaxIterations, "hard cap on the number of dispatched tool turns")
	cmd.Flags().IntVar(&minIterations, "min-iterations", orchestrator.DefaultMinIterations, "floor on dispatched tool turns — a \"stop\" action is rejected and NextAction asked again while fewer than this many turns have run and actionable leaves remain (LT-162: the model was found stopping after 1-3 turns with 10+ pending leaves still untried)")
	cmd.Flags().BoolVar(&allowAgentScripts, "allow-agent-scripts", false, "allow the model to propose script.explore actions — a sandboxed Python/shell script, run only after a static precheck and a fresh interactive y/N approval every time (never batch-approved). The same independently-scoped exception convention as --allow-writes/--auto-provision-account; omitted, a proposed script is skipped with a warning, never run")
	cmd.Flags().DurationVar(&scriptTimeout, "script-timeout", orchestrator.DefaultScriptTimeout, "wall-clock cap on one script.explore sandbox run")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print wave-by-wave recon progress to stderr")
	cmd.Flags().StringVar(&policyFile, "policy-file", "", "path to a program-policy declaration (see policy.yaml.example) for the D2 pre-flight check; default: the --scope file's sibling policy.yaml, else .engagements/policy.yaml if present")
	cmd.Flags().BoolVar(&allowPolicyOverride, "allow-policy-override", false, "downgrade a policy.yaml automated_scanning: disallowed verdict from a hard block to a warning — only for an operator holding out-of-band authorization that contradicts a stale file")

	return cmd
}

// stdinScriptApprovalGate prints a proposed script.explore action's full
// source text and any static Precheck notes, then blocks on an interactive
// stdin y/N prompt before scriptexec.Execute is allowed to run it — no
// batch/blanket approval, per doc93 M3's "every time" HITL requirement.
// scriptexec.Execute's own Precheck -> ApprovalGate -> sandbox ordering means
// this is never even called for a script Precheck already blocked.
func stdinScriptApprovalGate(stdin io.Reader, stderr io.Writer) scriptexec.ApprovalGate {
	return func(_ context.Context, req scriptexec.ScriptRequest, pre scriptexec.PrecheckResult) (bool, error) {
		_, _ = fmt.Fprintf(stderr, "\nagent: model proposes running this %s script:\n----------------------------------------\n%s\n----------------------------------------\n", req.Language, req.Source)
		if len(pre.Reasons) > 0 {
			_, _ = fmt.Fprintf(stderr, "agent: precheck notes: %s\n", strings.Join(pre.Reasons, "; "))
		}
		_, _ = fmt.Fprint(stderr, "agent: approve running this script now? [y/N] ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		approved := strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
		if !approved {
			_, _ = fmt.Fprintln(stderr, "agent: script not approved — skipping")
		}
		return approved, nil
	}
}
