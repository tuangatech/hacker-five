package webui

import (
	"context"
	"fmt"

	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/orchestrator"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
	"github.com/tuangatech/hacker-five/pkg/scriptexec"
)

// jobReconRunner adapts a *recon.Recon into orchestrator.ReconRunner while
// also feeding its result into job's own Recon Results panel
// (Job.SetReconResult) — pkg/orchestrator.Run does its own recon internally
// (the same recon+registry.Resolve pipeline `hackerfive plan` uses, for both
// the initial tree seed and any later recon.refresh action), so this is the
// only recon pass an agent-mode job runs; there is no separate
// runLaunchRecon call to populate that panel otherwise. orchestrator.Run
// itself bounds each call by Config.ReconTimeout — no separate timeout
// needed here (a real gap found live during M4's own smoke test, before
// that bound existed: a wave2 naabu port scan sat "running" for minutes
// with job.Ctx() alone never expiring short of Cancel/server shutdown).
type jobReconRunner struct {
	inner *recon.Recon
	job   *Job
}

func (r jobReconRunner) Run(ctx context.Context, target string, depth recon.Depth) (*recon.ReconResult, error) {
	result, err := r.inner.Run(ctx, target, depth)
	if result != nil {
		r.job.SetReconResult(result)
	}
	return result, err
}

// runLaunchAgentJob is docs/93-implementation-plan-agent-orchestrator.md M4:
// the Web UI's "Use LLM agent" launch path. It mirrors cmd/hackerfive/
// agent.go's construction (same recon/llmfallback/orchestrator.Config
// shape) but wires every callback into job instead of stdout/stderr, and
// uses Job.RequestScriptApproval — a blocking, per-job HTTP approve/reject
// round trip — as the scriptexec.ApprovalGate instead of a stdin y/N prompt.
// Unlike runLaunchJob's checked-detector-tab flow, there is no non-LLM
// fallback here: pkg/orchestrator.Run hard-requires a Client, so a missing
// LLM tier fails the whole job, surfaced as a normal job failure rather than
// a partial/degraded run.
func runLaunchAgentJob(job *Job, form LaunchFormData) {
	for _, wave := range []string{"wave0", "wave1", "wave2", "wave3"} {
		job.SetWaveStatus(wave, "pending")
	}
	job.SetPhase("agent")

	execCfg := job.ExecConfig()
	target := launchTargetScheme(form.Target)

	var s *scope.Scope
	if form.ScopeFile != "" {
		parsed, err := scope.Parse(form.ScopeFile)
		if err != nil {
			job.AppendLog("error", fmt.Sprintf("agent: parsing scope file: %v", err))
			job.MarkDone(err)
			return
		}
		s = parsed
	}
	// Unlike execCfg.ScopeFile (a bare path, lazily parsed by
	// scanner.Engine.loadScope at Run() time — scan.go's own convention),
	// pkg/planexec.RunPlan's scope-creep gate and pkg/orchestrator's own
	// script.explore sandbox scoping both read scanner.Config.Scope directly
	// with no ScopeFile fallback of their own (confirmed against the
	// codebase during M3) — so this path sets .Scope explicitly rather than
	// relying on execCfg's existing ScopeFile-only convention, the same fix
	// cmd/hackerfive/agent.go applies for the CLI.
	baseCfg := execCfg
	baseCfg.Scope = s

	client := httpclient.New(recon.ClientConfig(httpclient.Config{
		Timeout:             defaultTimeout,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: form.Concurrency,
	}), httpclient.WithRateLimit(ratelimit.New(form.RateLimit)))

	reconOpts := []recon.Option{
		recon.WithRateLimit(form.RateLimit),
		recon.WithConcurrency(form.Concurrency),
		recon.WithProgressCallback(func(wave, status string) {
			job.SetWaveStatus(wave, status)
			if status == "running" {
				job.AppendLog("info", waveDescription(wave))
			}
		}),
	}
	if s != nil {
		reconOpts = append(reconOpts, recon.WithScope(s))
	}
	if reconHeaders, err := parseHeaderLines(form.Headers); err == nil && len(reconHeaders) > 0 {
		reconOpts = append(reconOpts, recon.WithHeaders(reconHeaders))
	}
	runner := jobReconRunner{inner: recon.New(client, reconOpts...), job: job}

	index, warn := loadTemplateIndexOrWarn()
	if warn != "" {
		job.AppendLog("warn", "agent: "+warn)
	}

	fb, fbErr := llmfallback.New(llmfallback.WithLogCallback(func(level, msg string) { job.AppendLog(level, msg) }))
	if fbErr != nil {
		err := fmt.Errorf("agent requires a configured LLM tier (OPENROUTER_API_KEY and/or a reachable local runtime): %w", fbErr)
		job.AppendLog("error", err.Error())
		job.MarkDone(err)
		return
	}

	var approvalGate scriptexec.ApprovalGate
	if form.AllowLLMAgentScripts {
		approvalGate = job.RequestScriptApproval
	} else {
		job.AppendLog("warn", "agent: 'Allow agent scripts' not checked — a proposed script.explore action will be skipped (its leaf marked unresolved) rather than run")
	}

	orchCfg := orchestrator.Config{
		Target:            target,
		ReconDepth:        recon.DepthFull, // same "recon is enrichment the operator never opts out of, always full depth" posture as runLaunchRecon
		Recon:             runner,
		TemplateIndex:     index,
		BaseScanConfig:    baseCfg,
		Client:            fb,
		SessionLog:        job.AgentLog(),
		Budget:            orchestrator.DefaultBudgetUSD,
		MaxIterations:     orchestrator.DefaultMaxIterations,
		MinIterations:     orchestrator.DefaultMinIterations,
		AllowAgentScripts: form.AllowLLMAgentScripts,
		ApprovalGate:      approvalGate,
		OnFinding:         job.AppendFinding,
		OnLog:             job.AppendLog,
	}

	res, err := orchestrator.Run(job.Ctx(), orchCfg)
	if err != nil {
		job.AppendLog("error", fmt.Sprintf("agent: %v", err))
		job.MarkDone(err)
		return
	}
	job.AppendLog("info", fmt.Sprintf("agent: spent $%.4f of $%.2f budget, %d iteration(s)", res.SpendUSD, orchCfg.Budget, res.Iterations))
	// The agent's own PlanTree is the same type/shape Plan Preview already
	// renders — caching it here lets the operator open that page afterward
	// to review or re-run leaves the agent left unresolved/didn't reach
	// (e.g. it stopped on budget), the same way a plain recon-only job's
	// tree already feeds that page (runLaunchRecon).
	job.SetPlanTree(res.Tree, nil)
	job.MarkDone(nil)
}
