// Package orchestrator implements the hackerfive agent loop
// (docs/93-implementation-plan-agent-orchestrator.md M2): given a target, it
// builds an initial agenttask.PlanTree the same way `hackerfive plan` does
// (pkg/recon + registry.Resolve), then repeatedly asks
// llmfallback.Client.NextAction which of a fixed tool catalog to run next,
// dispatches it, and folds the result back into the tree/history before
// asking again — until the model says stop, the budget/iteration ceiling is
// reached, or nothing actionable remains.
//
// This package never fabricates a Finding itself: every Finding comes from
// either scan.leaf's real detector match (via pkg/planexec, unchanged from
// `hackerfive scan`/the webui Plan Preview) or script.explore's own proposed
// request (pkg/scriptexec) independently re-issued and confirmed outside the
// sandbox (scriptevidence.go) — never from the script's self-reported
// stdout/exit code alone. recon.refresh's result is merged back into the
// running PlanTree via the same deterministic registry.Resolve the initial
// tree build uses (mergeReconRefresh, docs/follow-up.md LT-160 item 2) —
// never an LLM inventing a leaf, and never touching an existing leaf's own
// Status/Confidence/Rationale.
package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/coverage"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/fieldsuggest"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/planexec"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scriptexec"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// DefaultBudgetUSD/DefaultMaxIterations are the whole-run ceilings applied
// when a Config leaves Budget/MaxIterations unset (<= 0) — never zero and
// never unbounded, per doc93 M2. Scaled up from
// llmfallback.PerCallDefaultSpendCeilingUSD's own $0.10 single-call default:
// a run makes many NextAction/TriageFindings calls, not one.
const (
	DefaultBudgetUSD     = 1.00
	DefaultMaxIterations = 20
	// DefaultMinIterations is applied when a Config leaves MinIterations
	// unset (<= 0). Found live (docs/follow-up.md LT-162's re-verification,
	// 2026-09-18): the model routinely chose "stop" after 1-3 dispatched
	// turns while 10-15+ pending leaves remained in the tree — well short of
	// DefaultMaxIterations, and short enough that a real, higher-priority
	// leaf (e.g. a "misconfig" class leaf ranked above the one leaf actually
	// tried) was never attempted. 5 is not tuned against a broader sweep;
	// it's a deliberately modest floor that forces meaningfully more
	// exploration without materially changing budget/wall-clock, chosen
	// pending a fuller re-run of doc93 M5's eval table.
	DefaultMinIterations = 5
	// DefaultScriptTimeout is applied when a Config leaves ScriptTimeout
	// unset (<= 0) — a script.explore call that never terminates would
	// otherwise block the whole run indefinitely.
	DefaultScriptTimeout = 30 * time.Second
	// DefaultReconTimeout is applied when a Config leaves ReconTimeout unset
	// (<= 0) — bounds every individual Config.Recon.Run call (the initial
	// tree-seeding recon and any later recon.refresh dispatch), the same
	// guard cmd/hackerfive/recon.go's/pkg/webui's own recon callers already
	// apply around a plain recon.Recon.Run. Without it, a hung external
	// recon tool (naabu/httpx/katana) would stall the whole run indefinitely
	// — job.Ctx()/cmd.Context() alone only ever expire on an operator's own
	// cancel or server shutdown. Found live running a Web UI agent-mode
	// smoke test: a wave2 naabu port scan against a real target sat
	// "running" for minutes with the run otherwise healthy.
	DefaultReconTimeout = 10 * time.Minute
)

// LLMClient is the subset of *llmfallback.Client this package calls —
// narrowed to an interface so a test can supply a fake instead of exercising
// a real model tier. *llmfallback.Client satisfies this as-is.
type LLMClient interface {
	NextAction(ctx context.Context, tree *agenttask.PlanTree, catalog []llmfallback.ToolSpec, history []llmfallback.TurnRecord, digest llmfallback.RunDigest) (llmfallback.Action, float64, error)
	TriageFindings(ctx context.Context, findings []detectors.Finding) (llmfallback.TriageResult, float64, error)
	// ResolveField is I4's field-miss caller (LT-138 item 1, docs/follow-up.md)
	// — resolveMissingLeafField's own fallback when a scan.leaf dispatch's
	// targeted leaf is blocked on a required field fieldsuggest.Deterministic
	// can't auto-fill deterministically.
	ResolveField(ctx context.Context, detector, field string, candidates []string) (llmfallback.FieldDecision, float64, error)
}

// ReconRunner is the subset of *recon.Recon this package calls — narrowed to
// an interface for the same reason as LLMClient, and because it lets a
// caller pre-build the real *recon.Recon with whatever scope/rate-limit/
// concurrency options `hackerfive plan`'s own construction uses, without
// this package needing to know about any of them.
type ReconRunner interface {
	Run(ctx context.Context, target string, depth recon.Depth) (*recon.ReconResult, error)
}

// Config configures one orchestrator Run. Target/Recon/Client are required;
// every other field has a safe default when left zero-valued.
type Config struct {
	// Target is the single seed target `hackerfive plan` would also take via
	// --targets — the same one Recon.Run and the initial registry.Resolve
	// call use to build the starting PlanTree.
	Target     string
	ReconDepth recon.Depth
	Recon      ReconRunner

	// TemplateIndex feeds both the initial registry.Resolve call and every
	// scan.leaf dispatch's planexec.RunPlan call — the same synced-corpus
	// index `hackerfive plan`/`scan` already load.
	TemplateIndex []templatesync.Entry

	// BaseScanConfig is the shared template planexec.RunPlan copies per leaf
	// for scan.leaf (Scope, AuthToken, AllowWrites, TemplatePaths, rate
	// limits, ...) — everything except Targets/Detector/TemplateID, which
	// RunPlan fills per leaf. Its Scope field also bounds script.explore's
	// sandbox (scriptexec.ScriptRequest.Scope) — a script can never reach
	// further than the scan itself is allowed to.
	BaseScanConfig scanner.Config

	Client     LLMClient
	SessionLog *agenttask.SessionLog

	// Budget is a hard cap (agenttask.PlanTree.SpendCeilingUSD) on cumulative
	// LLM cost across every NextAction/TriageFindings call this run makes.
	// <= 0 uses DefaultBudgetUSD — this run always has a real ceiling, never
	// an implicit unbounded one.
	Budget float64
	// MaxIterations caps the number of dispatched turns (a "stop" action
	// doesn't count as one). <= 0 uses DefaultMaxIterations.
	MaxIterations int
	// MinIterations is a floor on dispatched turns: a "stop" action is
	// rejected (fed back into history, NextAction asked again) while fewer
	// than MinIterations turns have been dispatched and actionable leaves
	// remain — see DefaultMinIterations. <= 0 uses DefaultMinIterations; a
	// value above MaxIterations is clamped down to it.
	MinIterations int

	// FastLane runs the leaves that need no judgment — every template-ID leaf
	// (one cheap single-template scan) and the parameter-free broad sweeps
	// (see fastLaneDetectors) — straight from the plan tree in Priority order,
	// without a NextAction call, and asks the model only when what remains
	// does need a decision (an endpoint- or credential-specific detector, an
	// unresolved leaf, recon.refresh/triage/script.explore, stop). LT-172
	// (docs/follow-up.md): on a live run 14 of 17 model turns were
	// single-template scans that finished in about a second, each behind a
	// 1-4 minute model call, and the one leaf class that actually produced
	// findings was reached 7th-9th because the model walked leaves in list
	// order. Fast-lane turns cost no LLM spend and count toward neither
	// MaxIterations nor MinIterations (both stay about the model's own turns);
	// each leaf is tried at most once. false (the zero value) keeps the
	// original one-model-call-per-turn behavior.
	FastLane bool

	// RunEveryLeaf widens the fast lane from the parameter-free leaves to every
	// runnable (pending, detector-assigned) leaf, in Priority order, with no
	// decision made about which is worth running. It turns the lane on by
	// itself. This is the deterministic baseline for what a model's choice is
	// worth (docs/94-llm-finding-capability-strategy.md, LT-183): a model that
	// only picks among leaves the tree already holds has to beat "run them all".
	// It is not a recommended default — an endpoint-specific leaf run blind can
	// cost a scan apiece — and it does not resolve unresolved leaves (that still
	// needs a model). Same scan.leaf dispatch, so --allow-writes and the other
	// gates apply unchanged.
	RunEveryLeaf bool

	// ReconTimeout bounds one Config.Recon.Run call (the initial
	// tree-seeding recon and any later recon.refresh dispatch). <= 0 uses
	// DefaultReconTimeout.
	ReconTimeout time.Duration

	// AllowAgentScripts gates script.explore (docs/93 M1/M3's
	// --allow-agent-scripts convention, independently scoped like
	// --allow-writes/--auto-provision-account — never folded into either).
	// false: script.explore stays in the offered catalog (so the model's
	// view of what's possible is stable across runs), but a chosen
	// script.explore action is never executed — the targeted leaf (if any)
	// is marked StatusUnresolved with the reason, a warning is logged via
	// OnLog, and the run continues.
	AllowAgentScripts bool
	// ScriptTimeout bounds one script.explore sandbox run. <= 0 uses
	// DefaultScriptTimeout.
	ScriptTimeout time.Duration
	// ApprovalGate is required whenever AllowAgentScripts is true —
	// scriptexec.Execute refuses to run a script unattended without one.
	ApprovalGate scriptexec.ApprovalGate

	// OnFinding/OnLog stream a scan.leaf dispatch's real detector output
	// live, mirroring pkg/planexec.ExecOptions' own callbacks — both
	// optional.
	OnFinding func(detectors.Finding)
	OnLog     func(level, msg string)

	// observeRecon is set by Run so a later recon dispatch can feed the model's
	// recon digest; not part of the public surface.
	observeRecon func(*recon.ReconResult)
}

// Result is one completed Run's outcome. Iterations counts the turns the
// model directed; FastLaneTurns counts the leaves the orchestrator dispatched
// itself (Config.FastLane). History holds both, in dispatch order — a
// fast-lane record has TurnRecord.Auto set.
type Result struct {
	Tree          *agenttask.PlanTree
	Findings      []detectors.Finding
	History       []llmfallback.TurnRecord
	Iterations    int
	FastLaneTurns int
	SpendUSD      float64

	// Recon is every endpoint recon observed (the initial pass and any
	// recon.refresh), values stripped — the input pkg/coverage needs to say where
	// a missed vulnerability was lost (LT-185). ReconDropped counts endpoints
	// beyond coverage.MaxLedgerEndpoints that were not kept.
	Recon        []coverage.Endpoint
	ReconDropped int

	// Degraded is empty on a healthy run. When the model stopped answering
	// (MaxConsecutiveLLMFailures decision calls in a row failed) it says so and
	// how much was left undone (LT-173): the run finished what needed no
	// decision and ended cleanly rather than failing with findings in hand.
	Degraded string
}

// MaxConsecutiveLLMFailures is how many decision calls in a row may fail
// (each already carries the client's own deadline and one retry) before Run
// stops asking the model and degrades (LT-173). Two, not one: a single
// transient failure should cost a retry, not the model for the rest of the run.
const MaxConsecutiveLLMFailures = 2

// ErrScriptsDisallowed is returned by the internal script.explore dispatch
// when Config.AllowAgentScripts is false — Run itself never surfaces this as
// a fatal error; it degrades the targeted leaf and continues (see
// Config.AllowAgentScripts's doc comment).
var ErrScriptsDisallowed = errors.New("orchestrator: script.explore requested but AllowAgentScripts is not set")

// Run builds an initial PlanTree from Config.Target (the same recon +
// registry.Resolve pipeline `hackerfive plan` uses) and then loops, calling
// Config.Client.NextAction each turn and dispatching its chosen tool, until
// the model chooses "stop", the budget/iteration ceiling is reached, or no
// actionable (pending/unresolved) leaf remains. Every Finding in the
// returned Result comes from a real scan.leaf dispatch's detector match
// (pkg/planexec, unchanged from `hackerfive scan`) — never from the model's
// own assertion.
func Run(ctx context.Context, cfg Config) (Result, error) {
	if cfg.Target == "" {
		return Result{}, errors.New("orchestrator: Config.Target is required")
	}
	if cfg.Recon == nil {
		return Result{}, errors.New("orchestrator: Config.Recon is required")
	}
	if cfg.Client == nil {
		return Result{}, errors.New("orchestrator: Config.Client is required")
	}
	if cfg.Budget <= 0 {
		cfg.Budget = DefaultBudgetUSD
	}
	if cfg.MaxIterations <= 0 {
		cfg.MaxIterations = DefaultMaxIterations
	}
	if cfg.MinIterations <= 0 {
		cfg.MinIterations = DefaultMinIterations
	}
	if cfg.MinIterations > cfg.MaxIterations {
		cfg.MinIterations = cfg.MaxIterations
	}
	if cfg.ScriptTimeout <= 0 {
		cfg.ScriptTimeout = DefaultScriptTimeout
	}
	if cfg.ReconTimeout <= 0 {
		cfg.ReconTimeout = DefaultReconTimeout
	}
	if cfg.SessionLog == nil {
		cfg.SessionLog = agenttask.NewSessionLog(nil)
	}

	result, err := runRecon(ctx, cfg, cfg.Target, cfg.ReconDepth)
	if err != nil {
		return Result{}, fmt.Errorf("orchestrator: initial recon: %w", err)
	}
	tree, _ := registry.Resolve(result, cfg.TemplateIndex)
	tree.SpendCeilingUSD = cfg.Budget
	warnDuplicateLeafTargets(cfg, tree)

	// LT-137 parity (docs/follow-up.md): tools_plan.go and webui's plan-exec
	// path already carry a plan's own recon result into DerivedTags so
	// planexec.runLeaf's per-leaf tag floor gets tech-matched "extras" union
	// in on top (doc15 Step 6a) — this package's dispatchScanLeaf reuses the
	// same planexec.RunPlan but, until now, never set this, so every
	// scan.leaf dispatch got floor-only scoping despite this loop already
	// holding a fresh, live recon.ReconResult in hand. UniformWallHosts is
	// the same established D6 pass-through (mirrors tools_plan.go/scan.go).
	cfg.BaseScanConfig.DerivedTags = registry.TechStackTags(result.TechStack, cfg.TemplateIndex)
	cfg.BaseScanConfig.UniformWallHosts = result.UniformWallHosts()

	rd := &reconDigest{}
	rd.observe(result)
	var reconLedger coverage.EndpointSet
	reconLedger.AddRecon(result)
	cfg.observeRecon = func(r *recon.ReconResult) {
		rd.observe(r)
		reconLedger.AddRecon(r)
	}

	catalog := buildCatalog(cfg)
	var (
		history  []llmfallback.TurnRecord
		findings []detectors.Finding
	)

	// fastTried is every leaf the fast lane has already dispatched once —
	// a leaf that stays pending afterwards (e.g. skipped) is never retried by
	// the lane, and never counts as work left for it.
	fastTried := map[string]bool{}
	fastTurns := 0
	snapshot := func() Result {
		return Result{Tree: tree, Findings: findings, History: history, FastLaneTurns: fastTurns, SpendUSD: tree.SpendSoFar(),
			Recon: reconLedger.List(), ReconDropped: reconLedger.Dropped()}
	}

	iteration := 0
	// rejectedStops counts "stop" actions turned away by the MinIterations
	// floor below. Capped at cfg.MinIterations retries (not tied to
	// iteration, which only counts real dispatches) so a model that keeps
	// choosing "stop" regardless of the nudge still terminates instead of
	// looping until MaxIterations purely on rejected-stop calls.
	rejectedStops := 0
	// llmFailures counts consecutive failed NextAction calls; llmDown is set
	// once it reaches MaxConsecutiveLLMFailures (LT-173). From then on the fast
	// lane runs regardless of cfg.FastLane and the model is never asked again.
	llmFailures, llmDown := 0, false
	var lastLLMErr error
	if _, off := cfg.Client.(NoModelClient); off {
		llmDown, lastLLMErr = true, ErrModelDisabled
		cfg.logf("info", "%v — running the deterministic fast lane only", ErrModelDisabled)
	}
	for iteration < cfg.MaxIterations {
		if tree.SpendCeilingUSD > 0 && tree.SpendSoFar() >= tree.SpendCeilingUSD {
			cfg.logf("info", "budget exhausted ($%.4f of $%.2f) — stopping", tree.SpendSoFar(), tree.SpendCeilingUSD)
			break
		}
		if !hasActionableLeavesExcept(tree, fastTried) {
			cfg.logf("info", "no pending/unresolved leaves remain — stopping")
			break
		}

		if cfg.FastLane || cfg.RunEveryLeaf || llmDown {
			// No NextAction call in this branch, so nothing else in the loop
			// notices a cancelled context.
			if err := ctx.Err(); err != nil {
				res := snapshot()
				res.Iterations = iteration
				return res, fmt.Errorf("orchestrator: %w", err)
			}
			if leaf := nextFastLaneLeaf(tree, fastTried, cfg.RunEveryLeaf); leaf != nil {
				fastTried[leaf.ID] = true
				fastTurns++
				history = append(history, dispatchFastLaneLeaf(ctx, cfg, tree, &findings, leaf))
				continue
			}
		}
		if llmDown {
			// The lane has nothing left and the model is gone: what remains
			// needs a decision nobody can make. End here, not by asking again.
			break
		}

		action, cost, err := cfg.Client.NextAction(ctx, tree, catalog, history, buildRunDigest(rd, findings))
		tree.AddSpend(cost)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				// The run itself was cancelled — not a model problem, and not
				// something to degrade around.
				res := snapshot()
				res.Iterations = iteration
				return res, fmt.Errorf("orchestrator: NextAction: %w", err)
			}
			llmFailures++
			lastLLMErr = err
			cfg.logf("warn", "NextAction failed (%d of %d consecutive): %v", llmFailures, MaxConsecutiveLLMFailures, err)
			if llmFailures >= MaxConsecutiveLLMFailures {
				llmDown = true
				cfg.logf("warn", "model unavailable — finishing the leaves that need no decision, then stopping cleanly")
			}
			continue
		}
		llmFailures = 0

		finish := cfg.SessionLog.BeginActor("agent", action.Kind, action.Rationale, action.Params)
		if action.Kind == "stop" {
			if iteration >= cfg.MinIterations || rejectedStops >= cfg.MinIterations {
				finish("stopped: "+action.Rationale, nil)
				break
			}
			// LT-162 (docs/follow-up.md): previously honored immediately,
			// even with plenty of pending leaves and iteration budget left —
			// the model's own stop rationale was never recorded anywhere
			// either. Now: rejected and fed back as a real history entry
			// (the rationale IS finally surfaced, via SessionLog too), so
			// the next NextAction call sees its own premature call-off and
			// has to either justify it again or pick something else.
			rejectedStops++
			msg := fmt.Sprintf("stop rejected: only %d of a minimum %d turn(s) dispatched and actionable leaves remain — model's stated rationale: %s", iteration, cfg.MinIterations, action.Rationale)
			finish(msg, nil)
			history = append(history, llmfallback.TurnRecord{Action: action, ResultSummary: msg})
			continue
		}
		iteration++

		resultSummary, dispatchErr := dispatch(ctx, cfg, tree, &findings, action)
		finish(resultSummary, dispatchErr)

		rec := llmfallback.TurnRecord{Action: action, ResultSummary: resultSummary}
		if dispatchErr != nil {
			rec.Error = dispatchErr.Error()
		}
		history = append(history, rec)
		cfg.logTurn(fmt.Sprintf("turn %d", iteration), rec)
	}

	res := snapshot()
	res.Iterations = iteration
	if llmDown {
		left := countActionableLeavesExcept(tree, fastTried)
		if errors.Is(lastLLMErr, ErrModelDisabled) {
			res.Degraded = fmt.Sprintf("%v; %d leaf/leaves left undispatched because they need a model decision", lastLLMErr, left)
		} else {
			res.Degraded = fmt.Sprintf("model unavailable after %d consecutive failed decision calls (last: %v); %d leaf/leaves left undispatched because they need a model decision", MaxConsecutiveLLMFailures, lastLLMErr, left)
		}
		cfg.logf("warn", "degraded: %s", res.Degraded)
	}
	return res, nil
}

// countActionableLeavesExcept is hasActionableLeavesExcept's count.
func countActionableLeavesExcept(tree *agenttask.PlanTree, skip map[string]bool) int {
	if tree == nil || tree.Root == nil {
		return 0
	}
	n := 0
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if skip[leaf.ID] {
			continue
		}
		if leaf.Status == agenttask.StatusPending || leaf.Status == agenttask.StatusUnresolved {
			n++
		}
	}
	return n
}

// fastLaneDetectors are the built-in detectors whose leaf is a parameter-free
// sweep of the target — nothing to choose between, so no model call is needed
// to decide to run it. Every other built-in detector (idor, authbypass, ssrf,
// sqli, businesslogic, ...) is specific to an endpoint, a parameter or a
// credential and stays a decision for the model.
var fastLaneDetectors = map[string]bool{"misconfig": true, "netservice": true, "tls": true}

// isFastLaneLeaf reports whether leaf can be dispatched without a decision: a
// runnable (pending, detector-assigned) leaf that is either a raw template-ID
// leaf (registry.LeafClass "templates" — one cheap single-template scan) or one
// of the parameter-free sweeps above.
func isFastLaneLeaf(leaf *agenttask.PlanNode) bool {
	if !isRunnableLeaf(leaf) {
		return false
	}
	return registry.LeafClass(leaf) == "templates" || fastLaneDetectors[leaf.Detector]
}

// isRunnableLeaf is the floor for dispatching any leaf: pending, with a
// detector assigned. Config.RunEveryLeaf makes this the whole test.
func isRunnableLeaf(leaf *agenttask.PlanNode) bool {
	return leaf.Status == agenttask.StatusPending && leaf.Detector != ""
}

// nextFastLaneLeaf returns the highest-Priority fast-lane leaf not yet tried
// (leaf order breaks ties), or nil when the lane has nothing left. every
// widens "fast-lane leaf" to any runnable leaf (Config.RunEveryLeaf). Priority is
// the decision engine's own dispatch ordering (registry.leafPriority) — the
// same one planexec.RunPlan uses for a plain scan.
func nextFastLaneLeaf(tree *agenttask.PlanTree, tried map[string]bool, every bool) *agenttask.PlanNode {
	if tree == nil || tree.Root == nil {
		return nil
	}
	var best *agenttask.PlanNode
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if tried[leaf.ID] {
			continue
		}
		if every {
			if !isRunnableLeaf(leaf) {
				continue
			}
		} else if !isFastLaneLeaf(leaf) {
			continue
		}
		if best == nil || leaf.Priority > best.Priority {
			best = leaf
		}
	}
	return best
}

// dispatchFastLaneLeaf runs leaf as a scan.leaf turn the orchestrator chose
// itself and returns its history record (Auto set). The dispatch is the same
// one a model-chosen scan.leaf gets — same field-miss handling, same finding
// dedup — only the choosing differs.
func dispatchFastLaneLeaf(ctx context.Context, cfg Config, tree *agenttask.PlanTree, findings *[]detectors.Finding, leaf *agenttask.PlanNode) llmfallback.TurnRecord {
	action := llmfallback.Action{
		Kind:      "scan.leaf",
		NodeID:    leaf.ID,
		Rationale: fmt.Sprintf("fast lane: %s leaf, priority %d — dispatched without a model decision", leaf.Detector, leaf.Priority),
	}
	finish := cfg.SessionLog.BeginActor("agent", action.Kind, action.Rationale, action.Params)
	summary, err := dispatch(ctx, cfg, tree, findings, action)
	finish(summary, err)

	rec := llmfallback.TurnRecord{Action: action, ResultSummary: summary, Auto: true}
	if err != nil {
		rec.Error = err.Error()
	}
	cfg.logTurn("fast lane", rec)
	return rec
}

// logTurn writes one line per dispatched turn via OnLog — the only per-turn
// visibility a CLI run had was the model's own stderr chatter, none of it
// saying what was run or what came back (LT-170, docs/follow-up.md).
func (cfg Config) logTurn(label string, rec llmfallback.TurnRecord) {
	line := fmt.Sprintf("%s: %s", label, rec.Action.Kind)
	if rec.Action.NodeID != "" {
		line += " " + rec.Action.NodeID
	}
	if rec.Action.Rationale != "" && !rec.Auto { // an auto turn's rationale is the same fixed sentence every time
		line += fmt.Sprintf(" (why: %s)", rec.Action.Rationale)
	}
	line += " — " + rec.ResultSummary
	if rec.Error != "" {
		line += " (error: " + rec.Error + ")"
	}
	cfg.logf("info", "%s", line)
}

func (cfg Config) logf(level, format string, args ...any) {
	if cfg.OnLog != nil {
		cfg.OnLog(level, fmt.Sprintf(format, args...))
	}
}

// warnDuplicateLeafTargets logs (via OnLog, so it survives a killed run —
// docs/follow-up.md LT-163 item 3) when two or more leaves in the freshly
// built tree share the same Detector+Target+EndpointTemplate — i.e. they'd
// dispatch the identical scan. This should never happen (registry.Resolve's
// own candidate generation already dedups by templated-string identity
// before a leaf is ever created), so a hit here is a real bug worth
// surfacing rather than a leaf-count vanity metric. Added investigating
// LT-166 (an eval run redispatching what looked like the same scan.leaf
// three times): reading the dedup path found it airtight for the one code
// path checked (recon.SuggestIDOREndpointCandidates), so this diagnostic
// exists to catch a duplicate that check can't see — a different leaf ID
// resolving to an identical dispatch, from a code path not yet found.
func warnDuplicateLeafTargets(cfg Config, tree *agenttask.PlanTree) {
	if tree == nil || tree.Root == nil {
		return
	}
	byKey := map[leafDispatchKey][]string{}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		k := leafDispatchKeyOf(leaf)
		byKey[k] = append(byKey[k], leaf.ID)
	}
	for k, ids := range byKey {
		if len(ids) < 2 {
			continue
		}
		cfg.logf("warn", "plan tree has %d leaves that would dispatch an identical scan (detector=%q target=%q endpoint_template=%q): %s — each will independently run and report, wasting budget/iterations on duplicate work",
			len(ids), k.detector, k.target, k.endpointTemplate, strings.Join(ids, ", "))
	}
}

// leafDispatchKey identifies what a leaf would actually dispatch —
// Detector+Target+EndpointTemplate — shared by warnDuplicateLeafTargets'
// same-tree duplicate check and mergeReconRefresh's (LT-160 item 2,
// docs/follow-up.md) cross-tree "is this genuinely new" check, so the two
// never drift into checking different notions of "identical leaf."
type leafDispatchKey struct{ detector, target, endpointTemplate string }

func leafDispatchKeyOf(leaf *agenttask.PlanNode) leafDispatchKey {
	return leafDispatchKey{leaf.Detector, leaf.Target, leaf.EndpointTemplate}
}

// hasActionableLeaves reports whether tree has any leaf a future turn could
// still make progress on — a StatusDone/StatusVetoed/StatusEscalated leaf
// never becomes actionable again, so once every leaf is one of those, the
// loop has nothing left to do regardless of what NextAction might say.
func hasActionableLeaves(tree *agenttask.PlanTree) bool {
	return hasActionableLeavesExcept(tree, nil)
}

// hasActionableLeavesExcept is hasActionableLeaves ignoring every leaf in
// skip — the fast lane's already-tried set: a leaf it dispatched that is still
// pending (skipped, not runnable) is not work the loop should keep asking the
// model about.
func hasActionableLeavesExcept(tree *agenttask.PlanTree, skip map[string]bool) bool {
	if tree == nil || tree.Root == nil {
		return false
	}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if skip[leaf.ID] {
			continue
		}
		if leaf.Status == agenttask.StatusPending || leaf.Status == agenttask.StatusUnresolved {
			return true
		}
	}
	return false
}

// buildCatalog returns the fixed tool catalog offered to NextAction.
// script.explore is always offered (see Config.AllowAgentScripts) so the
// model's view of what's possible doesn't change run to run based on a flag
// it can't see.
func buildCatalog(cfg Config) []llmfallback.ToolSpec {
	return []llmfallback.ToolSpec{
		{Kind: "recon.refresh", Description: "Re-probe a specific target (defaults to the action's node_id target, or the run's own seed target) for fresh recon facts. Any genuinely new, dispatchable leaf the fresh facts resolve to is added to the plan tree (existing leaves are never changed or removed) — use it to gather more signal, or to surface a new leaf worth a scan.leaf call next turn."},
		{Kind: "registry.lookup", Description: `Search the static capability registry for a detector/recon-tool/template-category matching a described gap. params: {"query": "<search text>"}.`},
		{Kind: "scan.leaf", Description: "Execute one existing plan-tree leaf (its own target+detector) via the real scanner. Requires node_id naming a pending or unresolved leaf that already has a detector assigned. The only way to produce a confirmed Finding."},
		{Kind: "triage.rank", Description: "Rank the findings collected so far by how worth investigating they are."},
		{Kind: "script.explore", Description: `Run a short, sandboxed Python or shell script for exploration a fixed detector/template genuinely cannot do. params: {"language": "python"|"shell", "source": "<script text>"}. Requires human approval every time; may be unavailable this run. Your script's own stdout/exit code is NEVER trusted as a finding by itself. To propose a finding, have the script print one line per candidate to stdout: "HACKERFIVE_FINDING_CANDIDATE: " followed by a JSON object {"method": "GET", "url": "...", "headers": {...}, "body": "", "type": "...", "severity": "low"|"medium"|"high"|"critical", "description": "...", "confirm_status": <int, optional>, "confirm_contains": "<substring, optional>"}. This request is independently re-issued outside the sandbox; a finding only ships if the real response matches confirm_status/confirm_contains. A candidate with neither confirm field is always dropped — give the request a real, falsifiable check, not just a claim.`},
		{Kind: "stop", Description: "Stop the run — nothing left worth another turn, or no listed tool can make further progress."},
	}
}

// dispatch runs action's tool and returns a short human-readable summary of
// what happened (fed back into the next NextAction call's history) and any
// error encountered. A non-nil error here is a tool-level failure (e.g. an
// invalid node_id, a script that failed precheck) — it does not stop Run's
// loop; it's recorded in history so the model can see the failure and choose
// differently next turn.
func dispatch(ctx context.Context, cfg Config, tree *agenttask.PlanTree, findings *[]detectors.Finding, action llmfallback.Action) (string, error) {
	switch action.Kind {
	case "recon.refresh":
		return dispatchReconRefresh(ctx, cfg, tree, action)
	case "registry.lookup":
		return dispatchRegistryLookup(action)
	case "scan.leaf":
		return dispatchScanLeaf(ctx, cfg, tree, findings, action)
	case "triage.rank":
		return dispatchTriageRank(ctx, cfg, tree, *findings)
	case "script.explore":
		if !cfg.AllowAgentScripts {
			if action.NodeID != "" {
				status := agenttask.StatusUnresolved
				reason := "script.explore requested but --allow-agent-scripts is not set"
				_ = tree.ApplyLeafUpdate(action.NodeID, agenttask.PlanNodePatch{Status: &status, Rationale: &reason})
			}
			cfg.logf("warn", "script.explore requested but --allow-agent-scripts is not set — skipping")
			return "skipped: --allow-agent-scripts not set", ErrScriptsDisallowed
		}
		return dispatchScriptExplore(ctx, cfg, findings, action)
	default:
		// NextAction's own contract already rejects any Kind not in the
		// offered catalog by degrading to "stop" before this is ever
		// reached — this default only guards against a future catalog
		// entry added here without a matching case.
		return "", fmt.Errorf("orchestrator: no dispatcher for action kind %q", action.Kind)
	}
}

func dispatchReconRefresh(ctx context.Context, cfg Config, tree *agenttask.PlanTree, action llmfallback.Action) (string, error) {
	var p struct {
		Target string `json:"target"`
	}
	if len(action.Params) > 0 {
		_ = json.Unmarshal(action.Params, &p)
	}
	target := p.Target
	if target == "" && action.NodeID != "" {
		if leaf := tree.Find(action.NodeID); leaf != nil {
			target = leaf.Target
		}
	}
	if target == "" {
		target = cfg.Target
	}

	result, err := runRecon(ctx, cfg, target, recon.DepthActive)
	if err != nil {
		return "", fmt.Errorf("recon.refresh: %w", err)
	}
	if cfg.observeRecon != nil {
		cfg.observeRecon(result)
	}
	merged := mergeReconRefresh(tree, result, cfg.TemplateIndex)
	suffix := "no new leaves"
	if merged > 0 {
		suffix = fmt.Sprintf("%d new leaf/leaves merged into the plan tree", merged)
	}
	return fmt.Sprintf("recon.refresh %s: %d endpoint(s), %d tech fact(s) — %s", target, len(result.Endpoints), len(result.TechStack), suffix), nil
}

// mergeReconRefresh is LT-160 item 2's fix (docs/follow-up.md): a
// recon.refresh dispatch used to fold only a fact-count summary into turn
// history, with no way for a genuinely new fact to ever become a
// dispatchable leaf mid-run — agenttask.PlanTree.ApplyLeafUpdate is
// deliberately leaf-mutation-only (doc90 §2's shape-change defense), and no
// post-construction "add a leaf" path existed outside registry.Resolve's own
// initial build (doc93 M2's own noted scope-narrowing).
//
// This closes that gap the same additive-only way llmfallback.
// MergeLLMProposals already does for an LLM-proposed leaf: fresh is run
// through the exact same deterministic registry.Resolve used to build the
// tree in the first place — so a "new leaf" here is never an LLM inventing
// one, only the same rule table registry.Resolve always applies, now
// re-applied to newly observed facts. A host recon.refresh newly discovered
// (one the initial tree never saw at all) gets its whole freshly-resolved
// subtree attached under root; a host the tree already has gets only its
// genuinely new leaves (leafDispatchKey not already present anywhere under
// that host) attached via agenttask.AttachLeaf — every existing leaf's own
// Status/Confidence/Rationale is left untouched, preserving doc02 Design
// Principle 5 ("a later pass can only ever weaken a plan, never strengthen
// it... none can add a leaf" — that principle constrains leaf-*resolution*
// passes re-judging an existing leaf; this is a different operation,
// growing the tree from new deterministic facts, not re-scoring one).
// Returns how many leaves were actually merged.
func mergeReconRefresh(tree *agenttask.PlanTree, fresh *recon.ReconResult, templateIndex []templatesync.Entry) int {
	if tree == nil || tree.Root == nil || fresh == nil {
		return 0
	}
	freshTree, _ := registry.Resolve(fresh, templateIndex)
	if freshTree == nil || freshTree.Root == nil {
		return 0
	}

	merged := 0
	for _, freshHost := range freshTree.Root.Children {
		existingHost := tree.Find(freshHost.ID)
		if existingHost == nil {
			// A host recon.refresh discovered that the initial tree never
			// saw at all — attach its whole freshly-resolved subtree, the
			// same shape registry.Resolve would have produced had this host
			// been part of the original recon result.
			tree.Root.Children = append(tree.Root.Children, freshHost)
			merged += len(agenttask.Leaves(freshHost))
			continue
		}
		existingKeys := make(map[leafDispatchKey]bool)
		for _, leaf := range agenttask.Leaves(existingHost) {
			existingKeys[leafDispatchKeyOf(leaf)] = true
		}
		for _, leaf := range agenttask.Leaves(freshHost) {
			if existingKeys[leafDispatchKeyOf(leaf)] {
				continue
			}
			agenttask.AttachLeaf(existingHost, leaf, registry.LeafClass(leaf))
			merged++
		}
	}
	return merged
}

// runRecon calls cfg.Recon.Run bounded by cfg.ReconTimeout — see
// DefaultReconTimeout's doc comment for why every call site goes through
// this rather than cfg.Recon.Run directly.
func runRecon(ctx context.Context, cfg Config, target string, depth recon.Depth) (*recon.ReconResult, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.ReconTimeout)
	defer cancel()
	return cfg.Recon.Run(ctx, target, depth)
}

func dispatchRegistryLookup(action llmfallback.Action) (string, error) {
	var p struct {
		Query string `json:"query"`
	}
	if len(action.Params) > 0 {
		_ = json.Unmarshal(action.Params, &p)
	}
	if p.Query == "" {
		return "", errors.New(`registry.lookup requires params: {"query": "..."}`)
	}
	matches := registry.Search(p.Query)
	if len(matches) == 0 {
		return fmt.Sprintf("no capability matched %q", p.Query), nil
	}
	names := make([]string, 0, len(matches))
	for _, c := range matches {
		names = append(names, c.Name)
	}
	return fmt.Sprintf("matched: %s", strings.Join(names, ", ")), nil
}

// fieldMissDetectors is the set of detectors fieldsuggest.Deterministic
// knows how to resolve a required-config-field miss for — resolveMissingLeafField's
// gate on which skipped leaf is even worth a retry attempt.
var fieldMissDetectors = map[string]bool{"idor": true, "authbypass": true, "ssrf": true}

func dispatchScanLeaf(ctx context.Context, cfg Config, tree *agenttask.PlanTree, findings *[]detectors.Finding, action llmfallback.Action) (string, error) {
	if action.NodeID == "" {
		return "", errors.New("scan.leaf requires node_id")
	}
	leaf := tree.Find(action.NodeID)
	if leaf == nil {
		return "", fmt.Errorf("scan.leaf: node %q not found", action.NodeID)
	}
	if leaf.Status != agenttask.StatusPending && leaf.Status != agenttask.StatusUnresolved {
		return "", fmt.Errorf("scan.leaf: node %q is not runnable (status %s)", action.NodeID, leaf.Status)
	}
	if leaf.Detector == "" {
		return "", fmt.Errorf("scan.leaf: node %q has no detector assigned yet", action.NodeID)
	}

	summary, realSkipped, err := runScanLeafOnce(ctx, cfg, cfg.BaseScanConfig, tree, leaf, findings)
	if len(realSkipped) == 0 || !fieldMissDetectors[leaf.Detector] {
		return summary, err
	}

	// LT-138 item 1 (docs/follow-up.md): the leaf resolved fine but is
	// blocked purely on a required execution field recon never derived
	// (idor's EndpointTemplate / authbypass's ProtectedPaths / ssrf's
	// SSRFParams) — I4's field-miss resolution used to never run for this
	// case at all (llmfallback.ResolveTreeLeaves only ever acts on a
	// StatusUnresolved decision-engine miss, not a StatusPending leaf blocked
	// on a field). resolveMissingLeafField mirrors pkg/mcpserver's own
	// resolveFieldSuggestions/fieldsuggest.Deterministic flow: a single
	// deterministic candidate auto-fills (no LLM call, no gate — already
	// unconditional in mcpserver/webui too) and the dispatch is retried once
	// against the filled-in config; a genuine miss is resolved via I4 but
	// only ever surfaced in the summary, never auto-applied to execution.
	filled, note, applied := resolveMissingLeafField(ctx, cfg, tree, leaf)
	if !applied {
		if note != "" {
			return summary + " — " + note, err
		}
		return summary, err
	}
	retrySummary, _, retryErr := runScanLeafOnce(ctx, cfg, filled, tree, leaf, findings)
	return retrySummary + " (" + note + ")", retryErr
}

// runScanLeafOnce runs planexec.RunPlan against every leaf but leaf excluded
// (dispatchScanLeaf's own single-leaf dispatch shape), returning a
// human-readable summary, the targeted leaf's own real skip reason(s) (never
// the "excluded by operator" noise LT-162 already filters out), and any
// dispatch error. Factored out of dispatchScanLeaf so LT-138's field-miss
// retry can call it a second time against a filled-in scanConfig without
// duplicating the Excluded-map/skip-filtering logic.
func runScanLeafOnce(ctx context.Context, cfg Config, scanConfig scanner.Config, tree *agenttask.PlanTree, leaf *agenttask.PlanNode, findings *[]detectors.Finding) (summary string, realSkipped []string, err error) {
	excluded := make(map[string]bool)
	for _, l := range agenttask.Leaves(tree.Root) {
		if l.ID != leaf.ID {
			excluded[l.ID] = true
		}
	}

	// LT-166 (docs/follow-up.md): every dispatch's RunPlan reloads the whole
	// corpus, so a finding from a corpus template (or the same detector hit)
	// is re-fired by each later dispatch. Only a finding not already recorded
	// this run is new — a repeat is counted and dropped (not appended to the
	// run's findings, not streamed again), so neither the report nor the
	// model's per-turn result mistakes a re-fire for fresh evidence.
	seen := findingKeys(*findings)
	var leafFindings []detectors.Finding
	duplicates := 0
	_, logs, skipped, err := planexec.RunPlan(ctx, tree, scanConfig, cfg.TemplateIndex, planexec.ExecOptions{
		Excluded:       excluded,
		DetConcurrency: 1,
		LLMConcurrency: 1,
		OnFinding: func(_ *agenttask.PlanNode, f detectors.Finding) {
			k := findingKey(f)
			if seen[k] {
				duplicates++
				return
			}
			seen[k] = true
			leafFindings = append(leafFindings, f)
			if cfg.OnFinding != nil {
				cfg.OnFinding(f)
			}
		},
		OnLog: func(_ *agenttask.PlanNode, level, msg string) {
			if cfg.OnLog != nil {
				cfg.OnLog(level, msg)
			}
		},
	})
	*findings = append(*findings, leafFindings...)
	// LT-162 (docs/follow-up.md): every other leaf in the tree is
	// deliberately marked Excluded above so RunPlan touches only the one
	// leaf this action named — which means `skipped` always contains one
	// "excluded by operator before approval" entry per other leaf, on every
	// single scan.leaf dispatch, success or not. Reporting that wholesale
	// meant the model never once saw "N finding(s)" as this turn's
	// ResultSummary — only a wall of noise about leaves it never asked to
	// run — leaving it with no real signal about whether a dispatch worked.
	// Only a skip belonging to the actually-targeted leaf (never in
	// `excluded`) is a real one worth reporting.
	for _, s := range skipped {
		if id, _, ok := strings.Cut(s, ":"); ok && excluded[id] {
			continue
		}
		realSkipped = append(realSkipped, s)
	}
	if len(realSkipped) > 0 {
		return fmt.Sprintf("skipped: %s", strings.Join(realSkipped, "; ")), realSkipped, err
	}
	return scanLeafSummary(leafFindings, duplicates, len(logs)), nil, err
}

// maxFindingsInSummary bounds how many new findings a scan.leaf result names.
const maxFindingsInSummary = 5

// scanLeafSummary is a scan.leaf turn's result as the model reads it next
// turn: how many findings were genuinely new (named, so it can tell them
// apart) and how many were repeats of ones already recorded — never a bare
// count (LT-171, docs/follow-up.md).
func scanLeafSummary(fresh []detectors.Finding, duplicates, logLines int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d new finding(s)", len(fresh))
	if len(fresh) > 0 {
		names := make([]string, 0, maxFindingsInSummary)
		for i, f := range fresh {
			if i == maxFindingsInSummary {
				names = append(names, fmt.Sprintf("+%d more", len(fresh)-maxFindingsInSummary))
				break
			}
			names = append(names, fmt.Sprintf("%s %s %s", f.ID, f.Severity, f.Target))
		}
		fmt.Fprintf(&b, " [%s]", strings.Join(names, "; "))
	}
	if duplicates > 0 {
		fmt.Fprintf(&b, ", %d repeat(s) of already-recorded findings ignored", duplicates)
	}
	fmt.Fprintf(&b, ", %d log line(s)", logLines)
	return b.String()
}

// findingKey identifies a finding for de-duplication within one run: the same
// detection of the same target, however many dispatches re-fire it.
func findingKey(f detectors.Finding) string {
	return f.ID + "\x00" + f.Type + "\x00" + f.Target + "\x00" + f.Description
}

func findingKeys(fs []detectors.Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[findingKey(f)] = true
	}
	return m
}

// resolveMissingLeafField is LT-138 item 1's fix (docs/follow-up.md). It
// re-probes leaf's own target host for fresh recon facts (mirroring
// dispatchReconRefresh's own recon call, self-contained rather than
// threading a persistent recon result through Run's whole loop) and runs
// them through fieldsuggest.Deterministic — the exact same no-LLM auto-fill
// pkg/mcpserver's resolveFieldSuggestions/pkg/webui already apply
// unconditionally. A single deterministic candidate is applied to a copy of
// cfg.BaseScanConfig and returned for an immediate retry (applied=true). A
// genuine miss (0 or >1 candidates) is resolved via I4 (cfg.Client.ResolveField,
// cost tracked against tree's own spend ceiling) but — matching
// pkg/mcpserver's applyFieldSuggestion doc comment ("an LLM-resolved miss is
// surfaced ... but never auto-injected into execution") — is only ever
// returned as a note, applied always false: auto-applying a model's own
// guess at which endpoint to enumerate would fire real, consequential
// requests based purely on that guess with no human review, the exact gate
// doc90 Decision 5/6 requires before anything consequential runs.
func resolveMissingLeafField(ctx context.Context, cfg Config, tree *agenttask.PlanTree, leaf *agenttask.PlanNode) (filled scanner.Config, note string, applied bool) {
	filled = cfg.BaseScanConfig
	result, err := runRecon(ctx, cfg, leaf.Target, recon.DepthActive)
	if err != nil {
		return filled, fmt.Sprintf("field-miss probe failed: %v", err), false
	}

	sugs, misses := fieldsuggest.Deterministic(result, map[string]bool{leaf.Detector: true})
	for _, s := range sugs {
		applyFieldSuggestionToScanConfig(&filled, s)
	}
	if len(sugs) > 0 {
		return filled, fmt.Sprintf("auto-filled %s's required field from a fresh recon probe (single deterministic candidate)", leaf.Detector), true
	}
	if len(misses) == 0 {
		return cfg.BaseScanConfig, "", false
	}

	var notes []string
	for _, m := range misses {
		decision, cost, err := cfg.Client.ResolveField(ctx, m.Detector, m.Field, m.Candidates)
		tree.AddSpend(cost)
		switch {
		case err != nil:
			notes = append(notes, fmt.Sprintf("%s.%s: I4 resolution failed: %v", m.Detector, m.Field, err))
		case decision.EscalateToHuman != "":
			notes = append(notes, fmt.Sprintf("%s.%s: I4 escalated to human: %s", m.Detector, m.Field, decision.EscalateToHuman))
		default:
			notes = append(notes, fmt.Sprintf("%s.%s: I4 suggests %q (%s) — needs human review/config, not auto-applied", m.Detector, m.Field, decision.SuggestedValue, decision.Rationale))
		}
	}
	return cfg.BaseScanConfig, strings.Join(notes, "; "), false
}

// applyFieldSuggestionToScanConfig writes a deterministic (non-LLM)
// recon-derived field value into cfg — the same switch
// pkg/mcpserver/tools_plan.go's applyFieldSuggestion and pkg/webui's own
// equivalent already apply (a fourth near-duplicate has crept in here rather
// than a shared helper; consolidating those three is a separate, unrelated
// cleanup, not attempted as part of this fix).
func applyFieldSuggestionToScanConfig(cfg *scanner.Config, s agenttask.FieldSuggestion) {
	switch s.Field {
	case "endpoint_template":
		cfg.EndpointTemplate = s.SuggestedValue
	case "protected_paths":
		if s.SuggestedValue != "" {
			cfg.ProtectedPaths = []string{s.SuggestedValue}
		} else {
			cfg.ProtectedPaths = s.Candidates
		}
	case "login_paths":
		cfg.LoginPaths = s.Candidates
	case "logout_paths":
		cfg.LogoutPaths = s.Candidates
	case "ssrf_params":
		cfg.SSRFParams = s.Candidates
	}
}

func dispatchTriageRank(ctx context.Context, cfg Config, tree *agenttask.PlanTree, findings []detectors.Finding) (string, error) {
	if len(findings) == 0 {
		return "no findings yet to triage", nil
	}
	result, cost, err := cfg.Client.TriageFindings(ctx, findings)
	tree.AddSpend(cost)
	if err != nil {
		return "", fmt.Errorf("triage.rank: %w", err)
	}
	if result.EscalateToHuman != "" {
		return "triage escalated: " + result.EscalateToHuman, nil
	}
	return fmt.Sprintf("ranked %d finding(s)", len(result.Ranked)), nil
}

func dispatchScriptExplore(ctx context.Context, cfg Config, findings *[]detectors.Finding, action llmfallback.Action) (string, error) {
	var p struct {
		Language string `json:"language"`
		Source   string `json:"source"`
	}
	if err := json.Unmarshal(action.Params, &p); err != nil {
		return "", fmt.Errorf(`script.explore: invalid params (want {"language": "python"|"shell", "source": "..."}): %w`, err)
	}
	var lang scriptexec.Language
	switch p.Language {
	case string(scriptexec.LangPython):
		lang = scriptexec.LangPython
	case string(scriptexec.LangShell):
		lang = scriptexec.LangShell
	default:
		return "", fmt.Errorf("script.explore: unsupported language %q", p.Language)
	}
	if strings.TrimSpace(p.Source) == "" {
		return "", errors.New("script.explore: empty source")
	}

	req := scriptexec.ScriptRequest{
		Language:     lang,
		Source:       p.Source,
		Scope:        cfg.BaseScanConfig.Scope,
		Timeout:      cfg.ScriptTimeout,
		ApprovalGate: cfg.ApprovalGate,
	}
	res, err := scriptexec.Execute(ctx, req)
	if err != nil {
		return "", fmt.Errorf("script.explore: %w", err)
	}

	summary := fmt.Sprintf("exit=%d stdout=%s stderr=%s", res.ExitCode, truncateForHistory(res.Stdout), truncateForHistory(res.Stderr))
	// LT-160 item 1 (docs/follow-up.md): the script's own stdout/exit code
	// above is never sufficient to become a Finding on its own — every
	// HACKERFIVE_FINDING_CANDIDATE line it printed is independently
	// re-issued outside the sandbox first (scriptevidence.go); only a
	// candidate whose real, re-issued response matches its own stated
	// confirmation condition ships.
	confirmedFindings, notes := reconfirmScriptCandidates(ctx, cfg, res.Stdout)
	seen := findingKeys(*findings)
	for _, f := range confirmedFindings {
		if seen[findingKey(f)] {
			continue
		}
		seen[findingKey(f)] = true
		*findings = append(*findings, f)
		if cfg.OnFinding != nil {
			cfg.OnFinding(f)
		}
	}
	if len(notes) > 0 {
		summary += " | " + strings.Join(notes, "; ")
	}
	return summary, nil
}

// maxHistorySnippet bounds how much of a script's stdout/stderr is folded
// back into TurnRecord.ResultSummary — the full output already reached the
// human via ApprovalGate/the CLI's own printing; history only needs enough
// for the next NextAction call to see what happened.
const maxHistorySnippet = 500

func truncateForHistory(s string) string {
	if len(s) <= maxHistorySnippet {
		return s
	}
	return s[:maxHistorySnippet] + "...(truncated)"
}
