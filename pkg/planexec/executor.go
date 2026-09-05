// Package planexec dispatches an approved agenttask.PlanTree's leaves into
// real pkg/scanner runs. Originally pkg/mcpserver's own executor.go (Phase 6
// Step 2) — extracted here (Phase 6 Step 4) so pkg/webui's Plan Preview page
// can dispatch the exact same tree an MCP client's elicitation-gated `plan`
// tool call would, instead of only ever computing it and throwing the result
// away (docs/follow-up.md's "Live Testing" LT-1). The MCP-specific pieces
// (mcp.ServerSession progress notifications, the elicitation round trip
// itself) stay in pkg/mcpserver — this package only knows about
// agenttask/scanner/templatesync, plus a small, protocol-agnostic
// ExecOptions callback surface both callers adapt to their own transport.
package planexec

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/workerpool"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// recognizedDetectors mirrors pkg/scanner/config.go's own unexported set —
// duplicated rather than exported from pkg/scanner, since it's a small,
// stable list and cfg.Validate() (called per leaf below) remains the real
// authority; this copy only decides whether a leaf is even worth building a
// Config for. A leaf whose Detector is a raw template ID (registry.Resolve's
// template-tag-match case, or an I4 use_existing_tag decision naming a
// template rather than a built-in detector) is dispatched separately, as a
// templates-only run — see RunPlan's eligibility loop and runLeaf, below.
var recognizedDetectors = map[string]bool{
	"idor": true, "misconfig": true, "authbypass": true, "ssrf": true, "businesslogic": true,
}

// executionResult is one leaf's dispatch outcome, folded into RunPlan's
// return value.
type executionResult struct {
	findings []detectors.Finding
	logs     []string
	err      error
}

// ExecOptions configures one RunPlan call — every field is optional/nil-safe
// except the two concurrency sizes, which a caller should always set
// explicitly (a non-positive value falls back to 1 rather than panicking on
// workerpool.New, but that's a degraded-not-ideal default, not a real tuning
// choice).
type ExecOptions struct {
	// Notify, if set, is called with informational progress text as each
	// dispatched leaf's engine reports it — mirrors what
	// mcp.ServerSession.NotifyProgress carried before this package existed;
	// pkg/mcpserver's own call site now builds that notification from this
	// callback instead of RunPlan doing it directly.
	Notify func(target, message string)
	// OnFinding, if set, is called synchronously the instant a leaf's
	// engine reports a real Finding — lets a caller stream results live
	// (e.g. into a running webui Job's SSE feed) instead of waiting for
	// RunPlan to return. Findings are still also collected into the
	// returned slice regardless, so a caller with no live-streaming need
	// (pkg/mcpserver, a single synchronous tool-call response) can leave
	// this nil and just use the return value, unchanged from before.
	OnFinding func(leaf *agenttask.PlanNode, f detectors.Finding)
	// OnLog mirrors OnFinding for scanner.Engine's log lines.
	OnLog func(leaf *agenttask.PlanNode, level, msg string)
	// Excluded marks leaf IDs an operator deselected before approving (a
	// webui Plan Preview "run this leaf" checkbox left unchecked) — skipped
	// outright, reported in the returned skipped slice like any other skip
	// reason, never silently dropped. nil/empty means nothing is excluded.
	Excluded map[string]bool
	// DetConcurrency/LLMConcurrency size the two dispatch tiers (R8-matched
	// vs. use_existing_tag/LLM-resolved, not "deterministic vs. currently-
	// costing-LLM" — see doc15 Step 2's Done note for the corrected tier
	// semantics).
	DetConcurrency int
	LLMConcurrency int
}

// RunPlan walks tree's leaves and dispatches each eligible one to a real
// scanner.Engine run, using baseCfg as the shared template (Scope,
// AuthToken, EndpointTemplate, ProtectedPaths, SSRFParams, AllowWrites,
// ExtraHeaders, TemplatePaths, Concurrency/RateLimit/Timeout — everything
// except Targets/Detector/TemplateID, which this function fills per leaf).
//
// The loaded template corpus (baseCfg.TemplatePaths) runs additively against
// a target for every leaf, so on a host with several builtin-capability
// leaves it would otherwise re-parse and re-fire the whole corpus once per
// leaf — same corpus, same target, pure duplicate load (docs/follow-up.md
// LT-18). RunPlan attaches TemplatePaths to only the first builtin leaf per
// host; the rest run their own detector alone. A specific-template leaf
// always keeps the corpus — it needs a full load to resolve its one id:.
// Eligible leaves are R8-matched or use_existing_tag-resolved leaves whose
// Detector is either one of scanner's recognized built-in names, or a real
// template ID/tag present in templateIndex — dispatched as a templates-only
// run in that second case (runLeaf). draft_template and escalate_to_human
// leaves, any Detector matching neither a built-in name nor a real template
// ID (a hallucination), and any leaf ID named in opts.Excluded are skipped
// (never executed this step) — skipped leaves are reported via skipped, not
// silently dropped.
func RunPlan(ctx context.Context, tree *agenttask.PlanTree, baseCfg scanner.Config, templateIndex []templatesync.Entry, opts ExecOptions) (findings []detectors.Finding, logs []string, skipped []string, err error) {
	if opts.DetConcurrency <= 0 {
		opts.DetConcurrency = 1
	}
	if opts.LLMConcurrency <= 0 {
		opts.LLMConcurrency = 1
	}

	knownTemplateIDs := make(map[string]bool, len(templateIndex))
	for _, entry := range templateIndex {
		knownTemplateIDs[entry.ID] = true
	}

	var deterministic, llmAssisted []*agenttask.PlanNode
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if opts.Excluded[leaf.ID] {
			skipped = append(skipped, fmt.Sprintf("%s: excluded by operator before approval", leaf.ID))
			continue
		}
		eligible := recognizedDetectors[leaf.Detector] || (leaf.Detector != "" && knownTemplateIDs[leaf.Detector])
		if !eligible {
			if leaf.Detector != "" {
				skipped = append(skipped, fmt.Sprintf("%s: not executed this step (unrecognized detector/template-ID %q — requires separate human promotion or manual run)", leaf.ID, leaf.Detector))
			}
			continue
		}
		if reason := missingRequiredField(leaf.Detector, baseCfg); reason != "" {
			skipped = append(skipped, fmt.Sprintf("%s: skipped — %s (same skip-and-explain posture as pkg/webui's fillReconFields)", leaf.ID, reason))
			continue
		}
		if strings.HasPrefix(leaf.Rationale, llmfallback.ResolvedRationalePrefix) {
			llmAssisted = append(llmAssisted, leaf)
		} else {
			deterministic = append(deterministic, leaf)
		}
	}

	// LT-18 part (c): decide which leaves carry the additive template-corpus
	// pass. A specific-template leaf always does (it needs a full load to
	// match its one id:); among builtin-capability leaves, only the first per
	// host does — the rest run their detector alone. Decided here, before
	// dispatch, in the same order leaves run (deterministic batch, then
	// llmAssisted).
	corpusLeaves := make(map[string]bool)
	if len(baseCfg.TemplatePaths) > 0 {
		seenHost := make(map[string]bool)
		for _, batch := range [][]*agenttask.PlanNode{deterministic, llmAssisted} {
			for _, leaf := range batch {
				if !recognizedDetectors[leaf.Detector] {
					corpusLeaves[leaf.ID] = true
					continue
				}
				if host := targetHostKey(leaf.Target); !seenHost[host] {
					seenHost[host] = true
					corpusLeaves[leaf.ID] = true
				}
			}
		}
	}

	var mu sync.Mutex
	dispatch := func(pool *workerpool.Pool, batch []*agenttask.PlanNode) {
		for _, leaf := range batch {
			leaf := leaf
			loadCorpus := corpusLeaves[leaf.ID]
			_ = pool.Submit(func(ctx context.Context) error {
				res := runLeaf(ctx, leaf, baseCfg, loadCorpus, opts)
				mu.Lock()
				findings = append(findings, res.findings...)
				logs = append(logs, res.logs...)
				mu.Unlock()
				status := agenttask.StatusDone
				patch := agenttask.PlanNodePatch{Status: &status}
				if res.err != nil {
					msg := res.err.Error()
					patch.Rationale = &msg
				}
				_ = tree.ApplyLeafUpdate(leaf.ID, patch)
				return res.err
			})
		}
	}

	detPool := workerpool.New(ctx, opts.DetConcurrency, 2*opts.DetConcurrency)
	dispatch(detPool, deterministic)
	detErrs := detPool.Wait()

	llmPool := workerpool.New(ctx, opts.LLMConcurrency, 2*opts.LLMConcurrency)
	dispatch(llmPool, llmAssisted)
	llmErrs := llmPool.Wait()

	allErrs := append(detErrs, llmErrs...)
	if len(allErrs) > 0 {
		err = fmt.Errorf("plan execution completed with %d leaf error(s), first: %w", len(allErrs), allErrs[0])
	}
	return findings, logs, skipped, err
}

// missingRequiredField reports, in plain text, which of idor's
// EndpointTemplate, authbypass's ProtectedPaths, ssrf's SSRFParams, or
// businesslogic's --allow-writes/auth-token is still unset on cfg for
// detector — "" if detector has no such requirement or it's already
// filled. Mirrors pkg/webui's fillReconFields: a detector that needs a
// field recon/I4 couldn't resolve — or, for businesslogic, a gate only a
// human can set — is skipped outright, never run against a live target
// with SkipXRequired papering over a blank value.
//
// businesslogic's case (P1-1, docs/follow-up.md): registry.Resolve can now
// emit a businesslogic leaf from an observed cart/checkout/coupon-shaped
// endpoint alone, with no idea whether the operator has opted into
// mutating checks. Without this gate that leaf would reach cfg.Validate
// and fail loudly instead of skipping cleanly — --allow-writes/AuthToken
// are exactly the two things recon/I4 must never supply on their own
// (CLAUDE.md's write-safety rule), so this only ever narrows what already
// requires a human, it never relaxes it.
func missingRequiredField(detector string, cfg scanner.Config) string {
	switch detector {
	case "idor":
		if cfg.EndpointTemplate == "" {
			return "no --endpoint given and recon/I4 found no usable candidate"
		}
	case "authbypass":
		if len(cfg.ProtectedPaths) == 0 {
			return "no --protected-paths given and recon/I4 found no usable candidate"
		}
	case "ssrf":
		if len(cfg.SSRFParams) == 0 {
			return "no --ssrf-param given and recon found no usable candidate"
		}
	case "businesslogic":
		if !cfg.AllowWrites {
			return "--allow-writes not set — businesslogic's mutating checks are never run without explicit opt-in"
		}
		if cfg.AuthToken == "" {
			return "no --auth-token given — businesslogic requires an owner auth token"
		}
	}
	return ""
}

// targetHostKey reduces a leaf's Target URL to a scheme+host key, so leaves
// on the same host (identical, or differing only in path) share one
// once-per-host corpus pass. Falls back to the raw string if it doesn't
// parse as a URL with a host.
func targetHostKey(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return target
	}
	return u.Scheme + "://" + u.Host
}

func runLeaf(ctx context.Context, leaf *agenttask.PlanNode, baseCfg scanner.Config, loadCorpus bool, opts ExecOptions) executionResult {
	cfg := baseCfg
	cfg.Targets = []string{leaf.Target}
	if !loadCorpus {
		// Another leaf on this host already carries the once-per-host additive
		// template-corpus pass (see RunPlan) — this builtin-detector leaf runs
		// its own check only.
		cfg.TemplatePaths = nil
	}

	validateOpts := scanner.ValidateOptions{
		SkipEndpointRequired:       true,
		SkipProtectedPathsRequired: true,
		SkipSSRFParamsRequired:     true,
		SkipAuthTokenRequired:      true,
	}
	if recognizedDetectors[leaf.Detector] {
		cfg.Detector = leaf.Detector
	} else {
		// A specific-template leaf, not a built-in detector — RunPlan's
		// eligibility loop only lets a leaf reach here if leaf.Detector is
		// either a recognized detector name or a real template ID/tag, so
		// anything not the former is the latter. Such a leaf always has
		// loadCorpus true (RunPlan), so TemplatePaths is baseCfg's own
		// (the same synced+bundled directories the whole plan uses) —
		// narrowing to just this one template happens by exact id: match at
		// load time (Config.TemplateID), not by pointing at a different
		// directory.
		cfg.Detector = ""
		cfg.TemplateID = leaf.Detector
		validateOpts.SkipDetectorRequired = true
	}

	if err := cfg.ValidateWithOptions(validateOpts); err != nil {
		return executionResult{err: fmt.Errorf("leaf %s: %w", leaf.ID, err)}
	}

	var res executionResult
	notify := func(message string) {
		if opts.Notify != nil {
			opts.Notify(leaf.Target, message)
		}
	}

	engine := scanner.New(cfg).
		WithFindingCallback(func(f detectors.Finding) {
			res.findings = append(res.findings, f)
			if opts.OnFinding != nil {
				opts.OnFinding(leaf, f)
			}
			notify("finding: " + f.Type)
		}).
		WithLogCallback(func(level, msg string) {
			res.logs = append(res.logs, level+": "+msg)
			if opts.OnLog != nil {
				opts.OnLog(leaf, level, msg)
			}
			notify(msg)
		})

	if _, err := engine.Run(ctx); err != nil {
		res.err = fmt.Errorf("leaf %s: %w", leaf.ID, err)
	}
	return res
}
