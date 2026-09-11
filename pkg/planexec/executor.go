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
	"sort"
	"strings"
	"sync"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
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
	"netservice": true,
}

// executionResult is one leaf's dispatch outcome, folded into RunPlan's
// return value.
type executionResult struct {
	findings []detectors.Finding
	logs     []string
	err      error
	// skip is set (instead of running the leaf) when a C7a deferred-gate
	// leaf still has no required field after any SeedFn contribution —
	// RunPlan appends it to skipped and does not mark the leaf done.
	skip string
}

// seedFillableDetector names the detectors whose one required field a
// SeedFn can supply (C7a) — the pre-dispatch missing-field gate is deferred
// to runLeaf for these when opts.SeedFn is set. EndpointSeedFromFindings
// only fills idor/ssrf; authbypass is here so a custom SeedFn could fill it
// too (the built-in leaves it, so it simply skips later — same outcome).
var seedFillableDetector = map[string]bool{"idor": true, "ssrf": true, "authbypass": true}

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
	// SeedFn is C7a's early-leaf-output → later-leaf-input hook (doc16 Phase
	// 7 Step 3): after each leaf finishes, RunPlan calls it with that leaf,
	// its findings, and the same-host leaves not yet dispatched; it returns
	// zero or more LeafSeeds applied to a target leaf's cloned Config
	// (blank fields only) just before that leaf runs. Best-effort by design
	// — a seed only lands if its target leaf hasn't started yet, which
	// priority ordering (sharper, higher-priority leaves first) makes the
	// common case. planexec.EndpointSeedFromFindings is the one built-in
	// implementation (idor EndpointTemplate / ssrf SSRFParams from a
	// same-host finding's URL). nil disables seeding entirely.
	SeedFn func(done *agenttask.PlanNode, findings []detectors.Finding, candidates []*agenttask.PlanNode) []LeafSeed
	// Excluded marks leaf IDs an operator deselected before approving (a
	// webui Plan Preview "run this leaf" checkbox left unchecked) — skipped
	// outright, reported in the returned skipped slice like any other skip
	// reason, never silently dropped. nil/empty means nothing is excluded.
	Excluded map[string]bool
	// OnOutOfScope is doc90's B4 scope-creep gate at the executor (doc15 Step
	// 3). Before dispatching, RunPlan checks every leaf target against
	// baseCfg.Scope; if any fall outside the scope the human approved and this
	// callback is set, RunPlan calls it with the distinct out-of-scope hosts
	// and — on a non-nil return — halts, dispatching nothing. It is the named
	// trigger point for a future mid-scan re-recon leaf surfacing new
	// out-of-scope hosts; today no leaf runs recon, so it only fires on a plan
	// that already carries an out-of-scope leaf (a hand-built tree, or a bug
	// upstream). nil (or a nil baseCfg.Scope) leaves the pre-B4 behaviour
	// unchanged — the engine's own per-target scope skip still applies.
	OnOutOfScope func(hosts []string) error
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

	// B4 scope-creep gate (doc15 Step 3): halt before any dispatch if an
	// approved leaf targets a host outside baseCfg.Scope.
	if opts.OnOutOfScope != nil && baseCfg.Scope != nil {
		var oos []string
		seen := map[string]bool{}
		for _, leaf := range agenttask.Leaves(tree.Root) {
			if baseCfg.Scope.Allowed(leaf.Target) {
				continue
			}
			if h := targetHostKey(leaf.Target); !seen[h] {
				seen[h] = true
				oos = append(oos, h)
			}
		}
		if len(oos) > 0 {
			if err := opts.OnOutOfScope(oos); err != nil {
				return nil, nil, nil, err
			}
		}
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
		if leaf.Status == agenttask.StatusVetoed {
			// C7b: an LLM plausibility pass judged this leaf implausible. It
			// stays in the tree (visible, with the veto reason in Rationale)
			// but is never dispatched.
			skipped = append(skipped, fmt.Sprintf("%s: skipped — plausibility veto: %s", leaf.ID, leaf.Rationale))
			continue
		}
		if leaf.Status == agenttask.StatusEscalated {
			// H4: LLM-fallback resolution ground through this leaf's
			// attempt/spend budget without a confident answer. Visible in the
			// tree with the reason in Rationale, never dispatched.
			skipped = append(skipped, fmt.Sprintf("%s: skipped — escalated (resolve budget exhausted): %s", leaf.ID, leaf.Rationale))
			continue
		}
		eligible := recognizedDetectors[leaf.Detector] || (leaf.Detector != "" && knownTemplateIDs[leaf.Detector])
		if !eligible {
			if leaf.Detector != "" {
				skipped = append(skipped, fmt.Sprintf("%s: not executed this step (unrecognized detector/template-ID %q — requires separate human promotion or manual run)", leaf.ID, leaf.Detector))
			}
			continue
		}
		// C7a: when a SeedFn is set, an idor/ssrf/authbypass leaf missing its
		// field here may still get it from an earlier same-host leaf's finding
		// during dispatch — defer that gate to runLeaf (post-seed) for those
		// detectors. Every other detector, and the no-SeedFn path, keep the
		// pre-dispatch gate exactly as before.
		if opts.SeedFn == nil || !seedFillableDetector[leaf.Detector] {
			if reason := missingRequiredFieldForLeaf(leaf, baseCfg); reason != "" {
				skipped = append(skipped, fmt.Sprintf("%s: skipped — %s (same skip-and-explain posture as pkg/webui's fillReconFields)", leaf.ID, reason))
				continue
			}
		}
		if strings.HasPrefix(leaf.Rationale, llmfallback.ResolvedRationalePrefix) {
			llmAssisted = append(llmAssisted, leaf)
		} else {
			deterministic = append(deterministic, leaf)
		}
	}

	// C7a: within each tier, dispatch higher-Priority leaves first. The
	// worker pool submits in slice order, so with a bounded pool this orders
	// *start* order — sharper, higher-confidence leaves (and, for SeedFn, the
	// ones whose findings help a later sibling) get a head start. Stable, so
	// leaves with no priority set keep their registry.Resolve order.
	sortByPriorityDesc(deterministic)
	sortByPriorityDesc(llmAssisted)

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

	// C7a seed store: a completed leaf's SeedFn output, keyed by the target
	// leaf ID, read by runLeaf just before that leaf builds its Config.
	// First writer wins. leavesByHost gives SeedFn its same-host candidate
	// set. Both guarded by mu, alongside the findings/logs accumulation.
	var mu sync.Mutex
	seeds := map[string]LeafSeed{}
	leavesByHost := map[string][]*agenttask.PlanNode{}
	if opts.SeedFn != nil {
		for _, leaf := range agenttask.Leaves(tree.Root) {
			h := targetHostKey(leaf.Target)
			leavesByHost[h] = append(leavesByHost[h], leaf)
		}
	}
	seedLookup := func(id string) (LeafSeed, bool) {
		mu.Lock()
		defer mu.Unlock()
		s, ok := seeds[id]
		return s, ok
	}

	dispatch := func(pool *workerpool.Pool, batch []*agenttask.PlanNode) {
		for _, leaf := range batch {
			leaf := leaf
			loadCorpus := corpusLeaves[leaf.ID]
			_ = pool.Submit(func(ctx context.Context) error {
				res := runLeaf(ctx, leaf, baseCfg, loadCorpus, opts, seedLookup)
				if res.skip != "" {
					mu.Lock()
					skipped = append(skipped, res.skip)
					mu.Unlock()
					return nil // deferred-gate leaf still missing its field — not run, not marked done
				}
				mu.Lock()
				findings = append(findings, res.findings...)
				logs = append(logs, res.logs...)
				if opts.SeedFn != nil {
					candidates := sameHostOthers(leavesByHost[targetHostKey(leaf.Target)], leaf.ID)
					for _, s := range opts.SeedFn(leaf, res.findings, candidates) {
						if s.TargetLeafID == "" || s.TargetLeafID == leaf.ID {
							continue
						}
						if _, exists := seeds[s.TargetLeafID]; !exists {
							seeds[s.TargetLeafID] = s
						}
					}
				}
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
// missingRequiredFieldForLeaf is missingRequiredField with LT-91's per-leaf
// override: an endpoint-driven idor leaf carries its own EndpointTemplate on
// the PlanNode (set by registry.resolveEndpointFacts' fan-out), which
// runLeaf copies into the config just before dispatch — so the gate must
// treat that leaf as already having its required field even though baseCfg
// doesn't. Every other leaf/detector falls through to the baseCfg check
// unchanged.
func missingRequiredFieldForLeaf(leaf *agenttask.PlanNode, cfg scanner.Config) string {
	applyLeafReconFields(&cfg, leaf, nil)
	return missingRequiredField(leaf.Detector, cfg)
}

// applyLeafReconFields copies the recon-derived required-field values a
// registry endpoint-driven leaf carries (LT-91 idor EndpointTemplate, LT-94
// authbypass ProtectedPaths / ssrf SSRFParams) into any still-blank cfg
// field. An explicit flag, a baseCfg auto-fill, or a C7a seed all win. When
// notify is non-nil a line is logged for each field actually filled.
func applyLeafReconFields(cfg *scanner.Config, leaf *agenttask.PlanNode, notify func(string)) {
	if leaf.EndpointTemplate != "" && cfg.EndpointTemplate == "" {
		cfg.EndpointTemplate = leaf.EndpointTemplate
		if notify != nil {
			notify(fmt.Sprintf("idor: enumerating recon-derived endpoint %s (LT-91)", leaf.EndpointTemplate))
		}
		// LT-95: a UUID-shaped candidate carries its own real seed ID —
		// copied alongside EndpointTemplate, never independently, since it
		// only means anything paired with the template it was derived from.
		if leaf.EndpointIDIsUUID {
			cfg.IDORSeedID = leaf.EndpointSeedID
			cfg.IDOREndpointIsUUID = true
			if notify != nil {
				notify("idor: UUID-shaped endpoint — enumerating with a random-UUID baseline seeded from a real observed ID (LT-95)")
			}
		}
	}
	if len(leaf.ProtectedPaths) > 0 && len(cfg.ProtectedPaths) == 0 {
		cfg.ProtectedPaths = append([]string(nil), leaf.ProtectedPaths...)
		if notify != nil {
			notify(fmt.Sprintf("authbypass: probing %d recon-derived protected path(s) (LT-94)", len(leaf.ProtectedPaths)))
		}
	}
	if len(leaf.SSRFParams) > 0 && len(cfg.SSRFParams) == 0 {
		cfg.SSRFParams = append([]string(nil), leaf.SSRFParams...)
		if notify != nil {
			notify(fmt.Sprintf("ssrf: probing recon-derived param(s) %s (LT-94)", strings.Join(leaf.SSRFParams, ", ")))
		}
	}
	if len(leaf.SSRFBodyParams) > 0 && len(cfg.SSRFBodyParams) == 0 {
		cfg.SSRFBodyParams = append([]string(nil), leaf.SSRFBodyParams...)
		if notify != nil {
			notify(fmt.Sprintf("ssrf: probing recon-derived body param(s) %s (LT-96)", strings.Join(leaf.SSRFBodyParams, ", ")))
		}
	}
	if leaf.CouponMintPath != "" && cfg.CouponMintPath == "" && cfg.CouponApplyPath == "" {
		cfg.CouponMintPath = leaf.CouponMintPath
		cfg.CouponApplyPath = leaf.CouponApplyPath
		cfg.CouponCodeField = leaf.CouponCodeField
		cfg.CouponAmountField = leaf.CouponAmountField
		if notify != nil {
			notify(fmt.Sprintf("businesslogic: probing recon-derived coupon mint %s / apply %s (LT-135)", leaf.CouponMintPath, leaf.CouponApplyPath))
		}
	}
}

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
		if len(cfg.SSRFParams) == 0 && len(cfg.SSRFBodyParams) == 0 {
			return "no --ssrf-param given and recon found no usable query or body param candidate"
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

func runLeaf(ctx context.Context, leaf *agenttask.PlanNode, baseCfg scanner.Config, loadCorpus bool, opts ExecOptions, seedLookup func(string) (LeafSeed, bool)) executionResult {
	cfg := baseCfg
	cfg.Targets = []string{leaf.Target}
	if !loadCorpus {
		// Another leaf on this host already carries the once-per-host additive
		// template-corpus pass (see RunPlan) — this builtin-detector leaf runs
		// its own check only.
		cfg.TemplatePaths = nil
	}

	// C7a: a seed produced by an earlier same-host leaf that finished before
	// this one started. Fills a blank required field only — an explicit
	// --endpoint/--ssrf-param, a recon/I4 auto-fill, and a value from any
	// other source all win. The seed value came from a Finding this run
	// itself produced against this already-approved, in-scope host, so it
	// stays inside the approved blast radius; it is logged, never silent.
	if seedLookup != nil {
		if s, ok := seedLookup(leaf.ID); ok {
			applyLeafSeed(&cfg, s, leaf, opts)
		}
	}

	// LT-91 / LT-94: an endpoint-driven idor/authbypass/ssrf leaf carries its
	// recon-derived required field(s) on the PlanNode
	// (registry.resolveEndpointFacts). Fill any still-blank config field from
	// them — an explicit flag, a recon/I4 auto-fill on baseCfg, or a C7a seed
	// all still win. Logged, never silent; the values are recon-derived paths
	// on the already-approved host, inside the approved blast radius.
	applyLeafReconFields(&cfg, leaf, func(m string) {
		if opts.Notify != nil {
			opts.Notify(leaf.Target, m)
		}
	})

	validateOpts := scanner.ValidateOptions{
		SkipEndpointRequired:       true,
		SkipProtectedPathsRequired: true,
		SkipSSRFParamsRequired:     true,
		SkipAuthTokenRequired:      true,
	}
	// C7a deferred gate: for a seed-fillable detector whose pre-dispatch
	// missing-field check RunPlan skipped, re-check now that any seed has been
	// applied — still blank means skip (reported via executionResult.skip),
	// never a live request against an unset endpoint/param.
	if opts.SeedFn != nil && seedFillableDetector[leaf.Detector] {
		if reason := missingRequiredField(leaf.Detector, cfg); reason != "" {
			return executionResult{skip: fmt.Sprintf("%s: skipped — %s (deferred gate, no SeedFn contribution)", leaf.ID, reason)}
		}
	}

	if recognizedDetectors[leaf.Detector] {
		cfg.Detector = leaf.Detector
		// LT-137 (docs/follow-up.md, found live 2026-09-10 running the G1
		// agent eval): without this, every executed leaf ran the full synced
		// template corpus (baseCfg.TemplatePaths, unfiltered) — minutes per
		// leaf against a real target. Mirrors cmd/hackerfive/scan.go's own
		// doc15 Step 6a narrowing: an explicit cfg.Tags (baseCfg's own,
		// never widened) wins untouched; otherwise this leaf's own
		// detector-category floor is unioned onto whatever tech-based
		// "extras" baseCfg.DerivedTags already carries (tools_plan.go /
		// pkg/webui compute those once, from the whole recon tech stack).
		if len(cfg.Tags) == 0 {
			cfg.DerivedTags = unionLeafTags(registry.DetectorTemplateTags(leaf.Detector), cfg.DerivedTags)
		}
	} else {
		// A specific-template leaf, not a built-in detector — RunPlan's
		// eligibility loop only lets a leaf reach here if leaf.Detector is
		// either a recognized detector name or a real template ID/tag, so
		// anything not the former is the latter. Such a leaf always has
		// loadCorpus true (RunPlan), so TemplatePaths is baseCfg's own
		// (the same synced+bundled directories the whole plan uses) —
		// narrowing to just this one template happens by exact id: match at
		// load time (Config.TemplateID), not by pointing at a different
		// directory. Since F4 (LT-71) the engine's loadTemplates takes an
		// id:-peek fast path for a TemplateID-only narrow, so this no longer
		// pays a full ~9,500-file parse to run one named template.
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

// sortByPriorityDesc stable-sorts leaves so a higher agenttask.PlanNode
// Priority comes first (C7a dispatch ordering). Stable: leaves that share a
// priority — including the 0 default on a hand-built tree — keep their input
// order.
// unionLeafTags composes a leaf's detector-category floor with baseCfg's
// tech-based extras — order-stable, de-duplicated, lower-cased (LT-137;
// mirrors cmd/hackerfive's unionScanTags and pkg/webui's unionLaunchTags;
// each package keeps its own copy rather than a shared util for one small
// helper, same precedent those two already established).
func unionLeafTags(floor, extras []string) []string {
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

func sortByPriorityDesc(leaves []*agenttask.PlanNode) {
	sort.SliceStable(leaves, func(i, j int) bool {
		return leaves[i].Priority > leaves[j].Priority
	})
}

// sameHostOthers returns every leaf in group except the one with exceptID —
// the candidate set RunPlan hands SeedFn after a same-host leaf finishes.
func sameHostOthers(group []*agenttask.PlanNode, exceptID string) []*agenttask.PlanNode {
	out := make([]*agenttask.PlanNode, 0, len(group))
	for _, l := range group {
		if l.ID != exceptID {
			out = append(out, l)
		}
	}
	return out
}

// LeafSeed is one input a completed leaf contributes to a still-pending
// same-host leaf (C7a). applyLeafSeed fills only a blank field, so a seed
// never overrides an explicit flag or a recon/I4 auto-fill.
type LeafSeed struct {
	TargetLeafID     string   // the leaf whose Config this seed fills
	EndpointTemplate string   // idor: an {{id}}-templated path, used only if cfg.EndpointTemplate is blank
	SSRFParams       []string // ssrf: URL-valued query param names, used only if cfg.SSRFParams is empty
}

// applyLeafSeed writes a seed's values into cfg's blank fields and logs each
// one it actually applied (via opts.Notify) — a seeded value that reaches a
// live request is always visible in the run's log, never silent.
func applyLeafSeed(cfg *scanner.Config, s LeafSeed, leaf *agenttask.PlanNode, opts ExecOptions) {
	notify := func(msg string) {
		if opts.Notify != nil {
			opts.Notify(leaf.Target, msg)
		}
	}
	if s.EndpointTemplate != "" && cfg.EndpointTemplate == "" {
		cfg.EndpointTemplate = s.EndpointTemplate
		notify(fmt.Sprintf("seeded idor endpoint_template from an earlier same-host finding: %s (C7a)", s.EndpointTemplate))
	}
	if len(s.SSRFParams) > 0 && len(cfg.SSRFParams) == 0 {
		cfg.SSRFParams = append([]string(nil), s.SSRFParams...)
		notify(fmt.Sprintf("seeded ssrf params from an earlier same-host finding: %s (C7a)", strings.Join(s.SSRFParams, ", ")))
	}
}

// EndpointSeedFromFindings is planexec's one built-in SeedFn (C7a): it pulls
// URLs out of a completed leaf's findings (Finding.Target and any
// http(s)-valued Finding.Evidence entry), keeps those on the same host as
// the completed leaf, and — reusing pkg/recon's own vetted
// SuggestIDOREndpointCandidates / SuggestSSRFParamsFromRecon templating —
// hands a still-pending same-host idor leaf an {{id}}-templated
// EndpointTemplate and a still-pending ssrf leaf its URL-valued param names.
// Conservative: same host only, blank fields only (enforced in
// applyLeafSeed), never touches auth/allow-writes.
func EndpointSeedFromFindings(done *agenttask.PlanNode, findings []detectors.Finding, candidates []*agenttask.PlanNode) []LeafSeed {
	if len(findings) == 0 || len(candidates) == 0 {
		return nil
	}
	doneHost := targetHostKey(done.Target)
	var eps []recon.EndpointFact
	seen := map[string]bool{}
	addURL := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || seen[raw] {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return
		}
		if u.Scheme+"://"+u.Host != doneHost {
			return // never seed across hosts
		}
		seen[raw] = true
		eps = append(eps, recon.EndpointFact{URL: raw, Method: "GET", Source: "planexec-seed", Confidence: "low"})
	}
	for _, f := range findings {
		addURL(f.Target)
		for _, v := range f.Evidence {
			if strings.HasPrefix(strings.TrimSpace(v), "http://") || strings.HasPrefix(strings.TrimSpace(v), "https://") {
				addURL(v)
			}
		}
	}
	if len(eps) == 0 {
		return nil
	}
	rr := &recon.ReconResult{Endpoints: eps}
	idorCandidates := recon.SuggestIDOREndpointCandidates(rr)
	ssrfParams := recon.SuggestSSRFParamsFromRecon(rr)
	if len(idorCandidates) == 0 && len(ssrfParams) == 0 {
		return nil
	}

	var seeds []LeafSeed
	for _, leaf := range candidates {
		if leaf.Status != agenttask.StatusPending || targetHostKey(leaf.Target) != doneHost {
			continue // RunPlan pre-filters to same-host, but a custom caller may not
		}
		switch leaf.Detector {
		case "idor":
			if len(idorCandidates) > 0 {
				seeds = append(seeds, LeafSeed{TargetLeafID: leaf.ID, EndpointTemplate: idorCandidates[0]})
			}
		case "ssrf":
			if len(ssrfParams) > 0 {
				seeds = append(seeds, LeafSeed{TargetLeafID: leaf.ID, SSRFParams: ssrfParams})
			}
		}
	}
	return seeds
}
