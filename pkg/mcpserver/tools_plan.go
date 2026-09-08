package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/fieldsuggest"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/planexec"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// planInput extends Step 1's minimal shape (target/scope/depth) with the
// same optional credential/behavior fields scanInput already exposes
// (tools_scan.go) — plan's own executor (Phase 6 Step 2) needs exactly the
// same inputs a scan call does, since executing an approved leaf is a scan
// call under the hood.
type planInput struct {
	Target          string            `json:"target" jsonschema:"target URL/domain to run recon against, then plan"`
	Scope           []string          `json:"scope" jsonschema:"required allow-list (domain, *.domain, or CIDR entries); the call is refused if empty"`
	Depth           string            `json:"depth,omitempty" jsonschema:"one of passive, active, full (default: active — Wave 2's httpx tech signals are what the decision engine matches against)"`
	AuthToken       string            `json:"auth_token,omitempty" jsonschema:"owner-account auth token for any idor/authbypass/businesslogic leaf; also read from HACKERFIVE_AUTH_TOKEN if unset"`
	OtherAuthToken  string            `json:"other_auth_token,omitempty" jsonschema:"second-account auth token, for idor's baseline comparison"`
	AllowWrites     bool              `json:"allow_writes,omitempty" jsonschema:"required for any businesslogic leaf's mutating checks; skipped with a warning otherwise"`
	ExtraHeaders    map[string]string `json:"extra_headers,omitempty"`
	SpendCeilingUSD float64           `json:"spend_ceiling_usd,omitempty" jsonschema:"hard cap on cumulative LLM-fallback (I4) cost for resolving and approving this plan; default 1.00 if unset or <=0"`
	Reason          string            `json:"reason,omitempty" jsonschema:"optional — the coordinator's stated reason for this call; recorded verbatim in the session.log, advisory only"`
}

// planOutput. Approved is true only once a human has accepted via
// elicitation AND execution actually ran — a declined or unsupported-client
// call still returns Tree/FieldSuggestions for inspection, matching Step
// 1's original read-only contract for that case.
type planOutput struct {
	Tree             *agenttask.PlanTree         `json:"tree"`
	FieldSuggestions []agenttask.FieldSuggestion `json:"field_suggestions,omitempty"`
	Approved         bool                        `json:"approved"`
	Note             string                      `json:"note,omitempty"`
	Findings         []detectors.Finding         `json:"findings,omitempty"`
	Logs             []string                    `json:"logs,omitempty"`
	SkippedLeaves    []string                    `json:"skipped_leaves,omitempty"`
	SpendUSD         float64                     `json:"spend_usd,omitempty"`
	// OutOfScope are hosts recon discovered outside the approved scope (B4,
	// doc15 Step 3). They are never scanned; the plan tool surfaces them so a
	// human sees what recon turned up, and requires an explicit
	// acknowledge_out_of_scope before execution when non-empty.
	OutOfScope []string `json:"out_of_scope,omitempty"`
}

// planOutputSchema — see Step 1's original comment (unchanged reason):
// agenttask.PlanNode is self-referential and jsonschema-go's reflection
// can't represent it.
var planOutputSchema = json.RawMessage(`{"type":"object"}`)

func addPlanTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:         "plan",
		Description:  "Run recon against a target, resolve it to a PlanTree via the deterministic decision engine (falling back to a tiered LLM for what it can't resolve), get human approval via elicitation, then execute the approved plan and return real findings. Refuses to run without an explicit scope allow-list.",
		OutputSchema: planOutputSchema,
	}, recordingPlan)
}

// recordingPlan wraps handlePlan with a session.log entry (doc15 Step 5 C1).
// Both SEP-2322 rounds are recorded: round 1 (the actual planning) and round
// 2 (the elicitation retry, where execution happens) each get their own
// entry, so the log shows the approval as a distinct event, not a gap.
func recordingPlan(ctx context.Context, req *mcp.CallToolRequest, in planInput) (res *mcp.CallToolResult, out planOutput, err error) {
	finish := sessionLog.Begin("plan", in.Reason, withElicitationGrant(planParamsSummary(in), req))
	res, out, err = handlePlan(ctx, req, in)
	summary := planResultSummary(out)
	if res != nil && len(res.InputRequests) > 0 {
		// Round 1: the SDK suppresses Out when InputRequests is set, so out is
		// zero here even though a tree was built — say so plainly.
		summary = "plan proposed — awaiting elicitation approval"
	}
	finish(summary, err)
	return res, out, err
}

// approveRequestSchema is the flat elicitation schema every gated tool in
// this package (plan, findings.triage) asks for — a single whole-response
// approve/reject, per doc15 Step 2's resolved design (ElicitParams.
// RequestedSchema only supports flat, non-nested top-level properties, so
// per-leaf approval isn't representable in one round trip — that stays
// Step 4's Web UI job).
var approveRequestSchema = &jsonschema.Schema{
	Type:       "object",
	Properties: map[string]*jsonschema.Schema{"approve": {Type: "boolean", Description: "Approve for execution"}},
	Required:   []string{"approve"},
}

// buildApprovalSchema is approveRequestSchema plus whichever explicit
// acknowledgements this particular plan needs the human to make separately
// from the single approve field — a hallucinated "yes" to one boolean
// shouldn't silently wave the others through:
//
//   - acknowledge_out_of_scope (B4, doc15 Step 3): the plan's own recon
//     discovered hosts outside the approved scope; the human must confirm
//     they have seen them and that they will NOT be scanned.
//   - acknowledge_writes (B2, doc16 Phase 7 Step 2): the plan carries a
//     businesslogic leaf AND allow_writes was requested; the human must
//     separately attest that state-changing requests to the target are
//     authorized before any mutating check runs.
func buildApprovalSchema(requireScopeAck, requireWritesAck bool) *jsonschema.Schema {
	props := map[string]*jsonschema.Schema{
		"approve": {Type: "boolean", Description: "Approve for execution"},
	}
	required := []string{"approve"}
	if requireScopeAck {
		props["acknowledge_out_of_scope"] = &jsonschema.Schema{Type: "boolean", Description: "Confirm you have seen the out-of-scope hosts recon discovered; they will NOT be scanned"}
		required = append(required, "acknowledge_out_of_scope")
	}
	if requireWritesAck {
		props["acknowledge_writes"] = &jsonschema.Schema{Type: "boolean", Description: "Confirm that sending state-changing (mutating) businesslogic requests — coupon self-mint/apply, apply-race — to this target is explicitly authorized and in scope"}
		required = append(required, "acknowledge_writes")
	}
	return &jsonschema.Schema{Type: "object", Properties: props, Required: required}
}

// isApproved reports whether resp — an entry from req.Params.InputResponses
// — represents an accepted elicitation with approve=true. Used by
// findings.triage (which has no scope-ack concern); the plan tool uses
// isPlanApproved instead.
func isApproved(resp mcp.InputResponse) bool {
	er, ok := resp.(*mcp.ElicitResult)
	return ok && er.Action == "accept" && er.Content["approve"] == true
}

// ackGiven reports whether resp is an accepted elicitation whose named
// boolean acknowledgement field is true — used to tell "approved but forgot
// an ack" apart from "declined outright" when composing the round-2 note.
func ackGiven(resp mcp.InputResponse, key string) bool {
	er, ok := resp.(*mcp.ElicitResult)
	return ok && er.Content[key] == true
}

// isPlanApproved is isApproved plus the per-plan acknowledgement gates: when
// requireScopeAck is true (B4 — recon found out-of-scope hosts)
// acknowledge_out_of_scope must also be true, and when requireWritesAck is
// true (B2 — a businesslogic leaf with allow_writes requested)
// acknowledge_writes must also be true, for the plan to execute.
func isPlanApproved(resp mcp.InputResponse, requireScopeAck, requireWritesAck bool) bool {
	if !isApproved(resp) {
		return false
	}
	er := resp.(*mcp.ElicitResult) // isApproved already type-asserted
	if requireScopeAck && er.Content["acknowledge_out_of_scope"] != true {
		return false
	}
	if requireWritesAck && er.Content["acknowledge_writes"] != true {
		return false
	}
	return true
}

// planHasBusinessLogicLeaf reports whether any leaf of tree carries the
// businesslogic detector — the gate (with allow_writes requested) for B2's
// acknowledge_writes attestation. A plan with no businesslogic leaf never
// runs a mutating check regardless of allow_writes, so it needs no
// attestation.
func planHasBusinessLogicLeaf(tree *agenttask.PlanTree) bool {
	if tree == nil {
		return false
	}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Detector == "businesslogic" {
			return true
		}
	}
	return false
}

// handlePlan implements the plan tool across SEP-2322's two-round-trip
// shape (real finding, 2026-09-02 — see planstate.go's doc comment): round
// 1 (no InputResponses yet) runs recon/I4/field-resolution and returns an
// InputRequests-carrying result with no structured output — the SDK's own
// AddTool wrapper suppresses Out serialization whenever InputRequests is
// set (confirmed by reading server.go's AddTool wrapper), so returning a
// zero planOutput here is correct, not a placeholder. Round 2 (the
// client's automatic retry, InputResponses["approve"] populated) looks up
// the cached pendingPlan by RequestState and finishes the job.
func handlePlan(ctx context.Context, req *mcp.CallToolRequest, in planInput) (*mcp.CallToolResult, planOutput, error) {
	if resp, ok := req.Params.InputResponses["approve"]; ok {
		return handlePlanApproval(ctx, req, resp)
	}

	sc, err := requireScope(in.Scope)
	if err != nil {
		return nil, planOutput{}, err
	}
	// D2 program-policy pre-flight (doc15 Step 3): block before spending recon
	// time on an operator-declared automated_scanning: disallowed target. No
	// MCP override. The security.txt/robots.txt advisory signals are folded in
	// after recon below.
	preWarns, err := preflightBlock([]string{in.Target})
	if err != nil {
		return nil, planOutput{}, err
	}
	reqHeaders, err := policyRequestHeaders() // LT-36
	if err != nil {
		return nil, planOutput{}, err
	}

	depth := recon.Depth(in.Depth)
	switch depth {
	case "":
		depth = recon.DepthActive
	case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
	default:
		return nil, planOutput{}, fmt.Errorf(`depth must be "passive", "active", or "full", got %q`, in.Depth)
	}

	index, _ := templatesync.LoadIndex(defaultTemplateIndexPath) // nil index degrades to skipping template-tag matching, not a hard failure

	// recon.ClientConfig forces InsecureSkipVerify true (LT-4, docs/follow-up.md)
	// — matches katana/httpx's own hardcoded TLS posture; this client is
	// never shared with scan's own detector requests.
	client := httpclient.New(recon.ClientConfig(httpclient.Config{
		Timeout:             defaultTimeout,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: defaultConcurrency,
	}), httpclient.WithRateLimit(ratelimit.New(defaultRateLimit)))

	r := recon.New(client, recon.WithScope(sc), recon.WithRateLimit(defaultRateLimit), recon.WithConcurrency(defaultConcurrency), recon.WithHeaders(reqHeaders))
	result, err := r.Run(ctx, in.Target, depth)
	if err != nil {
		return nil, planOutput{}, err
	}
	preflightWarnings := append(preWarns, reconSignalWarnings(result)...)
	for _, w := range preflightWarnings {
		result.Warnings = append(result.Warnings, "preflight: "+w)
	}

	tree, leafContexts := registry.Resolve(result, index)
	ceiling := in.SpendCeilingUSD
	if ceiling <= 0 {
		ceiling = llmfallback.PerCallDefaultSpendCeilingUSD()
	}
	tree.SpendCeilingUSD = ceiling

	fb, fbErr := llmfallback.New()

	escalations := llmfallback.ResolveTreeLeaves(ctx, fb, fbErr, tree, registry.Capabilities, index, leafContexts)
	// C7b (doc16 Phase 7 Step 3): plausibility pass over the confident leaves,
	// folded into the escalation list the elicitation summary shows — the
	// human sees any demoted/dropped leaf before approving. Ceiling-respecting
	// and a no-op when no LLM tier is configured (fb nil).
	escalations = append(escalations, llmfallback.VetoImplausibleLeaves(ctx, fb, fbErr, tree)...)

	baseCfg := buildBaseExecConfig(in, sc)
	// D6 (docs/16-implementation-plan-ph7.md Step 4): carry recon's
	// uniform-response-wall verdict into execution so RunPlan's per-leaf
	// scans skip the template corpus for a walled host (LT-59).
	if result.UniformResponse != nil {
		baseCfg.UniformWallHosts = map[string]string{result.UniformResponse.Host: result.UniformResponse.Kind}
	}
	// resolveFieldSuggestions applies only the deterministic (single- or
	// multi-candidate, no-ambiguity) auto-fills directly to baseCfg — the
	// same thing pkg/webui's fillReconFields already does unconditionally,
	// no human review needed since there's nothing to choose between. An
	// LLM-derived suggestion (idor's genuine 0/multiple-candidate miss,
	// resolved via ResolveField) is deliberately NOT applied here: it's
	// surfaced in FieldSuggestions for inspection, but a leaf that needs it
	// and doesn't have it is skipped at execution time (RunPlan), not run
	// with an unreviewed guess against a live target.
	fieldSuggestions := resolveFieldSuggestions(ctx, result, fb, fbErr, tree, &baseCfg, &escalations)

	var preflightLogs []string
	for _, w := range preflightWarnings {
		preflightLogs = append(preflightLogs, "warn: preflight: "+w)
	}

	// B4 (doc15 Step 3): recon found hosts outside the approved scope. They are
	// never scanned (registry.Resolve builds leaves only from in-scope hosts),
	// but the human must see them and separately acknowledge before execution.
	outOfScope := result.OutOfScope
	requireScopeAck := len(outOfScope) > 0
	// B2 (doc16 Phase 7 Step 2): allow_writes was requested AND the resolved
	// tree actually carries a businesslogic leaf — the human must attest to
	// the mutating checks separately from the plan approval itself.
	requireWritesAck := in.AllowWrites && planHasBusinessLogicLeaf(tree)

	if !clientSupportsElicitation(req.Session) {
		return nil, planOutput{
			Tree:             tree,
			FieldSuggestions: fieldSuggestions,
			SpendUSD:         tree.SpendSoFar(),
			Logs:             preflightLogs,
			OutOfScope:       outOfScope,
			Note:             "client does not support elicitation — plan returned unexecuted; re-run via an elicitation-capable client to approve and execute",
		}, nil
	}

	id := storePendingPlan(&pendingPlan{tree: tree, fieldSuggestions: fieldSuggestions, baseCfg: baseCfg, escalations: escalations, preflightLogs: preflightLogs, outOfScope: outOfScope})

	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"approve": &mcp.ElicitParams{
			Message:         summarizePlan(tree, fieldSuggestions, escalations, preflightWarnings, outOfScope, requireWritesAck),
			RequestedSchema: buildApprovalSchema(requireScopeAck, requireWritesAck),
		}},
		RequestState: id,
	}, planOutput{}, nil
}

// handlePlanApproval is round 2: id came back as req.Params.RequestState,
// echoed by the client per SEP-2322's own contract.
func handlePlanApproval(ctx context.Context, req *mcp.CallToolRequest, resp mcp.InputResponse) (*mcp.CallToolResult, planOutput, error) {
	pending, ok := takePendingPlan(req.Params.RequestState)
	if !ok {
		return nil, planOutput{}, fmt.Errorf("plan request state %q not found or expired (pending plans are cached for %s) — re-run plan from the start", req.Params.RequestState, pendingPlanTTL)
	}

	out := planOutput{Tree: pending.tree, FieldSuggestions: pending.fieldSuggestions, SpendUSD: pending.tree.SpendSoFar(), Logs: pending.preflightLogs, OutOfScope: pending.outOfScope}
	requireScopeAck := len(pending.outOfScope) > 0
	// B2: recompute rather than cache on pendingPlan — baseCfg.AllowWrites
	// records that writes were requested, and the tree tells us whether a
	// businesslogic leaf exists to run them.
	requireWritesAck := pending.baseCfg.AllowWrites && planHasBusinessLogicLeaf(pending.tree)
	if !isPlanApproved(resp, requireScopeAck, requireWritesAck) {
		switch {
		case isApproved(resp) && requireScopeAck && !ackGiven(resp, "acknowledge_out_of_scope"):
			out.Note = "plan not executed — approve was given but the out-of-scope acknowledgement (acknowledge_out_of_scope) was not; re-run and confirm all required acknowledgements"
		case isApproved(resp) && requireWritesAck && !ackGiven(resp, "acknowledge_writes"):
			out.Note = "plan not executed — approve was given but the write acknowledgement (acknowledge_writes) was not; re-run and set acknowledge_writes=true, or drop allow_writes to run the plan without the businesslogic mutating checks"
		default:
			out.Note = "plan not approved — returned unexecuted"
		}
		return nil, out, nil
	}
	// From here the plan is fully approved. AllowWrites is honored only when
	// the attestation was actually required and given (requireWritesAck true ⇒
	// acknowledge_writes was true, checked above); a plan that requested
	// allow_writes but has no businesslogic leaf leaves it off — nothing would
	// use it.
	pending.baseCfg.AllowWrites = requireWritesAck

	token := req.Params.GetProgressToken()
	// Reloaded here rather than cached on pendingPlan — cheap (a JSON file
	// read), and keeps that short-lived struct's shape minimal. A template
	// added/removed between round 1 and round 2 (a human re-syncing mid-
	// approval) is vanishingly unlikely to matter in practice, and either
	// way this is the freshest index available at dispatch time.
	templateIndex, _ := templatesync.LoadIndex(defaultTemplateIndexPath)
	notify := func(target, message string) {
		if token == nil {
			return
		}
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Message:       target + ": " + message,
		})
	}
	findings, logs, skipped, err := planexec.RunPlan(ctx, pending.tree, pending.baseCfg, templateIndex, planexec.ExecOptions{
		Notify:         notify,
		DetConcurrency: defaultConcurrency,
		LLMConcurrency: llmAssistedExecConcurrency,
		// C7a: let an earlier same-host leaf's finding seed a later idor/ssrf
		// leaf's blank endpoint/param (blank fields only, same host only,
		// every applied seed logged via Notify).
		SeedFn: planexec.EndpointSeedFromFindings,
		// B4 scope-creep gate (doc15 Step 3): the dormant executor trigger
		// point for a future mid-scan re-recon leaf. No leaf runs recon today,
		// so this only fires if the approved tree somehow carries a leaf
		// outside the approved scope — halt and make the operator re-plan.
		OnOutOfScope: func(hosts []string) error {
			return fmt.Errorf("execution halted (B4 scope-creep gate): the approved plan contains leaf target(s) outside the approved scope: %s — re-run plan to review", strings.Join(hosts, ", "))
		},
	})
	out.Approved = true
	out.Findings = findings
	out.Logs = append(pending.preflightLogs, logs...)
	out.SkippedLeaves = skipped
	out.SpendUSD = pending.tree.SpendSoFar()
	if err != nil {
		return nil, out, err
	}
	return nil, out, nil
}

// resolveFieldSuggestions wires doc14 Step 7's idor/ssrf/authbypass
// recon-derived field suggesters into the plan pipeline for the first time
// (they previously only ran from pkg/webui's Launch page) — a single
// candidate auto-fills deterministically with no LLM call and no suggestion
// surfaced (matching the CLI/webui behavior exactly); a genuine miss (idor's
// 0-or-multiple case; authbypass's 0-candidate ProtectedPaths case) is I4's
// second caller. ssrf/authbypass's login/logout never have a miss case (see
// pkg/recon/suggest.go) so they only ever auto-fill or stay empty.
//
// Every per-detector block is gated on the plan tree actually carrying a
// leaf for that detector. Without this gate, a misconfig-only plan (the
// common case — WebGoat/DVWA/most targets) still fired an I4 field-miss
// call for `idor`/`authbypass` on every `plan` invocation, since a target
// with no idor endpoints trivially hits the 0-candidate branch — a standing
// paid LLM call the DoD says I4 must never be ("fires only on a confirmed
// decision-engine miss — never as a standing parallel path"). A field
// suggestion only ever fills a field on an already-emitted leaf, so no leaf
// for the detector means nothing to fill.
func resolveFieldSuggestions(ctx context.Context, result *recon.ReconResult, fb *llmfallback.Client, fbErr error, tree *agenttask.PlanTree, baseCfg *scanner.Config, escalations *[]string) []agenttask.FieldSuggestion {
	// The deterministic (no-LLM) auto-fills now live in pkg/fieldsuggest so
	// cmd/hackerfive's plan/scan reuse the exact same branching (doc16 Phase
	// 7 Step 1 A6). This package keeps ownership of what fieldsuggest
	// deliberately doesn't do: applying a value to baseCfg, and resolving a
	// genuine miss via I4 (resolveOneFieldMiss). The planLeafDetectors gate
	// is passed through as fieldsuggest's `want` set — a want-excluded
	// detector yields neither a suggestion nor a Miss, so I4 still only ever
	// fires on a confirmed decision-engine miss.
	sugs, misses := fieldsuggest.Deterministic(result, planLeafDetectors(tree))

	out := make([]agenttask.FieldSuggestion, 0, len(sugs)+len(misses))
	for _, s := range sugs {
		applyFieldSuggestion(baseCfg, s)
		out = append(out, s)
	}
	for _, m := range misses {
		// LT-91: an idor endpoint_template "miss" (>1 recon candidate, no way
		// to pick one) is no longer a miss when the decision engine already
		// fanned out a per-candidate idor leaf for each — every candidate is
		// being enumerated on its own leaf, so there is nothing for a human or
		// I4 to resolve. Suppress the escalation rather than raise a
		// misleading "pick one and re-run".
		if m.Detector == "idor" && m.Field == "endpoint_template" && treeHasEndpointDrivenIdorLeaf(tree) {
			continue
		}
		if fs := resolveOneFieldMiss(ctx, fb, fbErr, tree, m.Detector, m.Field, m.Candidates, escalations); fs != nil {
			out = append(out, *fs)
		}
	}
	return out
}

// treeHasEndpointDrivenIdorLeaf reports whether tree carries at least one
// idor leaf that already has its own EndpointTemplate (registry's LT-91
// per-candidate fan-out) — meaning idor's endpoint field needs no further
// resolution.
func treeHasEndpointDrivenIdorLeaf(tree *agenttask.PlanTree) bool {
	if tree == nil {
		return false
	}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Detector == "idor" && leaf.EndpointTemplate != "" {
			return true
		}
	}
	return false
}

// applyFieldSuggestion writes a deterministic (non-LLM) recon-derived field
// value into cfg. Only fieldsuggest.Deterministic's own suggestions reach
// here — an LLM-resolved miss is surfaced in planOutput for inspection but
// never auto-injected into execution (see buildBaseExecConfig's doc comment).
func applyFieldSuggestion(cfg *scanner.Config, s agenttask.FieldSuggestion) {
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

// planLeafDetectors is the set of detector names the tree's leaves actually
// carry — the gate for whether a field suggestion (and its possible I4
// call) has any leaf to apply to.
func planLeafDetectors(tree *agenttask.PlanTree) map[string]bool {
	out := map[string]bool{}
	if tree == nil {
		return out
	}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Detector != "" {
			out[leaf.Detector] = true
		}
	}
	return out
}

// resolveOneFieldMiss handles idor's 0-or-multiple-candidate case (the only
// genuine I4 field-suggestion miss — see resolveFieldSuggestions) via the
// local-tier-only, low-stakes treatment ResolveField itself implements.
func resolveOneFieldMiss(ctx context.Context, fb *llmfallback.Client, fbErr error, tree *agenttask.PlanTree, detector, field string, candidates []string, escalations *[]string) *agenttask.FieldSuggestion {
	decision, cost := llmfallback.ResolveFieldMiss(ctx, fb, fbErr, detector, field, candidates)
	tree.AddSpend(cost)
	if decision.EscalateToHuman != "" {
		*escalations = append(*escalations, fmt.Sprintf("%s.%s: %s", detector, field, decision.EscalateToHuman))
		return &agenttask.FieldSuggestion{Detector: detector, Field: field, Candidates: candidates, EscalateToHuman: decision.EscalateToHuman}
	}
	return &agenttask.FieldSuggestion{Detector: detector, Field: field, SuggestedValue: decision.SuggestedValue, Rationale: decision.Rationale, Candidates: candidates}
}

func summarizePlan(tree *agenttask.PlanTree, fieldSuggestions []agenttask.FieldSuggestion, escalations, preflightWarnings, outOfScope []string, requireWritesAck bool) string {
	total, unresolved := 0, 0
	for _, leaf := range agenttask.Leaves(tree.Root) {
		total++
		if leaf.Status == agenttask.StatusUnresolved {
			unresolved++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Plan for %s: %d leaves (%d still unresolved), %d field suggestion(s), spend so far $%.4f (ceiling $%.2f).",
		tree.Root.Target, total, unresolved, len(fieldSuggestions), tree.SpendSoFar(), tree.SpendCeilingUSD)
	if len(preflightWarnings) > 0 {
		b.WriteString(" Pre-flight: " + strings.Join(preflightWarnings, "; "))
	}
	if len(escalations) > 0 {
		b.WriteString(" Escalations: " + strings.Join(escalations, "; "))
	}
	if len(outOfScope) > 0 {
		fmt.Fprintf(&b, " Out-of-scope hosts recon found (they will NOT be scanned): %s — set acknowledge_out_of_scope=true to proceed.", strings.Join(outOfScope, ", "))
	}
	if requireWritesAck {
		b.WriteString(" This plan includes state-changing (mutating) businesslogic checks (coupon self-mint/apply, apply-race) because allow_writes was requested — set acknowledge_writes=true to authorize them, or they will be skipped.")
	}
	b.WriteString(" Approve to execute against the live target?")
	return b.String()
}

// buildBaseExecConfig builds the scanner.Config template RunPlan clones per
// leaf (Targets/Detector left blank — the executor fills those in
// runLeaf). A resolved FieldSuggestion is visible in planOutput for a
// human/agent to inspect but is deliberately not auto-injected into
// execution here: matching Step 2's approval-gate framing, an idor
// EndpointTemplate or authbypass ProtectedPaths a human hasn't looked at is
// exactly the shape that should be sanity-checked (via a follow-up scan
// call, or a future Step) before it's used unauthenticated against a live
// target, not silently wired straight from an LLM suggestion into a real
// request.
func buildBaseExecConfig(in planInput, sc *scope.Scope) scanner.Config {
	authToken := in.AuthToken
	if authToken == "" {
		authToken = os.Getenv("HACKERFIVE_AUTH_TOKEN")
	}
	return scanner.Config{
		TemplatePaths:  defaultTemplateDirs(),
		Concurrency:    defaultConcurrency,
		RateLimit:      defaultRateLimit,
		Timeout:        defaultTimeout,
		OutputFormat:   "json",
		AuthToken:      authToken,
		OtherAuthToken: in.OtherAuthToken,
		AllowWrites:    in.AllowWrites,
		ExtraHeaders:   in.ExtraHeaders,
		Scope:          sc,
	}
}
