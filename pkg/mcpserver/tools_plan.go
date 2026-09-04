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
}

// planOutputSchema — see Step 1's original comment (unchanged reason):
// agenttask.PlanNode is self-referential and jsonschema-go's reflection
// can't represent it.
var planOutputSchema = json.RawMessage(`{"type":"object"}`)

func addPlanTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "plan",
		Description: "Run recon against a target, resolve it to a PlanTree via the deterministic decision engine (falling back to a tiered LLM for what it can't resolve), get human approval via elicitation, then execute the approved plan and return real findings. Refuses to run without an explicit scope allow-list.",
		OutputSchema: planOutputSchema,
	}, handlePlan)
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

// isApproved reports whether resp — an entry from req.Params.InputResponses
// — represents an accepted elicitation with approve=true.
func isApproved(resp mcp.InputResponse) bool {
	er, ok := resp.(*mcp.ElicitResult)
	return ok && er.Action == "accept" && er.Content["approve"] == true
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

	depth := recon.Depth(in.Depth)
	switch depth {
	case "":
		depth = recon.DepthActive
	case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
	default:
		return nil, planOutput{}, fmt.Errorf(`depth must be "passive", "active", or "full", got %q`, in.Depth)
	}

	index, _ := templatesync.LoadIndex(defaultTemplateIndexPath) // nil index degrades to skipping template-tag matching, not a hard failure

	client := httpclient.New(httpclient.Config{
		Timeout:             defaultTimeout,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: defaultConcurrency,
	}, httpclient.WithRateLimit(ratelimit.New(defaultRateLimit)))

	r := recon.New(client, recon.WithScope(sc), recon.WithRateLimit(defaultRateLimit), recon.WithConcurrency(defaultConcurrency))
	result, err := r.Run(ctx, in.Target, depth)
	if err != nil {
		return nil, planOutput{}, err
	}

	tree, leafContexts := registry.Resolve(result, index)
	ceiling := in.SpendCeilingUSD
	if ceiling <= 0 {
		ceiling = llmfallback.PerCallDefaultSpendCeilingUSD()
	}
	tree.SpendCeilingUSD = ceiling

	fb, fbErr := llmfallback.New()

	escalations := llmfallback.ResolveTreeLeaves(ctx, fb, fbErr, tree, registry.Capabilities, index, leafContexts)

	baseCfg := buildBaseExecConfig(in, sc)
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

	if !clientSupportsElicitation(req.Session) {
		return nil, planOutput{
			Tree:             tree,
			FieldSuggestions: fieldSuggestions,
			SpendUSD:         tree.SpendSoFar(),
			Note:             "client does not support elicitation — plan returned unexecuted; re-run via an elicitation-capable client to approve and execute",
		}, nil
	}

	id := storePendingPlan(&pendingPlan{tree: tree, fieldSuggestions: fieldSuggestions, baseCfg: baseCfg, escalations: escalations})

	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"approve": &mcp.ElicitParams{
			Message:         summarizePlan(tree, fieldSuggestions, escalations),
			RequestedSchema: approveRequestSchema,
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

	out := planOutput{Tree: pending.tree, FieldSuggestions: pending.fieldSuggestions, SpendUSD: pending.tree.SpendSoFar()}
	if !isApproved(resp) {
		out.Note = "plan not approved — returned unexecuted"
		return nil, out, nil
	}

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
	})
	out.Approved = true
	out.Findings = findings
	out.Logs = logs
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
func resolveFieldSuggestions(ctx context.Context, result *recon.ReconResult, fb *llmfallback.Client, fbErr error, tree *agenttask.PlanTree, baseCfg *scanner.Config, escalations *[]string) []agenttask.FieldSuggestion {
	var out []agenttask.FieldSuggestion

	idorCandidates := recon.SuggestIDOREndpointCandidates(result)
	if len(idorCandidates) == 1 {
		baseCfg.EndpointTemplate = idorCandidates[0]
		out = append(out, agenttask.FieldSuggestion{Detector: "idor", Field: "endpoint_template", SuggestedValue: idorCandidates[0], Rationale: "single recon-derived candidate, auto-filled"})
	} else {
		fs := resolveOneFieldMiss(ctx, fb, fbErr, tree, "idor", "endpoint_template", idorCandidates, escalations)
		if fs != nil {
			out = append(out, *fs)
		}
	}

	protected, login, logout := recon.SuggestAuthBypassPathsFromRecon(result)
	if len(protected) == 1 {
		baseCfg.ProtectedPaths = protected
		out = append(out, agenttask.FieldSuggestion{Detector: "authbypass", Field: "protected_paths", SuggestedValue: protected[0], Rationale: "single recon-derived candidate, auto-filled"})
	} else if len(protected) == 0 {
		if fs := resolveOneFieldMiss(ctx, fb, fbErr, tree, "authbypass", "protected_paths", protected, escalations); fs != nil {
			out = append(out, *fs)
		}
	} else {
		baseCfg.ProtectedPaths = protected
		out = append(out, agenttask.FieldSuggestion{Detector: "authbypass", Field: "protected_paths", Candidates: protected, Rationale: "multiple recon-derived candidates — all usable directly, no ambiguity to resolve"})
	}
	if len(login) > 0 {
		baseCfg.LoginPaths = login
		out = append(out, agenttask.FieldSuggestion{Detector: "authbypass", Field: "login_paths", Candidates: login, Rationale: "recon-derived, auto-fillable"})
	}
	if len(logout) > 0 {
		baseCfg.LogoutPaths = logout
		out = append(out, agenttask.FieldSuggestion{Detector: "authbypass", Field: "logout_paths", Candidates: logout, Rationale: "recon-derived, auto-fillable"})
	}

	if ssrfParams := recon.SuggestSSRFParamsFromRecon(result); len(ssrfParams) > 0 {
		baseCfg.SSRFParams = ssrfParams
		out = append(out, agenttask.FieldSuggestion{Detector: "ssrf", Field: "ssrf_params", Candidates: ssrfParams, Rationale: "every recon-derived candidate is directly usable, no ambiguity to resolve"})
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

func summarizePlan(tree *agenttask.PlanTree, fieldSuggestions []agenttask.FieldSuggestion, escalations []string) string {
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
	if len(escalations) > 0 {
		b.WriteString(" Escalations: " + strings.Join(escalations, "; "))
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
