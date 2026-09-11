package mcpserver

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/reporter"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// scanInput is the scan tool's schema. Scope is required (D3, doc15 Step
// 1) — a call with no entries is refused by requireScope before an Engine
// is ever constructed, never a silent CLI-style warning.
type scanInput struct {
	Targets          []string                   `json:"targets" jsonschema:"target URLs to scan"`
	Scope            []string                   `json:"scope" jsonschema:"required allow-list (domain, *.domain, or CIDR entries) every target must fall within; the call is refused if empty"`
	Detector         string                     `json:"detector" jsonschema:"one of idor, misconfig, authbypass, ssrf, businesslogic, netservice (netservice targets a \"tcp://host:port\" leaf, not an ordinary URL — see the scan tool's own targets field)"`
	Tags             []string                   `json:"tags,omitempty" jsonschema:"only fire loaded templates carrying at least one of these tags (OR match); empty means no filtering"`
	EndpointTemplate string                     `json:"endpoint_template,omitempty" jsonschema:"required for detector=idor, e.g. /api/report?id={{id}}"`
	ProtectedPaths   []string                   `json:"protected_paths,omitempty" jsonschema:"required for detector=authbypass"`
	AuthToken        string                     `json:"auth_token,omitempty" jsonschema:"owner-account auth token; also read from HACKERFIVE_AUTH_TOKEN if unset"`
	OtherAuthToken   string                     `json:"other_auth_token,omitempty" jsonschema:"second-account auth token, for idor's baseline comparison"`
	AllowWrites      bool                       `json:"allow_writes,omitempty" jsonschema:"REQUESTS detector=businesslogic's mutating checks (coupon self-mint/apply, apply-race); honored only after a human attests via an elicitation round trip (B2) — a bare true here never runs writes on its own, and the mutating checks are skipped with a warning when unattested"`
	ExtraHeaders     map[string]string          `json:"extra_headers,omitempty"`
	TechStack        []recon.TechFact           `json:"tech_stack,omitempty" jsonschema:"optional — a prior recon tool call's result.tech_stack; adds this stack's product-specific template tags on top of the detector-category floor (LT-16/LT-17, doc15 Step 6a)"`
	UniformResponse  *recon.UniformResponseFact `json:"uniform_response,omitempty" jsonschema:"optional — a prior recon tool call's result.uniform_response; when set, the per-target template corpus is skipped for that host (it answers every request with one block/catch-all page) and one honest finding is emitted instead (D6, LT-59)"`
	AllTemplates     bool                       `json:"all_templates,omitempty" jsonschema:"load the full ~9.5k synced corpus, bypassing the default per-detector template scoping (doc15 Step 6a); no effect when tags is set"`
	Reason           string                     `json:"reason,omitempty" jsonschema:"optional — the coordinator's stated reason for this call; recorded verbatim in the session.log, advisory only"`
}

// scanOutput is the scan tool's result: every Finding the run produced,
// plus the same warning/error log lines a CLI run prints to stderr —
// nothing here bypasses the deterministic matcher/extractor engine
// (Decision 2); the agent selects targets/detector, it never crafts a raw
// request.
type scanOutput struct {
	Findings []detectors.Finding `json:"findings"`
	Logs     []string            `json:"logs,omitempty"`
}

// attestWritesSchema is the scan tool's B2 elicitation schema (doc16 Phase 7
// Step 2): a detector=businesslogic call that set allow_writes must clear a
// dedicated attestation round trip before any mutating check runs. Two
// separate booleans, both required — a hallucinated "yes" to one field
// shouldn't wave the other through — mirroring the plan tool's
// approveWithScopeAckSchema shape exactly.
var attestWritesSchema = &jsonschema.Schema{
	Type: "object",
	Properties: map[string]*jsonschema.Schema{
		"approve":            {Type: "boolean", Description: "Approve this scan for execution"},
		"acknowledge_writes": {Type: "boolean", Description: "Confirm that sending state-changing (mutating) businesslogic requests — coupon self-mint/apply, apply-race — to this target is explicitly authorized and in scope"},
	},
	Required: []string{"approve", "acknowledge_writes"},
}

// isWritesAttested reports whether resp is an accepted elicitation with BOTH
// approve=true and acknowledge_writes=true — the only response that lets the
// scan tool set scanner.Config.AllowWrites. Same construction as the plan
// tool's isPlanApproved: the grant comes from a round trip the agent does
// not control the content of, so no agent can set AllowWrites for its own
// call "in the same breath it decided it wanted to" (doc16 Step 2 B2).
func isWritesAttested(resp mcp.InputResponse) bool {
	er, ok := resp.(*mcp.ElicitResult)
	return ok && er.Action == "accept" && er.Content["approve"] == true && er.Content["acknowledge_writes"] == true
}

// writesRequested reports whether in is the one shape B2's attestation gate
// applies to: detector=businesslogic AND allow_writes set. Every other scan
// runs single-round exactly as before.
func writesRequested(in scanInput) bool {
	return in.AllowWrites && in.Detector == "businesslogic"
}

func addScanTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "scan",
		Description: "Run a HackerFive detector (plus the loaded template corpus) against one or more targets. Refuses to run without an explicit scope allow-list. A detector=businesslogic call with allow_writes set must clear a human attestation (elicitation) round trip before any mutating check runs.",
	}, recordingScan)
}

// recordingScan wraps the scan handler with a session.log entry (doc15 Step
// 5 C1), mirroring recordingPlan/recordingFindingsTriage. Round 1 of a B2
// attestation exchange (InputRequests set, Out suppressed by the SDK) is
// logged as a distinct "awaiting" event, not a gap.
func recordingScan(ctx context.Context, req *mcp.CallToolRequest, in scanInput) (res *mcp.CallToolResult, out scanOutput, err error) {
	finish := sessionLog.Begin("scan", in.Reason, withElicitationGrant(scanParamsSummary(in), req))
	res, out, err = handleScan(ctx, req, in)
	summary := scanResultSummary(out)
	if res != nil && len(res.InputRequests) > 0 {
		summary = "scan proposed — awaiting allow_writes attestation (B2)"
	}
	finish(summary, err)
	return res, out, err
}

// handleScan routes B2's two-round-trip attestation for a writes-capable
// businesslogic scan (doc16 Phase 7 Step 2) and otherwise runs the scan
// single-round as before. Round 2 (the client's automatic retry, an
// "approve" response present) looks up the cached scanInput by RequestState
// and runs it with AllowWrites set only if the human attested.
func handleScan(ctx context.Context, req *mcp.CallToolRequest, in scanInput) (*mcp.CallToolResult, scanOutput, error) {
	if resp, ok := req.Params.InputResponses["approve"]; ok {
		pending, ok := takePendingScan(req.Params.RequestState)
		if !ok {
			return nil, scanOutput{}, fmt.Errorf("scan request state %q not found or expired (pending scans are cached for %s) — re-run scan from the start", req.Params.RequestState, pendingPlanTTL)
		}
		return runScan(ctx, req, pending.in, isWritesAttested(resp))
	}

	if !writesRequested(in) {
		return runScan(ctx, req, in, false)
	}

	// A writes-capable businesslogic scan: the human must attest before any
	// mutating request. Without an elicitation-capable client there is no way
	// to obtain that attestation, so the scan still runs — read-only, mutating
	// checks skipped — with a log line saying why (matches the plan tool's
	// "returned unexecuted" degrade posture: never an error, never a silent
	// write).
	if !clientSupportsElicitation(req.Session) {
		return runScan(ctx, req, in, false)
	}

	id := storePendingScan(&pendingScan{in: in})
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"approve": &mcp.ElicitParams{
			Message:         writesAttestMessage(in),
			RequestedSchema: attestWritesSchema,
		}},
		RequestState: id,
	}, scanOutput{}, nil
}

func writesAttestMessage(in scanInput) string {
	return fmt.Sprintf(
		"detector=businesslogic with allow_writes: HackerFive will send state-changing (mutating) requests — coupon self-mint/apply, apply-race — to %s. These change target state and are not read-only. Approve only if this is explicitly authorized and in scope, and set acknowledge_writes=true to confirm.",
		strings.Join(in.Targets, ", "))
}

// runScan is the scan tool's actual execution path — the pre-B2 handler body,
// plus writesApproved threaded into cfg.AllowWrites. writesApproved is only
// ever true on the round-2 retry of an attested businesslogic scan (B2); on
// every other path it is false, so a bare allow_writes:true in the request
// body never reaches the engine as a write grant.
func runScan(ctx context.Context, req *mcp.CallToolRequest, in scanInput, writesApproved bool) (res *mcp.CallToolResult, out scanOutput, err error) {
	sc, err := requireScope(in.Scope)
	if err != nil {
		return nil, scanOutput{}, err
	}

	// B2 (doc16 Phase 7 Step 2): allow_writes was requested for a businesslogic
	// scan but not attested via elicitation — say so at the tool level, ahead
	// of the engine's own generic "--allow-writes not set" warning, so the log
	// records that a write grant was asked for and withheld.
	if writesRequested(in) && !writesApproved {
		out.Logs = append(out.Logs, "warn: allow_writes was requested but not attested via elicitation — businesslogic's mutating checks will be skipped (B2)")
	}

	// D2 program-policy pre-flight (doc15 Step 3): a hard refusal when the
	// operator's HACKERFIVE_POLICY_FILE marks a target automated_scanning:
	// disallowed; advisory warnings otherwise. No MCP override.
	preWarns, err := preflightBlock(in.Targets)
	if err != nil {
		return nil, scanOutput{}, err
	}
	for _, w := range preWarns {
		out.Logs = append(out.Logs, "warn: preflight: "+w)
	}

	authToken := in.AuthToken
	if authToken == "" {
		authToken = os.Getenv("HACKERFIVE_AUTH_TOKEN")
	}

	cfg := scanner.Config{
		Targets:          in.Targets,
		TemplatePaths:    defaultTemplateDirs(),
		Tags:             in.Tags,
		Detector:         in.Detector,
		Concurrency:      defaultConcurrency,
		RateLimit:        defaultRateLimit,
		Timeout:          defaultTimeout,
		OutputFormat:     "json",
		AuthToken:        authToken,
		OtherAuthToken:   in.OtherAuthToken,
		EndpointTemplate: in.EndpointTemplate,
		ProtectedPaths:   in.ProtectedPaths,
		AllowWrites:      writesApproved,
		ExtraHeaders:     in.ExtraHeaders,
		Scope:            sc,
	}

	// D6 (docs/16-implementation-plan-ph7.md Step 4): a recon-classified
	// uniform response wall short-circuits the per-target template corpus.
	if in.UniformResponse != nil {
		cfg.UniformWallHosts = map[string]string{in.UniformResponse.Host: in.UniformResponse.Kind}
		out.Logs = append(out.Logs, fmt.Sprintf("info: template scope: recon classified %s as a %s — the template corpus will be skipped for it (D6)", in.UniformResponse.Host, in.UniformResponse.Kind))
	}

	// LT-107 (doc16 Phase 7 Step 7): pass the recon tech stack through so the
	// engine's end-of-scan coverage-gap ledger can run.
	cfg.TechStack = in.TechStack

	// doc15 Step 6a: template scoping is on by default. An explicit Tags
	// wins untouched; all_templates forces the full synced corpus;
	// otherwise the scan is scoped to its detector's category floor
	// (registry.DetectorTemplateTags) plus — when a prior recon tool
	// call's tech_stack is passed along — that stack's product-specific
	// tags (registry.TechStackTags). Degrades to floor-only, then to the
	// full corpus, with a logged note rather than an error.
	if len(in.Tags) == 0 && !in.AllTemplates {
		floor := registry.DetectorTemplateTags(in.Detector)
		var extras []string
		if len(in.TechStack) > 0 {
			if index, idxErr := templatesync.LoadIndex(defaultTemplateIndexPath); idxErr == nil {
				extras = registry.TechStackTags(in.TechStack, index)
			} else {
				out.Logs = append(out.Logs, fmt.Sprintf("warn: template scope: could not load template index (%v) — scoping by detector category only", idxErr))
			}
		}
		cfg.DerivedTags = unionScanTags(floor, extras)
		switch {
		case len(cfg.DerivedTags) == 0:
			out.Logs = append(out.Logs, fmt.Sprintf("info: template scope: %s has no category floor and no tech match — running the full corpus", in.Detector))
		case len(extras) > 0:
			out.Logs = append(out.Logs, fmt.Sprintf("info: template scope: %d tag(s) = %d %s-category floor + %d tech-matched: %s", len(cfg.DerivedTags), len(floor), in.Detector, len(extras), strings.Join(cfg.DerivedTags, ", ")))
		default:
			out.Logs = append(out.Logs, fmt.Sprintf("info: template scope: %d %s-category tag(s) (pass a recon tech_stack for tech-matched CVEs, or all_templates for everything): %s", len(cfg.DerivedTags), in.Detector, strings.Join(cfg.DerivedTags, ", ")))
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, scanOutput{}, err
	}

	// D1 (doc16 Phase 7 Step 4): bound how much scan concurrency this
	// session can aggregate against one host across parallel `scan` calls.
	// Blocks here if the host is already at the per-host call ceiling.
	tmplConc, releaseGate := sessionScanGate.enter(in.Targets)
	defer releaseGate()
	cfg.TemplateConcurrency = tmplConc
	if tmplConc < aggregateTemplateConcurrencyPerHost {
		out.Logs = append(out.Logs, fmt.Sprintf("info: D1 concurrency ceiling: this session has other scan calls in flight against the same host — capping this call's per-target template fan-out at %d", tmplConc))
	}

	token := req.Params.GetProgressToken()
	notify := func(message string) {
		if token == nil {
			return
		}
		_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Message:       message,
		})
	}

	engine := scanner.New(cfg).
		WithFindingCallback(func(f detectors.Finding) {
			out.Findings = append(out.Findings, f)
			notify("finding: " + f.Type + " on " + f.Target)
		}).
		WithLogCallback(func(level, msg string) {
			out.Logs = append(out.Logs, level+": "+msg)
			notify(msg)
		})

	if _, err := engine.Run(ctx); err != nil {
		return nil, out, err
	}
	// LT-6 tail (docs/follow-up.md): the CLI's `scan` command dedups a
	// native+nuclei 1:1 pair (missing-header, weak-HSTS) before export; the
	// MCP scan tool's output never did, so a downstream findings.export call
	// echoing this list straight back would carry the duplicate pair.
	out.Findings = reporter.Dedup(reporter.DropSupersededNucleiFindings(reporter.SplitAggregates(out.Findings)))
	return nil, out, nil
}

// defaultTemplateDirs is defaultTemplateDirsWithLabels (tools_templates.go)
// without the labels — scan's TemplatePaths doesn't need per-source labels,
// only the directory list.
func defaultTemplateDirs() []string {
	dirs, _ := defaultTemplateDirsWithLabels()
	return dirs
}

// unionScanTags is the detector-category floor ∪ tech-matched extras
// composition for the scan tool's doc15 Step 6a default template scoping —
// order-stable, de-duplicated, lower-cased (mirrors cmd/hackerfive's
// unionTags and pkg/webui's unionLaunchTags; each package keeps its own
// copy rather than a shared util for one small helper).
func unionScanTags(floor, extras []string) []string {
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
