package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// TestPlanTool_MissingScope_Refused/InvalidDepth mirror recon's own tests
// (tools_recon_test.go) — plan wraps the same recon.Run pipeline, so the
// same pre-flight rejections apply before any network call happens. The
// full elicitation/execution round trip needs a real target and a real
// elicitation-capable client and is covered by doc15 Step 2's live
// verification, not an offline unit test.
func TestPlanTool_MissingScope_Refused(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "plan",
		Arguments: map[string]any{"target": "example.com", "scope": []string{}},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want a tool-level error result: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for a plan call with an empty scope list")
	}
}

func TestPlanTool_InvalidDepth_Rejected(t *testing.T) {
	ctx := context.Background()
	session, err := connect(ctx, New())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "plan",
		Arguments: map[string]any{
			"target": "example.com",
			"scope":  []string{"example.com"},
			"depth":  "not-a-real-depth",
		},
	})
	if err != nil {
		t.Fatalf("CallTool returned a protocol error, want a tool-level error result: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError=true for an invalid depth value")
	}
}

// missingRequiredField's own tests moved to pkg/planexec/executor_test.go
// (Phase 6 Step 4) alongside the function itself.

// applyLeafDecision/writeProposedTemplate moved to pkg/llmfallback (doc15
// Step 2's 2026-09-03 addendum item 2) — their tests moved with them, to
// pkg/llmfallback/resolve_test.go.

func TestIsApproved(t *testing.T) {
	tests := []struct {
		name string
		resp mcp.InputResponse
		want bool
	}{
		{"accepted with approve=true", &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, true},
		{"accepted with approve=false", &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": false}}, false},
		{"declined", &mcp.ElicitResult{Action: "decline"}, false},
		{"canceled", &mcp.ElicitResult{Action: "cancel"}, false},
		{"accepted but missing approve key", &mcp.ElicitResult{Action: "accept", Content: map[string]any{}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isApproved(tt.resp))
		})
	}
}

func TestHandlePlanApproval_UnknownRequestState_ReturnsError(t *testing.T) {
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{RequestState: "does-not-exist"}}
	_, out, err := handlePlanApproval(context.Background(), req, &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found or expired")
	assert.Equal(t, planOutput{}, out)
}

func TestHandlePlanApproval_Declined_ReturnsUnexecuted(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}}
	id := storePendingPlan(&pendingPlan{tree: tree})

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{RequestState: id}}
	_, out, err := handlePlanApproval(context.Background(), req, &mcp.ElicitResult{Action: "decline"})
	require.NoError(t, err)
	assert.False(t, out.Approved)
	assert.Contains(t, out.Note, "not approved")
	assert.Same(t, tree, out.Tree)
}

func TestSummarizePlan(t *testing.T) {
	tree := &agenttask.PlanTree{
		Root: &agenttask.PlanNode{ID: "root", Target: "http://example.com", Children: []*agenttask.PlanNode{
			{ID: "leaf1", Status: agenttask.StatusDone},
			{ID: "leaf2", Status: agenttask.StatusUnresolved},
		}},
		SpendCeilingUSD: 1.00,
	}

	msg := summarizePlan(tree, []agenttask.FieldSuggestion{{Detector: "idor", Field: "endpoint_template"}}, []string{"idor.endpoint_template: no candidates found"}, []string{"example.com: no entry in policy.yaml"}, []string{"cdn.vendor.example", "old.example.net"}, false)

	assert.Contains(t, msg, "http://example.com")
	assert.Contains(t, msg, "2 leaves (1 still unresolved)")
	assert.Contains(t, msg, "1 field suggestion(s)")
	assert.Contains(t, msg, "ceiling $1.00")
	assert.Contains(t, msg, "Escalations: idor.endpoint_template: no candidates found")
	assert.Contains(t, msg, "Pre-flight: example.com: no entry in policy.yaml")
	assert.Contains(t, msg, "Out-of-scope hosts recon found (they will NOT be scanned): cdn.vendor.example, old.example.net")
	assert.Contains(t, msg, "acknowledge_out_of_scope=true")
	assert.Contains(t, msg, "Approve to execute")
}

func TestSummarizePlan_NoEscalations_OmitsOptionalClauses(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Target: "http://example.com"}}
	msg := summarizePlan(tree, nil, nil, nil, nil, false)
	assert.NotContains(t, msg, "Escalations:")
	assert.NotContains(t, msg, "Pre-flight:")
	assert.NotContains(t, msg, "Out-of-scope")
	assert.NotContains(t, msg, "acknowledge_writes")
}

// TestSummarizePlan_WritesAck covers B2: when the plan carries a
// businesslogic leaf and allow_writes was requested, the elicitation message
// spells out the mutating checks and asks for acknowledge_writes.
func TestSummarizePlan_WritesAck(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Target: "http://example.com"}}
	msg := summarizePlan(tree, nil, nil, nil, nil, true)
	assert.Contains(t, msg, "acknowledge_writes=true")
	assert.Contains(t, msg, "mutating")
}

func TestPlanHasBusinessLogicLeaf(t *testing.T) {
	blTree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "a", Detector: "misconfig"},
		{ID: "b", Detector: "businesslogic"},
	}}}
	plainTree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "a", Detector: "misconfig"},
		{ID: "b", Detector: "idor"},
	}}}
	assert.True(t, planHasBusinessLogicLeaf(blTree))
	assert.False(t, planHasBusinessLogicLeaf(plainTree))
	assert.False(t, planHasBusinessLogicLeaf(nil))
}

// TestIsPlanApproved_ScopeAck covers B4's extra gate: when the plan's recon
// found out-of-scope hosts, approve=true alone is not enough — the human must
// also set acknowledge_out_of_scope=true.
func TestIsPlanApproved_ScopeAck(t *testing.T) {
	approveOnly := &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}
	both := &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_out_of_scope": true}}
	declined := &mcp.ElicitResult{Action: "decline"}

	assert.True(t, isPlanApproved(approveOnly, false, false), "no ack required -> approve alone is enough")
	assert.False(t, isPlanApproved(approveOnly, true, false), "scope ack required but not given -> not approved")
	assert.True(t, isPlanApproved(both, true, false), "scope ack required and given -> approved")
	assert.False(t, isPlanApproved(declined, true, false))
	assert.False(t, isPlanApproved(declined, false, false))
}

// TestIsPlanApproved_WritesAck covers B2's gate: when the plan carries a
// businesslogic leaf with allow_writes requested, approve=true alone is not
// enough — acknowledge_writes=true is also required.
func TestIsPlanApproved_WritesAck(t *testing.T) {
	approveOnly := &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}
	withWrites := &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_writes": true}}
	bothAcks := &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_writes": true, "acknowledge_out_of_scope": true}}

	assert.False(t, isPlanApproved(approveOnly, false, true), "writes ack required but not given -> not approved")
	assert.True(t, isPlanApproved(withWrites, false, true), "writes ack required and given -> approved")
	assert.False(t, isPlanApproved(withWrites, true, true), "both acks required, only writes given -> not approved")
	assert.True(t, isPlanApproved(bothAcks, true, true), "both acks required and given -> approved")
}

// TestHandlePlanApproval_OutOfScope_RequiresAck drives the round-2 handler
// with a pendingPlan carrying out-of-scope hosts: approve without the ack
// leaves the plan unexecuted with an explanatory note; approve WITH the ack
// proceeds (and, with an empty tree, completes cleanly).
func TestHandlePlanApproval_OutOfScope_RequiresAck(t *testing.T) {
	newReq := func(id string) *mcp.CallToolRequest {
		return &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{RequestState: id}}
	}

	id := storePendingPlan(&pendingPlan{
		tree:       &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}},
		outOfScope: []string{"cdn.vendor.example"},
	})
	_, out, err := handlePlanApproval(context.Background(), newReq(id),
		&mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}})
	require.NoError(t, err)
	assert.False(t, out.Approved, "approve without the scope ack must not execute")
	assert.Contains(t, out.Note, "acknowledge_out_of_scope")
	assert.Equal(t, []string{"cdn.vendor.example"}, out.OutOfScope)

	id = storePendingPlan(&pendingPlan{
		tree:       &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}},
		outOfScope: []string{"cdn.vendor.example"},
	})
	_, out, err = handlePlanApproval(context.Background(), newReq(id),
		&mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true, "acknowledge_out_of_scope": true}})
	require.NoError(t, err)
	assert.True(t, out.Approved, "approve + ack must execute")
}

// TestHandlePlanApproval_WritesAck_RequiredButWithheld covers B2's round-2
// gate: a pending plan whose tree has a businesslogic leaf and whose baseCfg
// carries AllowWrites (allow_writes was requested) is NOT executed when the
// human approves without acknowledge_writes — the note names the missing ack.
func TestHandlePlanApproval_WritesAck_RequiredButWithheld(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{
		{ID: "bl", Detector: "businesslogic", Target: "http://example.com"},
	}}}
	id := storePendingPlan(&pendingPlan{tree: tree, baseCfg: scanner.Config{AllowWrites: true}})

	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{RequestState: id}}
	_, out, err := handlePlanApproval(context.Background(), req,
		&mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}})
	require.NoError(t, err)
	assert.False(t, out.Approved, "approve without acknowledge_writes must not execute a writes-capable businesslogic plan")
	assert.Contains(t, out.Note, "acknowledge_writes")
}

func TestBuildBaseExecConfig_ExplicitAuthTokenWins(t *testing.T) {
	t.Setenv("HACKERFIVE_AUTH_TOKEN", "from-env")
	sc, err := scope.New([]string{"example.com"})
	require.NoError(t, err)

	cfg := buildBaseExecConfig(planInput{AuthToken: "explicit-token", OtherAuthToken: "other", AllowWrites: true}, sc)

	assert.Equal(t, "explicit-token", cfg.AuthToken)
	assert.Equal(t, "other", cfg.OtherAuthToken)
	assert.True(t, cfg.AllowWrites)
	assert.Same(t, sc, cfg.Scope)
	assert.Equal(t, "json", cfg.OutputFormat)
	assert.NotEmpty(t, cfg.TemplatePaths)
}

func TestBuildBaseExecConfig_FallsBackToEnvVar(t *testing.T) {
	t.Setenv("HACKERFIVE_AUTH_TOKEN", "from-env")
	sc, err := scope.New([]string{"example.com"})
	require.NoError(t, err)

	cfg := buildBaseExecConfig(planInput{}, sc)

	assert.Equal(t, "from-env", cfg.AuthToken)
}

// reconResultWithEndpoints builds a minimal *recon.ReconResult carrying
// exactly the EndpointFacts a test needs, to drive
// resolveFieldSuggestions/the pkg/recon Suggest* functions it wraps
// deterministically.
func reconResultWithEndpoints(endpoints ...recon.EndpointFact) *recon.ReconResult {
	return &recon.ReconResult{Target: "https://example.com", Endpoints: endpoints}
}

// treeWithLeafDetectors builds a minimal PlanTree whose leaves carry the
// given detector names — the precondition resolveFieldSuggestions now gates
// on (a field suggestion only ever fills a field on an already-emitted
// leaf, so with no leaf for a detector the whole block, I4 call included, is
// skipped).
func treeWithLeafDetectors(detectors ...string) *agenttask.PlanTree {
	root := &agenttask.PlanNode{ID: "root"}
	for i, d := range detectors {
		root.Children = append(root.Children, &agenttask.PlanNode{ID: fmt.Sprintf("leaf-%d", i), Target: "https://example.com", Detector: d})
	}
	return &agenttask.PlanTree{Root: root}
}

// TestResolveFieldSuggestions_SingleCandidateEverything_AutoFillsNoEscalation
// exercises resolveFieldSuggestions' every auto-fill branch (idor's single
// candidate, authbypass's single protected/login/logout candidate, ssrf's
// keyword match) in one pass — none of these should ever reach I4
// (resolveOneFieldMiss), so fb/fbErr are left as a guaranteed-unreachable
// nil/nil.
func TestResolveFieldSuggestions_SingleCandidateEverything_AutoFillsNoEscalation(t *testing.T) {
	result := reconResultWithEndpoints(
		recon.EndpointFact{URL: "https://example.com/api/report?report_id=482"},
		recon.EndpointFact{URL: "https://example.com/admin", StatusCode: 403},
		recon.EndpointFact{URL: "https://example.com/login"},
		recon.EndpointFact{URL: "https://example.com/logout"},
		recon.EndpointFact{URL: "https://example.com/proxy?url=http://internal"},
	)
	tree := treeWithLeafDetectors("idor", "authbypass", "ssrf")
	baseCfg := scanner.Config{}
	var escalations []string

	suggestions := resolveFieldSuggestions(context.Background(), result, nil, errors.New("no llm configured"), tree, &baseCfg, &escalations)

	assert.Empty(t, escalations, "every candidate here is unambiguous — none should reach I4")
	assert.Equal(t, "/api/report?report_id={{id}}", baseCfg.EndpointTemplate)
	assert.Equal(t, []string{"/admin"}, baseCfg.ProtectedPaths)
	assert.Equal(t, []string{"/login"}, baseCfg.LoginPaths)
	assert.Equal(t, []string{"/logout"}, baseCfg.LogoutPaths)
	assert.Equal(t, []string{"url"}, baseCfg.SSRFParams)
	assert.NotEmpty(t, suggestions)
	for _, fs := range suggestions {
		assert.Empty(t, fs.EscalateToHuman, "an auto-filled suggestion must never carry an escalation")
	}
}

// TestResolveFieldSuggestions_NoCandidates_EscalatesToHuman covers idor's
// zero-candidate miss and authbypass's zero-ProtectedPaths miss — the only
// two genuine I4 triggers doc14 Step 7 names. fb=nil forces
// ResolveFieldMiss's deterministic local-only escalation path (pkg/llmfallback's
// own contract), so this stays offline and fast.
func TestResolveFieldSuggestions_NoCandidates_EscalatesToHuman(t *testing.T) {
	result := reconResultWithEndpoints(recon.EndpointFact{URL: "https://example.com/about"})
	tree := treeWithLeafDetectors("idor", "authbypass")
	baseCfg := scanner.Config{}
	var escalations []string

	suggestions := resolveFieldSuggestions(context.Background(), result, nil, errors.New("no llm configured"), tree, &baseCfg, &escalations)

	require.Len(t, escalations, 2, "idor.endpoint_template and authbypass.protected_paths should both escalate")
	require.Len(t, suggestions, 2)
	for _, fs := range suggestions {
		assert.NotEmpty(t, fs.EscalateToHuman)
	}
	assert.Empty(t, baseCfg.EndpointTemplate)
	assert.Empty(t, baseCfg.ProtectedPaths)
}

// TestResolveFieldSuggestions_MultipleProtectedCandidates_AllUsableNoAmbiguity
// covers authbypass's third branch: more than one ProtectedPaths candidate
// is still unambiguous (every one is directly usable), unlike idor's
// multiple-candidate case.
func TestResolveFieldSuggestions_MultipleProtectedCandidates_AllUsableNoAmbiguity(t *testing.T) {
	result := reconResultWithEndpoints(
		recon.EndpointFact{URL: "https://example.com/admin", StatusCode: 403},
		recon.EndpointFact{URL: "https://example.com/settings", StatusCode: 401},
	)
	tree := treeWithLeafDetectors("authbypass")
	baseCfg := scanner.Config{}
	var escalations []string

	resolveFieldSuggestions(context.Background(), result, nil, errors.New("no llm configured"), tree, &baseCfg, &escalations)

	assert.ElementsMatch(t, []string{"/admin", "/settings"}, baseCfg.ProtectedPaths)
	assert.NotContains(t, escalations, "authbypass")
}

func TestResolveOneFieldMiss_NoLLMConfigured_EscalatesWithReason(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}}
	var escalations []string

	fs := resolveOneFieldMiss(context.Background(), nil, errors.New("no llm configured"), tree, "idor", "endpoint_template", nil, &escalations)

	require.NotNil(t, fs)
	assert.Equal(t, "idor", fs.Detector)
	assert.Equal(t, "endpoint_template", fs.Field)
	assert.Contains(t, fs.EscalateToHuman, "no llm configured")
	require.Len(t, escalations, 1)
	assert.Contains(t, escalations[0], "idor.endpoint_template")
	assert.Equal(t, 0.0, tree.SpendSoFar(), "a nil fallback client must never record spend")
}
