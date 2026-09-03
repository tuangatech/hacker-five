package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// findingsTriageInput mirrors findings.export's own shape (tools_findings.go):
// a plain finding list in, no Job/state coupling — I4's third caller (doc15
// Step 2) has no natural home on a Job the way pkg/webui has one, and
// mcpserver has no Job concept of its own, so this is stateless like every
// other tool here.
type findingsTriageInput struct {
	Findings []detectors.Finding `json:"findings"`
}

type findingsTriageOutput struct {
	Ranked          []llmfallback.RankedFinding `json:"ranked,omitempty"`
	EscalateToHuman string                      `json:"escalate_to_human,omitempty"`
	Approved        bool                        `json:"approved"`
}

// addFindingsTriageTool, like plan, is a two-round SEP-2322 tool
// (planstate.go's doc comment has the full real-world finding): round 1
// computes the ranking and returns InputRequests; round 2 (the client's
// automatic retry) looks up the cached ranking by RequestState and applies
// the human's decision. No exception for "it's just sorting" (doc15 Step
// 2's own instruction) — a ranking is presented for approval exactly like a
// plan or a leaf mutation, never auto-applied.
func addFindingsTriageTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "findings.triage",
		Description: "Rank a finding list by what's worth investigating first, via the tiered LLM fallback (I4). Never adds a finding or changes severity/confidence — ranking only. Presented for human approval via elicitation before being returned as approved.",
	}, handleFindingsTriage)
}

func handleFindingsTriage(ctx context.Context, req *mcp.CallToolRequest, in findingsTriageInput) (*mcp.CallToolResult, findingsTriageOutput, error) {
	if resp, ok := req.Params.InputResponses["approve"]; ok {
		pending, ok := takePendingTriage(req.Params.RequestState)
		if !ok {
			return nil, findingsTriageOutput{}, nil // expired/unknown state — nothing to approve, same as a stale plan retry
		}
		if !isApproved(resp) {
			return nil, findingsTriageOutput{Ranked: pending.ranked}, nil
		}
		return nil, findingsTriageOutput{Ranked: pending.ranked, Approved: true}, nil
	}

	if len(in.Findings) == 0 {
		return nil, findingsTriageOutput{}, nil
	}

	fb, err := llmfallback.New()
	if err != nil {
		return nil, findingsTriageOutput{EscalateToHuman: "LLM fallback unavailable: " + err.Error()}, nil
	}

	result, _, err := fb.TriageFindings(ctx, in.Findings)
	if err != nil {
		// Escalated, not a hard tool error — same posture as ResolveLeaf/
		// ResolveField's own call failures in the plan tool (tools_plan.go):
		// an LLM-fallback call failing is an expected, recoverable outcome
		// (model unavailable, transient network issue), not a HackerFive
		// bug the caller needs a protocol-level error for.
		return nil, findingsTriageOutput{EscalateToHuman: "LLM fallback call failed: " + err.Error()}, nil
	}
	if result.EscalateToHuman != "" {
		return nil, findingsTriageOutput{EscalateToHuman: result.EscalateToHuman}, nil
	}

	if !clientSupportsElicitation(req.Session) {
		return nil, findingsTriageOutput{Ranked: result.Ranked}, nil
	}

	id := storePendingTriage(&pendingTriage{ranked: result.Ranked})
	return &mcp.CallToolResult{
		InputRequests: mcp.InputRequestMap{"approve": &mcp.ElicitParams{
			Message:         "A ranking of the given findings is ready — approve to use it?",
			RequestedSchema: approveRequestSchema,
		}},
		RequestState: id,
	}, findingsTriageOutput{}, nil
}
