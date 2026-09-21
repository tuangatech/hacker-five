package llmfallback

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

// The decision call is a ~150-token JSON choice, so it gets a tight envelope
// (LT-173, docs/follow-up.md). Live, before this: the model spent minutes on
// hidden reasoning tokens for that answer and two consecutive 4-minute stalls
// ended otherwise healthy vAPI and crAPI runs.
const (
	// decisionTimeout is one NextAction attempt's deadline. completeLabeled
	// retries once on this deadline, so a stalled call costs at most twice this
	// (4 minutes) rather than twice requestTimeout (8), and the orchestrator
	// gives up on the model after MaxConsecutiveLLMFailures such calls.
	decisionTimeout = 120 * time.Second

	// decisionMaxTokens is generous on purpose: on most providers the cap covers
	// reasoning plus the answer (see callOpts), so it bounds a runaway rather
	// than trimming a normal reply.
	decisionMaxTokens = 2048

	// decisionReasoningEffort keeps a reasoning-capable model from deliberating
	// at length over a choice among six tools.
	decisionReasoningEffort = "low"

	// envDecisionReasoningEffort overrides decisionReasoningEffort. Set it to an
	// empty value to send no `reasoning` field at all — the escape hatch for a
	// model or provider that rejects the field, since support is per-model.
	envDecisionReasoningEffort = "HACKERFIVE_DECISION_REASONING_EFFORT"
)

// decisionCallOpts is the output envelope NextAction's model call runs under.
func decisionCallOpts() callOpts {
	effort := decisionReasoningEffort
	if v, ok := os.LookupEnv(envDecisionReasoningEffort); ok {
		effort = strings.TrimSpace(v)
	}
	return callOpts{maxTokens: decisionMaxTokens, reasoningEffort: effort}
}

// orchestrateActionKinds is the fixed allow-list NextAction validates every
// returned Action.Kind against (docs/93-implementation-plan-agent-
// orchestrator.md M1) — the closed tool catalog pkg/orchestrator's loop
// dispatches. "script.explore" is the sole shell/exec-shaped kind (doc90
// Decision 2, reopened scoped) and carries no special status here: like
// every other kind, an unrecognized value degrades to "stop", never trusted
// through. Enforcement of script.explore's sandbox/HITL gate lives in
// pkg/scriptexec and pkg/orchestrator, not in this validation.
var orchestrateActionKinds = map[string]bool{
	"recon.refresh":   true,
	"registry.lookup": true,
	"scan.leaf":       true,
	"triage.rank":     true,
	"script.explore":  true,
	"stop":            true,
}

// ToolSpec describes one tool in the catalog pkg/orchestrator's loop offers
// NextAction — a name plus a short human-readable description of when to
// pick it and what Params shape it expects. The catalog is supplied by the
// caller (not hardcoded here) so pkg/orchestrator remains the single place
// that defines what each kind actually does; this package only validates
// that a returned Kind names one of the kinds offered.
type ToolSpec struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

// TurnRecord is one already-completed loop iteration, fed back into the next
// NextAction call so the model doesn't repeat an action that already ran or
// already failed — the orchestrator's only memory, since every call here
// remains stateless (doc90 Decision 5): the caller reconstructs history from
// its own loop state and passes it in fresh each time.
type TurnRecord struct {
	Action        Action `json:"action"`
	ResultSummary string `json:"result_summary,omitempty"`
	Error         string `json:"error,omitempty"`
	// Auto marks a turn the orchestrator dispatched itself, without asking the
	// model (its deterministic fast lane, LT-172). The record is kept for the
	// run's own audit trail, but buildOrchestratePrompt renders it only as a
	// count — the model's window is for turns it chose, and a long auto run
	// would otherwise push those out of the bounded history.
	Auto bool `json:"auto,omitempty"`
}

// FindingDigest is one confirmed finding as NextAction's prompt shows it —
// just enough to tell one finding from another. Never carries evidence bodies.
type FindingDigest struct {
	ID       string `json:"id"`
	Type     string `json:"type,omitempty"`
	Severity string `json:"severity,omitempty"`
	Target   string `json:"target,omitempty"`
}

// RunDigest is the run state the plan tree alone doesn't carry, supplied by
// the caller on every NextAction call (LT-171, docs/follow-up.md). Before it
// existed the model saw a bare "1 finding(s)" per turn and nothing of what
// recon had actually observed, so it reasoned from leaf rationales and its
// own earlier guesses — one run wrote "already confirmed" for a finding that
// was a different, unrelated detection re-fired by an earlier turn.
type RunDigest struct {
	// Recon is one short, already-rendered line per notable recon fact
	// (fingerprinted technology, API spec, app-surface verdict, ...).
	Recon []string
	// Findings is every distinct finding confirmed so far this run.
	Findings []FindingDigest
}

// Action is one orchestrator turn's decision: which tool to run next, on
// which existing plan-tree node (if any), with what tool-specific
// parameters, and why. NodeID, when non-empty, must already exist in the
// tree NextAction was called with — this package rejects (degrades to stop)
// a fabricated node id the same way agenttask.PlanTree.ApplyLeafUpdate
// rejects a shape change, so an orchestrator loop can trust NodeID without
// re-validating it. Params is opaque here (tool-specific: e.g.
// script.explore expects {"language": "python"|"shell", "source": "..."});
// pkg/orchestrator decodes it once it knows which Kind it's dispatching.
type Action struct {
	Kind      string          `json:"kind"`
	NodeID    string          `json:"node_id,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Rationale string          `json:"rationale,omitempty"`
}

const orchestrateSystemPrompt = `You are HackerFive's scan orchestrator. You are given the current state of a plan tree (a target's candidate checks, each with a status/confidence/rationale), a fixed catalog of tools you may invoke next, and a short history of turns already taken this run. Decide the SINGLE next action to take toward finding and confirming a real, in-scope vulnerability — or decide to stop.

You never invent a plan-tree node id that isn't listed below. You never claim a vulnerability was found yourself — only a tool's own dispatched execution (scan.leaf's detector match, or script.explore's independently reconfirmed evidence) can ever produce a Finding; your job here is only to pick which tool runs next, not to assert a result.

Prefer a deterministic tool (registry.lookup, scan.leaf) over script.explore whenever one plausibly covers the gap — script.explore is for exploration a fixed detector/template genuinely cannot do (e.g. non-numeric ID-space decoding, custom signing-scheme reverse-engineering), not a default first move. Choose "stop" once nothing left in the tree is worth another turn, or you are not confident any listed tool makes progress.

The plan tree, the recon facts and the "findings confirmed so far" list are the ground truth for this run. A finding is confirmed only if it appears in that list; a turn's result summary that merely reports a count is not evidence of a new or a specific finding, so never describe something as already confirmed from it. Choose among leaves by what recon actually observed for the target — a leaf naming a specific endpoint or technology recon found is a stronger candidate than a generic one. Some leaves may already have been run for you (status=done); pick from what remains.

Respond with ONLY a JSON object, no other text, matching exactly:
{"kind": "<one of the catalog kinds below>", "node_id": "<existing plan-tree node id, or omit if this action doesn't target one>", "params": {<tool-specific parameters, or omit if the tool needs none>}, "rationale": "<short reason>"}`

// NextAction is the orchestrator loop's single per-turn call
// (docs/93-implementation-plan-agent-orchestrator.md M1/M2): given the
// current tree, the tool catalog on offer, and prior turns this run, decide
// one Action. Mirrors ResolveLeaf/Suggest's contract exactly: a real call
// error (network, no tier available) is returned as an error for the caller
// to handle, while a malformed or out-of-catalog model response degrades to
// Action{Kind: "stop"} with the reason in Rationale — never fabricated,
// never silently retried. costUSD is the cost of the one call made (0 if the
// local tier served it).
func (c *Client) NextAction(ctx context.Context, tree *agenttask.PlanTree, catalog []ToolSpec, history []TurnRecord, digest RunDigest) (Action, float64, error) {
	prompt := buildOrchestratePrompt(tree, catalog, history, digest)
	text, cost, err := c.completeBestAvailableWith(ctx, orchestrateSystemPrompt, prompt, "NextAction", decisionTimeout, decisionCallOpts())
	if err != nil {
		return Action{}, cost, err
	}

	var action Action
	if err := decodeJSONResponse(text, &action); err != nil {
		return Action{Kind: "stop", Rationale: "malformed NextAction response: " + err.Error()}, cost, nil
	}
	if !orchestrateActionKinds[action.Kind] {
		return Action{Kind: "stop", Rationale: fmt.Sprintf("model returned unrecognized action kind %q", action.Kind)}, cost, nil
	}
	kindOffered := false
	for _, t := range catalog {
		if t.Kind == action.Kind {
			kindOffered = true
			break
		}
	}
	if action.Kind != "stop" && !kindOffered {
		return Action{Kind: "stop", Rationale: fmt.Sprintf("model chose kind %q, which was not in the offered catalog", action.Kind)}, cost, nil
	}
	if action.NodeID != "" && (tree == nil || tree.Find(action.NodeID) == nil) {
		return Action{Kind: "stop", Rationale: fmt.Sprintf("model referenced unknown node id %q", action.NodeID)}, cost, nil
	}
	return action, cost, nil
}

// maxHistoryTurnsInPrompt bounds how many of the most recent TurnRecords
// buildOrchestratePrompt includes. Found live (docs/follow-up.md LT-162's
// re-verification, 2026-09-19): pkg/orchestrator.Config.MinIterations forces
// a run to keep dispatching turns instead of stopping after 1-2, and this
// function used to render the ENTIRE history unbounded every call — a
// Juice Shop run's prompt grew turn over turn until a NextAction call
// exceeded the 240s request timeout entirely (a hard failure, no result at
// all). Older turns are summarized by count instead of dropped silently, so
// the model still knows the run has a longer past than it can see verbatim.
const maxHistoryTurnsInPrompt = 10

// maxLeafNodesInPrompt bounds how many plan-tree leaves buildOrchestratePrompt
// renders (docs/follow-up.md LT-165): unlike turn history (already capped by
// maxHistoryTurnsInPrompt), the leaf list used to be rendered in full on
// every call — on a target with a larger tree (crAPI's, live-observed larger
// than vAPI/DVWA/Juice Shop's), this plausibly compounded NextAction's
// already-slow real-world latency (60-150s+ per call against
// deepseek/deepseek-v4.1-flash). boundedLeavesForPrompt keeps every
// actionable (pending/unresolved) leaf visible first — those are the only
// ones a node_id could usefully target this turn — and drops an
// already-settled one (done/vetoed/escalated) first when the cap is hit.
const maxLeafNodesInPrompt = 80

// boundedLeavesForPrompt returns at most maxLeafNodesInPrompt of leaves,
// preferring every actionable (StatusPending/StatusUnresolved) one over an
// already-settled one — a settled leaf carries no decision NextAction needs
// to make, while an actionable leaf's id must stay visible for it to have
// anything real left to reference. If even the actionable set alone exceeds
// the cap, it's truncated too rather than ballooning the prompt further; an
// omitted actionable leaf becomes visible on a later call once earlier ones
// resolve and free up room (a leaf's Status changes as the run progresses).
func boundedLeavesForPrompt(leaves []*agenttask.PlanNode) (shown []*agenttask.PlanNode, omitted int) {
	if len(leaves) <= maxLeafNodesInPrompt {
		return leaves, 0
	}
	var actionable, settled []*agenttask.PlanNode
	for _, leaf := range leaves {
		if leaf.Status == agenttask.StatusPending || leaf.Status == agenttask.StatusUnresolved {
			actionable = append(actionable, leaf)
		} else {
			settled = append(settled, leaf)
		}
	}
	if len(actionable) >= maxLeafNodesInPrompt {
		return actionable[:maxLeafNodesInPrompt], len(leaves) - maxLeafNodesInPrompt
	}
	room := maxLeafNodesInPrompt - len(actionable)
	if room > len(settled) {
		room = len(settled)
	}
	shown = append(shown, actionable...)
	shown = append(shown, settled[:room]...)
	return shown, len(leaves) - len(shown)
}

// maxReconLinesInPrompt / maxFindingsInPrompt bound the two RunDigest
// sections for the same reason maxLeafNodesInPrompt/maxHistoryTurnsInPrompt
// bound theirs: NextAction's latency scales with prompt size.
const (
	maxReconLinesInPrompt = 30
	maxFindingsInPrompt   = 25
)

func buildOrchestratePrompt(tree *agenttask.PlanTree, catalog []ToolSpec, history []TurnRecord, digest RunDigest) string {
	var b strings.Builder

	b.WriteString("plan tree nodes (leaves only — only these ids are valid node_id values):\n")
	if tree != nil && tree.Root != nil {
		leaves, omitted := boundedLeavesForPrompt(agenttask.Leaves(tree.Root))
		if omitted > 0 {
			fmt.Fprintf(&b, "(%d leaf/leaves omitted for space, already-settled ones dropped first — showing %d)\n", omitted, len(leaves))
		}
		for _, leaf := range leaves {
			det := leaf.Detector
			if det == "" {
				det = "(unresolved)"
			}
			// The endpoint template is what distinguishes one endpoint-driven leaf
			// from its siblings on the same host+detector — without it (LT-171)
			// every such leaf read identically apart from an opaque id.
			endpoint := ""
			if leaf.EndpointTemplate != "" {
				endpoint = fmt.Sprintf(" endpoint=%q", leaf.EndpointTemplate)
			}
			fmt.Fprintf(&b, "- id=%s target=%s%s detector=%s status=%s confidence=%s attempts=%d spend_usd=%.4f rationale=%q\n",
				leaf.ID, leaf.Target, endpoint, det, leaf.Status, leaf.Confidence, leaf.Attempts, leaf.SpendUSD, leaf.Rationale)
		}
	}

	b.WriteString("\nrecon facts (observed this run):\n")
	if len(digest.Recon) == 0 {
		b.WriteString("(none recorded)\n")
	}
	for i, line := range digest.Recon {
		if i == maxReconLinesInPrompt {
			fmt.Fprintf(&b, "(%d more recon fact(s) omitted)\n", len(digest.Recon)-maxReconLinesInPrompt)
			break
		}
		fmt.Fprintf(&b, "- %s\n", line)
	}

	b.WriteString("\nfindings confirmed so far this run (distinct):\n")
	if len(digest.Findings) == 0 {
		b.WriteString("(none yet)\n")
	}
	for i, f := range digest.Findings {
		if i == maxFindingsInPrompt {
			fmt.Fprintf(&b, "(%d more finding(s) omitted)\n", len(digest.Findings)-maxFindingsInPrompt)
			break
		}
		fmt.Fprintf(&b, "- id=%s type=%s severity=%s target=%s\n", f.ID, f.Type, f.Severity, f.Target)
	}

	b.WriteString("\navailable tools:\n")
	for _, t := range catalog {
		fmt.Fprintf(&b, "- %s: %s\n", t.Kind, t.Description)
	}

	b.WriteString("\nturn history this run (most recent last):\n")
	// Auto-dispatched turns (the orchestrator's fast lane) are summarized as a
	// count, not listed — see TurnRecord.Auto.
	var shown []TurnRecord
	auto := 0
	for _, h := range history {
		if h.Auto {
			auto++
			continue
		}
		shown = append(shown, h)
	}
	if auto > 0 {
		fmt.Fprintf(&b, "(%d leaf scan(s) were auto-dispatched without a decision — their outcome is in the plan tree statuses and the findings list above)\n", auto)
	}
	if len(shown) == 0 {
		b.WriteString("(none yet)\n")
	} else if len(shown) > maxHistoryTurnsInPrompt {
		omitted := len(shown) - maxHistoryTurnsInPrompt
		fmt.Fprintf(&b, "(%d earlier turn(s) omitted — showing the most recent %d)\n", omitted, maxHistoryTurnsInPrompt)
		shown = shown[omitted:]
	}
	for _, h := range shown {
		fmt.Fprintf(&b, "- kind=%s node_id=%s rationale=%q result=%q error=%q\n",
			h.Action.Kind, h.Action.NodeID, h.Action.Rationale, h.ResultSummary, h.Error)
	}

	return b.String()
}
