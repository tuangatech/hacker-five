// Package agenttask defines the Job.PlanTree data model (doc90 Group H,
// docs/14-implementation-plan-ph5.md Step 2's H2/H3): a task tree an agent
// coordinator plans against, shared by pkg/mcpserver and pkg/webui without
// either depending on the other. Nothing in this package invokes an LLM or
// populates a tree from a real target yet — that's Step 3's decision engine
// and Phase 6's coordinator.
package agenttask

import (
	"errors"
	"sort"
	"sync"
)

// PlanNodeStatus is a PlanNode's lifecycle state.
type PlanNodeStatus string

const (
	StatusPending    PlanNodeStatus = "pending"
	StatusInProgress PlanNodeStatus = "in_progress"
	StatusDone       PlanNodeStatus = "done"
	// StatusUnresolved marks a leaf the decision engine (Step 3's R8)
	// couldn't match to any registry entry — visible and inspectable,
	// never silently dropped and never itself a trigger for an LLM call.
	StatusUnresolved PlanNodeStatus = "unresolved"
	// StatusVetoed marks a StatusPending leaf an optional LLM plausibility
	// pass (C7b, doc16 Phase 7 Step 3 / docs/follow-up.md LT-49) judged
	// implausible — the deterministic engine was confident, but the fact it
	// rested on looks fabricated or irrelevant (an SPA catch-all APISpec, a
	// CDN-brand tech fact). Kept visible with the veto reason in Rationale,
	// never dispatched by planexec, and never re-fed to ResolveTreeLeaves
	// (that only acts on StatusUnresolved).
	StatusVetoed PlanNodeStatus = "vetoed"
	// StatusEscalated marks a leaf whose LLM-fallback resolution ground
	// through its per-leaf attempt/spend budget without a confident answer
	// (H4, doc16 Phase 7 Step 4). MAPTA's finding (doc90 §2): rising
	// tool-call count and dollar cost on one leaf each independently
	// correlate with *falling* odds of success (r ≈ −0.6), so "still
	// grinding, no confidence gain" is a stop signal, not a reason to spend
	// more. A StatusEscalated leaf is terminal for the resolver —
	// ResolveTreeLeaves never calls a model for it again — and, like
	// StatusUnresolved/StatusVetoed, is never dispatched by planexec.
	StatusEscalated PlanNodeStatus = "escalated"
)

// MaxLeafResolveAttempts/MaxLeafResolveSpendUSD are PlanNode.ShouldEscalate's
// per-leaf ceilings (H4). Deliberately small: leaf resolution
// (pkg/llmfallback.ResolveLeaf) is single-shot per plan pass, so Attempts
// only climbs when the same persisted tree is re-resolved across passes,
// and a single resolve call that costs this much has already spent more on
// one leaf than a whole default plan pass is budgeted for
// (llmfallback.PerCallDefaultSpendCeilingUSD == $0.10 for the entire tree).
const (
	MaxLeafResolveAttempts = 3
	MaxLeafResolveSpendUSD = 0.05
)

// Dispatch-ordering priority bands for a leaf (C7a, doc16 Phase 7 Step 3):
// planexec.RunPlan submits higher-Priority leaves first. Coarse bands, not a
// fine-grained score — the executor still dispatches concurrently within a
// tier, so this orders *start* order, not completion order.
const (
	// PriorityDeadEnd sits below every dispatchable band — for a
	// StatusUnresolved / "matched nothing" leaf that has no automated check
	// to run. Without it a recon-followup class node (e.g. a lone
	// unresolved "tech fact X matched no capability") could outrank real
	// scan work in start order (docs/follow-up.md LT-70).
	PriorityDeadEnd = 1
	PriorityLow     = 10
	PriorityMedium  = 20
	PriorityHigh    = 30
)

// PriorityForConfidence maps a leaf's coordinator confidence band to its
// base dispatch priority. A caller may add a small bump on top (e.g. a
// specific-template or endpoint-confirmed leaf is a sharper signal than a
// broad capability sweep at the same band).
func PriorityForConfidence(c Confidence) int {
	switch c {
	case ConfidenceHigh:
		return PriorityHigh
	case ConfidenceMedium:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

// DemoteConfidence returns the next band down (high→medium→low; low stays
// low) — used by the C7b plausibility pass's "demote" verdict.
func DemoteConfidence(c Confidence) Confidence {
	switch c {
	case ConfidenceHigh:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// Confidence is the coordinator's own banded success-probability estimate
// for attempting a PlanNode leaf — Cyber-AutoAgent's convention, and the
// corrected Decision 4 destination (docs/14-implementation-plan-ph5.md's
// Objective section): this is never Finding.Confidence. It never touches a
// Finding once one is actually produced; Finding.Severity/Finding.Confidence
// stay exactly as they are today, both deterministic and detector-set.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"   // >80%
	ConfidenceMedium Confidence = "medium" // 50-80%
	ConfidenceLow    Confidence = "low"    // <50%
)

// BandConfidence maps a raw 0-100 success-probability estimate to Cyber-
// AutoAgent's band convention: High >80, Medium 50-80 inclusive, Low <50.
func BandConfidence(percent float64) Confidence {
	switch {
	case percent > 80:
		return ConfidenceHigh
	case percent >= 50:
		return ConfidenceMedium
	default:
		return ConfidenceLow
	}
}

// PlanNode is one candidate (target, detector/template) pairing in a
// PlanTree. Non-leaf nodes (those with Children) represent task
// decomposition — PentestGPT's PTT shape (doc90 §2) — and are not
// individually mutable once built; only leaves may change post-construction,
// via PlanTree.ApplyLeafUpdate.
//
// registry.Resolve builds three tiers: root → one node per host →
// GroupIntoClassNodes' one intermediate node per vuln-class → the leaves of
// that class (C7a, doc16 Phase 7 Step 3 — replacing the old flat
// root→host→[leaf...] shape). Leaves() flattens all of it, so consumers that
// only care about leaves are unaffected by the extra tier.
type PlanNode struct {
	ID         string         `json:"id"`
	Target     string         `json:"target"`
	Detector   string         `json:"detector,omitempty"`  // detector name, or a template ID/tag
	Class      string         `json:"class,omitempty"`     // vuln-class label — set only on a GroupIntoClassNodes intermediate node
	Rationale  string         `json:"rationale,omitempty"` // why the coordinator picked this candidate
	Status     PlanNodeStatus `json:"status,omitempty"`
	Confidence Confidence     `json:"confidence,omitempty"`
	Priority   int            `json:"priority,omitempty"` // dispatch ordering — higher runs first (C7a); 0 = unset
	// EndpointTemplate is set only on an endpoint-driven idor leaf the
	// decision engine fanned out from a recon candidate (LT-91,
	// docs/follow-up.md): one leaf per {{id}}-templated path, so a spec/crawl
	// that yields several ID-shaped routes scans every one — the same "all
	// candidates are usable" treatment authbypass's ProtectedPaths already
	// gets — instead of collapsing to a single ambiguous field miss. Empty on
	// every other leaf; planexec.runLeaf copies a non-empty value into a
	// blank scanner.Config.EndpointTemplate just before dispatch.
	EndpointTemplate string `json:"endpoint_template,omitempty"`
	// EndpointSeedID / EndpointIDIsUUID are LT-95's (docs/follow-up.md)
	// UUID-keyed-BOLA counterpart to EndpointTemplate: a real, concrete ID
	// value recon actually observed for this leaf's {{id}} position
	// (recon.SuggestIDORSeedIDs), and whether that ID is UUID-shaped.
	// idor.SequentialIntStrategy can never reach a UUID-keyed route by
	// brute-forcing a numeric range; when EndpointIDIsUUID is true,
	// pkg/scanner/engine.go dispatches idor.RandomUUIDStrategy with this
	// seed instead. Empty/false on every int-keyed or seedless leaf.
	EndpointSeedID   string `json:"endpoint_seed_id,omitempty"`
	EndpointIDIsUUID bool   `json:"endpoint_id_is_uuid,omitempty"`
	// ProtectedPaths / SSRFParams are the recon-derived required-field values
	// for an endpoint-driven authbypass / ssrf leaf (LT-94, docs/follow-up.md),
	// set by registry.resolveEndpointFacts from the same Suggest*FromRecon
	// calls that emit the leaf. planexec.runLeaf copies them into a blank
	// scanner.Config just before dispatch, so the plan→execute path is
	// self-sufficient without the caller pre-filling baseCfg (the webui Plan
	// Preview / a bare planexec.RunPlan caller otherwise skipped the leaf for
	// a "missing" field recon had already derived). Empty on every other leaf.
	ProtectedPaths []string `json:"protected_paths,omitempty"`
	SSRFParams     []string `json:"ssrf_params,omitempty"`
	// SSRFBodyParams is SSRFParams' JSON-body-field counterpart (LT-96,
	// docs/follow-up.md), populated from SuggestSSRFBodyParamsFromRecon
	// alongside SSRFParams on the same endpoint-driven ssrf leaf — additive,
	// not a replacement; a leaf may carry either, both, or neither.
	SSRFBodyParams []string `json:"ssrf_body_params,omitempty"`
	// Attempts/SpendUSD accrue per-leaf across LLM-fallback resolution
	// passes (H4, doc16 Phase 7 Step 4) — incremented by
	// PlanTree.RecordLeafAttempt, read by ShouldEscalate. Both 0 on a leaf
	// the resolver never touched.
	Attempts int         `json:"attempts,omitempty"`
	SpendUSD float64     `json:"spend_usd,omitempty"`
	Children []*PlanNode `json:"children,omitempty"`
}

// ShouldEscalate reports whether this leaf has ground through its per-leaf
// resolution budget (MaxLeafResolveAttempts / MaxLeafResolveSpendUSD)
// without a confident answer — the H4 stop signal. Only meaningful for a
// leaf; a non-leaf or nil node never escalates.
func (n *PlanNode) ShouldEscalate() bool {
	if n == nil || len(n.Children) > 0 {
		return false
	}
	if n.Attempts >= MaxLeafResolveAttempts {
		return true
	}
	return MaxLeafResolveSpendUSD > 0 && n.SpendUSD >= MaxLeafResolveSpendUSD
}

// ClassNodeID is the deterministic ID GroupIntoClassNodes/AttachLeaf give a
// host's vuln-class intermediate node.
func ClassNodeID(host, class string) string {
	return "class:" + host + ":" + class
}

// GroupIntoClassNodes rewrites hostNode.Children — currently a flat leaf
// list — into one intermediate node per vuln-class (C7a). classOf labels
// each leaf; leaves sharing a label land under one node whose ID is
// ClassNodeID(hostNode.Target, label), Class is the label, and Priority is
// the max of its leaves' priorities. Class nodes are ordered by descending
// node priority, then label, for a deterministic tree shape. A no-op if
// hostNode is nil, has no children, or is already grouped (any child itself
// has children) so calling it twice is safe.
func GroupIntoClassNodes(hostNode *PlanNode, classOf func(*PlanNode) string) {
	if hostNode == nil || len(hostNode.Children) == 0 {
		return
	}
	for _, c := range hostNode.Children {
		if len(c.Children) > 0 {
			return // already grouped
		}
	}
	order := make([]string, 0, 4)
	byClass := make(map[string][]*PlanNode)
	for _, leaf := range hostNode.Children {
		cls := classOf(leaf)
		if _, seen := byClass[cls]; !seen {
			order = append(order, cls)
		}
		byClass[cls] = append(byClass[cls], leaf)
	}
	nodes := make([]*PlanNode, 0, len(order))
	for _, cls := range order {
		nodes = append(nodes, newClassNode(hostNode.Target, cls, byClass[cls]))
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Priority != nodes[j].Priority {
			return nodes[i].Priority > nodes[j].Priority
		}
		return nodes[i].Class < nodes[j].Class
	})
	hostNode.Children = nodes
}

// AttachLeaf routes leaf under hostNode's class node for the given label,
// creating that class node if hostNode doesn't have one yet — the
// post-construction equivalent of GroupIntoClassNodes for a leaf added after
// the tree was first built (llmfallback.MergeLLMProposals). hostNode must
// already be grouped; if it still holds bare leaves this falls back to a
// plain append so a caller can't accidentally produce a mixed tree.
func AttachLeaf(hostNode *PlanNode, leaf *PlanNode, class string) {
	if hostNode == nil || leaf == nil {
		return
	}
	grouped := len(hostNode.Children) == 0
	for _, c := range hostNode.Children {
		if len(c.Children) > 0 {
			grouped = true
		}
		if c.Class == class && len(c.Children) > 0 {
			c.Children = append(c.Children, leaf)
			if leaf.Priority > c.Priority {
				c.Priority = leaf.Priority
			}
			return
		}
	}
	if !grouped {
		hostNode.Children = append(hostNode.Children, leaf)
		return
	}
	hostNode.Children = append(hostNode.Children, newClassNode(hostNode.Target, class, []*PlanNode{leaf}))
}

func newClassNode(host, class string, leaves []*PlanNode) *PlanNode {
	prio := 0
	for _, l := range leaves {
		if l.Priority > prio {
			prio = l.Priority
		}
	}
	return &PlanNode{
		ID:       ClassNodeID(host, class),
		Target:   host,
		Class:    class,
		Priority: prio,
		Children: leaves,
	}
}

// PlanTree is a Job's task tree. Phase 6 Step 2's executor dispatches
// leaves to parallel goroutines (deterministic and LLM-assisted tiers
// alike), so every access to Root or the spend counters below goes through
// mu — safe for a single in-process human-typed CLI/webui.Job call before
// Step 2, unsafe the moment concurrent leaf goroutines call
// ApplyLeafUpdate/AddSpend on the same tree.
type PlanTree struct {
	Root *PlanNode `json:"root"`

	mu sync.Mutex
	// SpendCeilingUSD is a hard cap on cumulative LLM-fallback cost
	// attributed to resolving this tree (doc15 H5) — zero means unset, no
	// ceiling enforced. Set once by the plan tool handler before any
	// fallback call; never mutated after.
	SpendCeilingUSD float64 `json:"spend_ceiling_usd,omitempty"`
	spendSoFarUSD   float64
}

// Find walks the tree depth-first for the node with the given ID, or nil if
// none matches.
func (t *PlanTree) Find(nodeID string) *PlanNode {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.findLocked(nodeID)
}

func (t *PlanTree) findLocked(nodeID string) *PlanNode {
	if t.Root == nil {
		return nil
	}
	return findNode(t.Root, nodeID)
}

// AddSpend records an LLM-fallback call's real cost against this tree's
// running total and reports whether SpendCeilingUSD is now exceeded. The
// caller must stop issuing further fallback calls the instant this returns
// true — this is a hard-fail budget (doc15 H5), not a warn-and-continue one.
// A zero SpendCeilingUSD never trips (unset, no ceiling enforced).
func (t *PlanTree) AddSpend(usd float64) (exceeded bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.spendSoFarUSD += usd
	return t.SpendCeilingUSD > 0 && t.spendSoFarUSD > t.SpendCeilingUSD
}

// SpendSoFar returns the running total recorded via AddSpend.
func (t *PlanTree) SpendSoFar() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.spendSoFarUSD
}

// Leaves walks n depth-first, returning every node with no children — the
// only nodes PlanTree.ApplyLeafUpdate ever mutates. Shared by
// pkg/mcpserver's executor/plan tool and pkg/webui's plan-preview page, so
// this tree walk is described once rather than duplicated per consumer
// package.
func Leaves(n *PlanNode) []*PlanNode {
	if n == nil {
		return nil
	}
	if len(n.Children) == 0 {
		return []*PlanNode{n}
	}
	var out []*PlanNode
	for _, child := range n.Children {
		out = append(out, Leaves(child)...)
	}
	return out
}

func findNode(n *PlanNode, nodeID string) *PlanNode {
	if n.ID == nodeID {
		return n
	}
	for _, child := range n.Children {
		if found := findNode(child, nodeID); found != nil {
			return found
		}
	}
	return nil
}

// PlanNodePatch is the only shape a post-construction mutation may take.
// Children is included specifically so a shape-changing request can be
// recognized and rejected by ApplyLeafUpdate, not merely a field the API
// happens to omit. Detector was added in Phase 6 Step 2 specifically for
// I4's fallback resolving a StatusUnresolved leaf (pkg/llmfallback's
// use_existing_tag decision) — assigning a leaf's detector after
// construction is a real, deliberate widening of what "leaf mutation"
// means, not a loosening of doc90 §2's shape-change defense: the leaf
// itself (its ID/Target/position in the tree) is still fixed, only which
// detector runs against it can now be set once, post-construction.
type PlanNodePatch struct {
	Status     *PlanNodeStatus
	Confidence *Confidence
	Rationale  *string
	Detector   *string
	// Attempts/SpendUSD, when non-nil, set the leaf's H4 counters
	// absolutely (assignment, matching the other pointer fields). The
	// resolver's own additive path is PlanTree.RecordLeafAttempt; these are
	// here so an external coordinator patch can report or reset grind.
	Attempts *int
	SpendUSD *float64
	Children []*PlanNode // any non-nil value here is rejected: see ApplyLeafUpdate
}

var (
	// ErrNodeNotFound is returned when nodeID doesn't match any node in the tree.
	ErrNodeNotFound = errors.New("agenttask: node not found")
	// ErrNotLeaf is returned when the target node has children — only leaves
	// may be mutated post-construction.
	ErrNotLeaf = errors.New("agenttask: node is not a leaf; only leaf nodes may be mutated")
	// ErrShapeChange is returned when the patch itself carries a Children
	// value — add/remove/reparent has no valid code path through this API.
	ErrShapeChange = errors.New("agenttask: mutation would change the plan tree's shape; only leaf Status/Confidence/Rationale/Detector may be updated")
)

// ApplyLeafUpdate finds nodeID and applies patch's non-nil Status/Confidence/
// Rationale/Detector fields to it in place. It rejects the mutation, unchanged, if
// patch.Children is non-nil (ErrShapeChange), nodeID doesn't exist
// (ErrNodeNotFound), or the matched node has children (ErrNotLeaf) — doc90
// §2's defense against a hallucinated full-plan rewrite: only a leaf's own
// status/confidence/rationale can ever change after the tree is built.
func (t *PlanTree) ApplyLeafUpdate(nodeID string, patch PlanNodePatch) error {
	if patch.Children != nil {
		return ErrShapeChange
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.findLocked(nodeID)
	if node == nil {
		return ErrNodeNotFound
	}
	if len(node.Children) > 0 {
		return ErrNotLeaf
	}
	if patch.Status != nil {
		node.Status = *patch.Status
	}
	if patch.Confidence != nil {
		node.Confidence = *patch.Confidence
	}
	if patch.Rationale != nil {
		node.Rationale = *patch.Rationale
	}
	if patch.Detector != nil {
		node.Detector = *patch.Detector
	}
	if patch.Attempts != nil {
		node.Attempts = *patch.Attempts
	}
	if patch.SpendUSD != nil {
		node.SpendUSD = *patch.SpendUSD
	}
	return nil
}

// RecordLeafAttempt additively charges one LLM-fallback resolution attempt
// and its cost against a leaf's H4 counters and reports whether the leaf
// has now exhausted its per-leaf budget (PlanNode.ShouldEscalate). It does
// NOT itself flip Status to StatusEscalated — the caller does that only
// when the attempt also failed to resolve the leaf, so a successful but
// expensive resolution isn't wrongly marked escalated. spentUSD may be 0
// (a cache hit, a call that never reached a paid tier). Errors mirror
// ApplyLeafUpdate: ErrNodeNotFound, ErrNotLeaf.
func (t *PlanTree) RecordLeafAttempt(nodeID string, spentUSD float64) (budgetExhausted bool, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	node := t.findLocked(nodeID)
	if node == nil {
		return false, ErrNodeNotFound
	}
	if len(node.Children) > 0 {
		return false, ErrNotLeaf
	}
	node.Attempts++
	node.SpendUSD += spentUSD
	return node.ShouldEscalate(), nil
}
