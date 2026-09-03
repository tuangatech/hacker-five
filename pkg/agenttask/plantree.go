// Package agenttask defines the Job.PlanTree data model (doc90 Group H,
// docs/14-implementation-plan-ph5.md Step 2's H2/H3): a task tree an agent
// coordinator plans against, shared by pkg/mcpserver and pkg/webui without
// either depending on the other. Nothing in this package invokes an LLM or
// populates a tree from a real target yet — that's Step 3's decision engine
// and Phase 6's coordinator.
package agenttask

import (
	"errors"
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
)

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
type PlanNode struct {
	ID         string         `json:"id"`
	Target     string         `json:"target"`
	Detector   string         `json:"detector,omitempty"` // detector name, or a template ID/tag
	Rationale  string         `json:"rationale,omitempty"` // why the coordinator picked this candidate
	Status     PlanNodeStatus `json:"status,omitempty"`
	Confidence Confidence     `json:"confidence,omitempty"`
	Children   []*PlanNode    `json:"children,omitempty"`
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
	Children   []*PlanNode // any non-nil value here is rejected: see ApplyLeafUpdate
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
	return nil
}
