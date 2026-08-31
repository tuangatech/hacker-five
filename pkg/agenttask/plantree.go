// Package agenttask defines the Job.PlanTree data model (doc90 Group H,
// docs/14-implementation-plan-ph5.md Step 2's H2/H3): a task tree an agent
// coordinator plans against, shared by pkg/mcpserver and pkg/webui without
// either depending on the other. Nothing in this package invokes an LLM or
// populates a tree from a real target yet — that's Step 3's decision engine
// and Phase 6's coordinator.
package agenttask

import "errors"

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
	ID         string
	Target     string
	Detector   string // detector name, or a template ID/tag
	Rationale  string // why the coordinator picked this candidate
	Status     PlanNodeStatus
	Confidence Confidence
	Children   []*PlanNode
}

// PlanTree is a Job's task tree.
type PlanTree struct {
	Root *PlanNode
}

// Find walks the tree depth-first for the node with the given ID, or nil if
// none matches.
func (t *PlanTree) Find(nodeID string) *PlanNode {
	if t.Root == nil {
		return nil
	}
	return findNode(t.Root, nodeID)
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
// happens to omit.
type PlanNodePatch struct {
	Status     *PlanNodeStatus
	Confidence *Confidence
	Rationale  *string
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
	ErrShapeChange = errors.New("agenttask: mutation would change the plan tree's shape; only leaf Status/Confidence/Rationale may be updated")
)

// ApplyLeafUpdate finds nodeID and applies patch's non-nil Status/Confidence/
// Rationale fields to it in place. It rejects the mutation, unchanged, if
// patch.Children is non-nil (ErrShapeChange), nodeID doesn't exist
// (ErrNodeNotFound), or the matched node has children (ErrNotLeaf) — doc90
// §2's defense against a hallucinated full-plan rewrite: only a leaf's own
// status/confidence/rationale can ever change after the tree is built.
func (t *PlanTree) ApplyLeafUpdate(nodeID string, patch PlanNodePatch) error {
	if patch.Children != nil {
		return ErrShapeChange
	}
	node := t.Find(nodeID)
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
	return nil
}
