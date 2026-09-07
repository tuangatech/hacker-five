package unit

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func TestBandConfidence(t *testing.T) {
	cases := []struct {
		name    string
		percent float64
		want    agenttask.Confidence
	}{
		{"just above high threshold", 80.1, agenttask.ConfidenceHigh},
		{"comfortably high", 95, agenttask.ConfidenceHigh},
		{"exactly the high/medium boundary is medium", 80, agenttask.ConfidenceMedium},
		{"mid-band", 65, agenttask.ConfidenceMedium},
		{"exactly the medium/low boundary is medium", 50, agenttask.ConfidenceMedium},
		{"just below medium/low boundary is low", 49.9, agenttask.ConfidenceLow},
		{"comfortably low", 5, agenttask.ConfidenceLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, agenttask.BandConfidence(tc.percent))
		})
	}
}

// buildTestTree returns:
//
//	root (has children: not a leaf)
//	├── branch (has children: not a leaf)
//	│   └── leaf-a (no children: a leaf)
//	└── leaf-b (no children: a leaf)
func buildTestTree() *agenttask.PlanTree {
	leafA := &agenttask.PlanNode{ID: "leaf-a", Target: "http://a.test", Detector: "misconfig", Status: agenttask.StatusPending}
	branch := &agenttask.PlanNode{ID: "branch", Target: "http://a.test", Children: []*agenttask.PlanNode{leafA}}
	leafB := &agenttask.PlanNode{ID: "leaf-b", Target: "http://b.test", Detector: "idor", Status: agenttask.StatusPending}
	root := &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{branch, leafB}}
	return &agenttask.PlanTree{Root: root}
}

func TestLeaves_FlattensDepthFirst(t *testing.T) {
	tree := buildTestTree()

	got := agenttask.Leaves(tree.Root)
	require.Len(t, got, 2)
	assert.Equal(t, "leaf-a", got[0].ID)
	assert.Equal(t, "leaf-b", got[1].ID)
}

func TestLeaves_SingleNodeTreeIsItsOwnLeaf(t *testing.T) {
	root := &agenttask.PlanNode{ID: "root"}
	got := agenttask.Leaves(root)
	require.Len(t, got, 1)
	assert.Equal(t, "root", got[0].ID)
}

func TestLeaves_NilNodeReturnsNil(t *testing.T) {
	assert.Nil(t, agenttask.Leaves(nil))
}

func TestPlanTree_Find(t *testing.T) {
	tree := buildTestTree()

	found := tree.Find("leaf-a")
	require.NotNil(t, found)
	assert.Equal(t, "http://a.test", found.Target)

	assert.Nil(t, tree.Find("does-not-exist"))
}

func TestPlanTree_ApplyLeafUpdate_Allowed(t *testing.T) {
	tree := buildTestTree()

	status := agenttask.StatusDone
	confidence := agenttask.ConfidenceHigh
	rationale := "confirmed via live probe"

	err := tree.ApplyLeafUpdate("leaf-b", agenttask.PlanNodePatch{
		Status:     &status,
		Confidence: &confidence,
		Rationale:  &rationale,
	})
	require.NoError(t, err)

	leafB := tree.Find("leaf-b")
	require.NotNil(t, leafB)
	assert.Equal(t, agenttask.StatusDone, leafB.Status)
	assert.Equal(t, agenttask.ConfidenceHigh, leafB.Confidence)
	assert.Equal(t, "confirmed via live probe", leafB.Rationale)

	// Sibling leaf is untouched.
	leafA := tree.Find("leaf-a")
	require.NotNil(t, leafA)
	assert.Equal(t, agenttask.StatusPending, leafA.Status)
}

func TestPlanTree_ApplyLeafUpdate_RejectsShapeChange(t *testing.T) {
	tree := buildTestTree()
	originalLeafB := *tree.Find("leaf-b")

	err := tree.ApplyLeafUpdate("leaf-b", agenttask.PlanNodePatch{
		Children: []*agenttask.PlanNode{{ID: "injected"}},
	})

	require.ErrorIs(t, err, agenttask.ErrShapeChange)
	assert.Equal(t, originalLeafB, *tree.Find("leaf-b"), "rejected mutation must leave the node untouched")
}

func TestPlanTree_ApplyLeafUpdate_RejectsNonLeaf(t *testing.T) {
	tree := buildTestTree()

	status := agenttask.StatusDone
	err := tree.ApplyLeafUpdate("branch", agenttask.PlanNodePatch{Status: &status})

	require.ErrorIs(t, err, agenttask.ErrNotLeaf)
	assert.Empty(t, tree.Find("branch").Status, "rejected mutation must leave the node untouched")
}

func TestPlanTree_ApplyLeafUpdate_RejectsUnknownNode(t *testing.T) {
	tree := buildTestTree()

	status := agenttask.StatusDone
	err := tree.ApplyLeafUpdate("does-not-exist", agenttask.PlanNodePatch{Status: &status})

	require.ErrorIs(t, err, agenttask.ErrNodeNotFound)
}

// TestPlanTree_ApplyLeafUpdate_SetsDetector covers the Phase 6 Step 2
// addition: I4's fallback (pkg/llmfallback.LeafDecision.UseExistingTag)
// assigns a detector to a leaf registry.Resolve left StatusUnresolved
// (empty Detector) — this is the concrete case that motivated widening
// PlanNodePatch beyond Status/Confidence/Rationale.
func TestPlanTree_ApplyLeafUpdate_SetsDetector(t *testing.T) {
	tree := buildTestTree()
	unresolved := &agenttask.PlanNode{ID: "leaf-c", Target: "http://c.test", Status: agenttask.StatusUnresolved}
	tree.Root.Children = append(tree.Root.Children, unresolved)

	detector := "misconfig"
	err := tree.ApplyLeafUpdate("leaf-c", agenttask.PlanNodePatch{Detector: &detector})
	require.NoError(t, err)
	assert.Equal(t, "misconfig", tree.Find("leaf-c").Detector)
}

// TestPlanTree_ApplyLeafUpdate_ConcurrentCallsAreRaceFree is the actual
// proof doc15 Step 2's Definition of Done item asks for — run with -race,
// not just asserted correct in a single-goroutine test. Phase 6 Step 2's
// executor dispatches leaves to parallel goroutines (deterministic and
// LLM-assisted tiers alike), each calling ApplyLeafUpdate independently.
func TestPlanTree_ApplyLeafUpdate_ConcurrentCallsAreRaceFree(t *testing.T) {
	root := &agenttask.PlanNode{ID: "root"}
	for i := 0; i < 20; i++ {
		root.Children = append(root.Children, &agenttask.PlanNode{
			ID: fmt.Sprintf("leaf-%d", i), Status: agenttask.StatusPending,
		})
	}
	tree := &agenttask.PlanTree{Root: root}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status := agenttask.StatusDone
			_ = tree.ApplyLeafUpdate(fmt.Sprintf("leaf-%d", i), agenttask.PlanNodePatch{Status: &status})
			tree.AddSpend(0.01)
			_ = tree.Find(fmt.Sprintf("leaf-%d", i))
		}(i)
	}
	wg.Wait()

	for i := 0; i < 20; i++ {
		assert.Equal(t, agenttask.StatusDone, tree.Find(fmt.Sprintf("leaf-%d", i)).Status)
	}
	assert.InDelta(t, 0.20, tree.SpendSoFar(), 0.001)
}

func TestPlanTree_AddSpend_ReportsCeilingExceeded(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}, SpendCeilingUSD: 1.0}

	assert.False(t, tree.AddSpend(0.5))
	assert.False(t, tree.AddSpend(0.4))
	assert.True(t, tree.AddSpend(0.2)) // total 1.1 > 1.0
	assert.InDelta(t, 1.1, tree.SpendSoFar(), 0.001)
}

func TestPlanTree_AddSpend_ZeroCeilingNeverTrips(t *testing.T) {
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}}
	assert.False(t, tree.AddSpend(1000))
}

func TestPriorityForConfidence(t *testing.T) {
	assert.Equal(t, agenttask.PriorityHigh, agenttask.PriorityForConfidence(agenttask.ConfidenceHigh))
	assert.Equal(t, agenttask.PriorityMedium, agenttask.PriorityForConfidence(agenttask.ConfidenceMedium))
	assert.Equal(t, agenttask.PriorityLow, agenttask.PriorityForConfidence(agenttask.ConfidenceLow))
	assert.Equal(t, agenttask.PriorityLow, agenttask.PriorityForConfidence(""), "unset confidence is treated as low")
}

func TestDemoteConfidence(t *testing.T) {
	assert.Equal(t, agenttask.ConfidenceMedium, agenttask.DemoteConfidence(agenttask.ConfidenceHigh))
	assert.Equal(t, agenttask.ConfidenceLow, agenttask.DemoteConfidence(agenttask.ConfidenceMedium))
	assert.Equal(t, agenttask.ConfidenceLow, agenttask.DemoteConfidence(agenttask.ConfidenceLow), "low is the floor")
}

// TestGroupIntoClassNodes covers C7a's structural upgrade (doc16 Phase 7
// Step 3): a flat leaf list under a host node becomes one intermediate node
// per vuln-class, class nodes ordered by descending priority, and Leaves()
// still flattens the whole thing.
func TestGroupIntoClassNodes(t *testing.T) {
	host := &agenttask.PlanNode{ID: "host:h.test", Target: "h.test", Children: []*agenttask.PlanNode{
		{ID: "l1", Target: "h.test", Detector: "misconfig", Status: agenttask.StatusPending, Priority: agenttask.PriorityLow},
		{ID: "l2", Target: "h.test", Detector: "idor", Status: agenttask.StatusPending, Priority: agenttask.PriorityHigh},
		{ID: "l3", Target: "h.test", Detector: "misconfig", Status: agenttask.StatusPending, Priority: agenttask.PriorityMedium},
		{ID: "l4", Target: "h.test", Status: agenttask.StatusUnresolved},
	}}

	classOf := func(n *agenttask.PlanNode) string {
		if n.Status == agenttask.StatusUnresolved {
			return "recon-followup"
		}
		return n.Detector
	}
	agenttask.GroupIntoClassNodes(host, classOf)

	require.Len(t, host.Children, 3, "one node per distinct class")
	assert.Equal(t, "idor", host.Children[0].Class, "highest-priority class first")
	assert.Equal(t, agenttask.ClassNodeID("h.test", "idor"), host.Children[0].ID)
	assert.Equal(t, agenttask.PriorityHigh, host.Children[0].Priority, "class node priority is its max leaf priority")

	// misconfig node holds both misconfig leaves, in input order.
	misconfig := host.Children[1]
	assert.Equal(t, "misconfig", misconfig.Class)
	require.Len(t, misconfig.Children, 2)
	assert.Equal(t, "l1", misconfig.Children[0].ID)
	assert.Equal(t, "l3", misconfig.Children[1].ID)

	// Leaves() is unchanged for consumers that only want leaves.
	leaves := agenttask.Leaves(host)
	require.Len(t, leaves, 4)

	// Idempotent — a second call is a no-op.
	agenttask.GroupIntoClassNodes(host, classOf)
	require.Len(t, host.Children, 3)
	require.Len(t, agenttask.Leaves(host), 4)
}

// TestAttachLeaf covers the post-construction path (llmfallback.MergeLLMProposals):
// a leaf added after the tree was grouped lands under the right class node,
// creating it if absent.
func TestAttachLeaf(t *testing.T) {
	host := &agenttask.PlanNode{ID: "host:h.test", Target: "h.test", Children: []*agenttask.PlanNode{
		{ID: "c-misconfig", Target: "h.test", Class: "misconfig", Priority: agenttask.PriorityLow, Children: []*agenttask.PlanNode{
			{ID: "l1", Target: "h.test", Detector: "misconfig", Status: agenttask.StatusPending, Priority: agenttask.PriorityLow},
		}},
	}}

	// Same class as an existing node -> appended there, node priority bumped.
	agenttask.AttachLeaf(host, &agenttask.PlanNode{ID: "l2", Target: "h.test", Detector: "misconfig", Status: agenttask.StatusPending, Priority: agenttask.PriorityHigh}, "misconfig")
	require.Len(t, host.Children, 1)
	require.Len(t, host.Children[0].Children, 2)
	assert.Equal(t, agenttask.PriorityHigh, host.Children[0].Priority)

	// New class -> new class node appended.
	agenttask.AttachLeaf(host, &agenttask.PlanNode{ID: "l3", Target: "h.test", Detector: "idor", Status: agenttask.StatusPending}, "idor")
	require.Len(t, host.Children, 2)
	assert.Equal(t, "idor", host.Children[1].Class)
	assert.Equal(t, agenttask.ClassNodeID("h.test", "idor"), host.Children[1].ID)

	assert.Len(t, agenttask.Leaves(host), 3)
}

// TestApplyLeafUpdate_VetoedStatus confirms a leaf can be flipped to
// StatusVetoed (C7b's "drop" verdict) through the same guarded mutation API.
func TestApplyLeafUpdate_VetoedStatus(t *testing.T) {
	tree := buildTestTree()
	vetoed := agenttask.StatusVetoed
	reason := "plausibility veto (dropped): premise is an SPA catch-all"
	require.NoError(t, tree.ApplyLeafUpdate("leaf-b", agenttask.PlanNodePatch{Status: &vetoed, Rationale: &reason}))
	assert.Equal(t, agenttask.StatusVetoed, tree.Find("leaf-b").Status)
	assert.Equal(t, reason, tree.Find("leaf-b").Rationale)
}
