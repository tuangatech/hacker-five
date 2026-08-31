package unit

import (
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
