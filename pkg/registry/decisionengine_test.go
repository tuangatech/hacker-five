package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func findLeaf(t *testing.T, tree *agenttask.PlanTree, host string, predicate func(*agenttask.PlanNode) bool) *agenttask.PlanNode {
	t.Helper()
	hostNode := tree.Find("host:" + host)
	require.NotNil(t, hostNode, "expected a host node for %q", host)
	for _, leaf := range hostNode.Children {
		if predicate(leaf) {
			return leaf
		}
	}
	return nil
}

func TestResolve_MatchedTechRule_ProducesPendingLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"}},
	}

	tree := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, leaf, "expected a misconfig leaf for a PHP tech fact")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
	assert.Equal(t, agenttask.ConfidenceMedium, leaf.Confidence)
	assert.Equal(t, "example.test", leaf.Target)
}

func TestResolve_UnmatchedTechFact_ProducesUnresolvedLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "TotallyUnknownStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"}},
	}

	tree := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	require.Len(t, hostNode.Children, 1, "an unmatched TechFact must produce exactly one unresolved leaf, not be dropped")
	assert.Equal(t, agenttask.StatusUnresolved, hostNode.Children[0].Status)
	assert.Empty(t, hostNode.Children[0].Detector, "an unresolved leaf has no dispatched capability")
}

func TestResolve_TemplateTagMatch_ProducesLeafWithTemplateIDAsDetector(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "SomeNicheStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"}},
	}
	index := []templatesync.Entry{
		{ID: "niche-stack-default-creds", Tags: []string{"somenichestack", "default-login"}},
		{ID: "unrelated-template", Tags: []string{"wordpress"}},
	}

	tree := Resolve(result, index)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "niche-stack-default-creds" })
	require.NotNil(t, leaf, "expected a leaf whose Detector is the matched template's ID")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
}

func TestResolve_TemplateTagMatch_CapsLeavesPerTech(t *testing.T) {
	var index []templatesync.Entry
	for i := 0; i < maxTemplateLeavesPerTech+10; i++ {
		index = append(index, templatesync.Entry{ID: "tmpl", Tags: []string{"php"}})
	}
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"}},
	}

	tree := Resolve(result, index)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	templateLeaves := 0
	for _, leaf := range hostNode.Children {
		if leaf.Detector == "tmpl" {
			templateLeaves++
		}
	}
	assert.LessOrEqual(t, templateLeaves, maxTemplateLeavesPerTech)
}

func TestResolve_GroupsMultipleHostsUnderRoot(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "a.example.test", Source: "httpx-tech-detect", Confidence: "medium"},
			{Name: "PHP", Host: "b.example.test", Source: "httpx-tech-detect", Confidence: "medium"},
		},
	}

	tree := Resolve(result, nil)

	require.NotNil(t, tree.Find("host:a.example.test"))
	require.NotNil(t, tree.Find("host:b.example.test"))
	assert.Len(t, tree.Root.Children, 2)
}

func TestResolve_NoTechFacts_ProducesEmptyRoot(t *testing.T) {
	tree := Resolve(&recon.ReconResult{Target: "http://example.test"}, nil)
	assert.Empty(t, tree.Root.Children)
}
