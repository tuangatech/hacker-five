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

func TestResolve_UnmatchedTechFact_RationaleIncludesCorrelatedEndpoint(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "TotallyUnknownStack", Host: "example.test", Source: "fingerprint-header", Confidence: "medium"}},
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/graphql", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
			{URL: "http://other-host.test/unrelated", Method: "GET", StatusCode: 200, Source: "wave3-crawl"}, // different host — must not be pulled in
		},
	}

	tree := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	require.Len(t, hostNode.Children, 1)
	rationale := hostNode.Children[0].Rationale
	assert.Contains(t, rationale, "matched no registry capability or template tag")
	assert.Contains(t, rationale, "observed on this host:")
	assert.Contains(t, rationale, "GET /graphql (200)")
	assert.NotContains(t, rationale, "other-host.test", "an endpoint on a different host must not be correlated in")
}

func TestResolve_UnmatchedTechFact_NoEndpoints_RationaleUnchanged(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "TotallyUnknownStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"}},
	}

	tree := Resolve(result, nil)

	rationale := tree.Find("host:example.test").Children[0].Rationale
	assert.NotContains(t, rationale, "observed on this host:", "no real endpoints to correlate means no suffix, not an empty one")
}

func TestCorrelatedEndpoints_FiltersByHostAndCaps(t *testing.T) {
	endpoints := []recon.EndpointFact{
		{URL: "http://a.test/1", Method: "GET"},
		{URL: "http://a.test/2", Method: "GET"},
		{URL: "http://a.test/3", Method: "GET"},
		{URL: "http://a.test/4", Method: "GET"}, // beyond the cap
		{URL: "http://b.test/1", Method: "GET"}, // different host
	}
	got := correlatedEndpoints("a.test", endpoints)
	require.Len(t, got, maxCorrelatedEndpoints)
	for _, ep := range got {
		assert.Contains(t, ep.URL, "a.test")
	}
}

func TestDescribeEndpoints_TruncatesLongPath(t *testing.T) {
	longPath := "/api/" + repeatString("x", 100)
	got := describeEndpoints([]recon.EndpointFact{{URL: "http://example.test" + longPath, Method: "GET", StatusCode: 200}})
	assert.LessOrEqual(t, len(got), len("GET  (200)")+63, "path must be truncated, not embedded in full")
	assert.Contains(t, got, "...")
}

func repeatString(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
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
