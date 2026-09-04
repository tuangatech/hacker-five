package llmfallback

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
)

func TestPlanFromRecon_ReturnsProposals(t *testing.T) {
	srv := fakeChatServer(t, `{"proposals":[{"target":"example.test","detector":"misconfig","rationale":"combined signal"}]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	result := &recon.ReconResult{Target: "http://example.test", TechStack: []recon.TechFact{{Name: "nginx", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"}}}
	got, cost, err := c.PlanFromRecon(context.Background(), result, nil)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "example.test", got[0].Target)
	assert.Equal(t, "misconfig", got[0].Detector)
	assert.Equal(t, float64(0), cost, "local-only resolution cost = 0")
}

func TestPlanFromRecon_EmptyProposalsIsValid(t *testing.T) {
	srv := fakeChatServer(t, `{"proposals":[]}`)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	got, _, err := c.PlanFromRecon(context.Background(), &recon.ReconResult{Target: "http://example.test"}, nil)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPlanFromReconSummary_OmitsHostNotes(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts:  []recon.HostFact{{Host: "example.test", Source: "dns-resolve", Confidence: "high", Notes: []string{"registrant-email: someone@example.test"}}},
	}
	summary := planFromReconSummary(result)
	assert.NotContains(t, summary, "registrant-email", "HostFact.Notes must not reach the LLM prompt")
	assert.Contains(t, summary, "example.test")
}

func buildMergeTestTree() *agenttask.PlanTree {
	return &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Target: "http://example.test", Children: []*agenttask.PlanNode{
		{ID: "host:example.test", Target: "example.test", Children: []*agenttask.PlanNode{
			{ID: "example.test-leaf-0", Target: "example.test", Detector: "misconfig", Status: agenttask.StatusPending},
		}},
	}}}
}

func TestMergeLLMProposals_MergesValidProposal(t *testing.T) {
	tree := buildMergeTestTree()
	caps := []registry.Capability{{Name: "idor"}}

	n := MergeLLMProposals(tree, []PlanProposal{{Target: "example.test", Detector: "idor", Rationale: "combined signal"}}, caps, nil)

	assert.Equal(t, 1, n)
	hostNode := tree.Find("host:example.test")
	require.Len(t, hostNode.Children, 2)
	leaf := hostNode.Children[1]
	assert.Equal(t, "idor", leaf.Detector)
	assert.Contains(t, leaf.Rationale, ResolvedRationalePrefix)
	assert.Contains(t, leaf.Rationale, "combined signal")
}

func TestMergeLLMProposals_RejectsUnrecognizedTarget(t *testing.T) {
	tree := buildMergeTestTree()
	caps := []registry.Capability{{Name: "idor"}}

	n := MergeLLMProposals(tree, []PlanProposal{{Target: "not-a-real-host.test", Detector: "idor", Rationale: "x"}}, caps, nil)

	assert.Equal(t, 0, n, "a target with no existing host node (never surfaced by registry.Resolve) must never be merged in")
	assert.Nil(t, tree.Find("host:not-a-real-host.test"))
}

func TestMergeLLMProposals_RejectsUnknownDetector(t *testing.T) {
	tree := buildMergeTestTree()

	n := MergeLLMProposals(tree, []PlanProposal{{Target: "example.test", Detector: "totally-made-up-detector", Rationale: "x"}}, nil, nil)

	assert.Equal(t, 0, n, "a hallucinated detector name (not a real capability or template ID) must never be merged in")
}

func TestMergeLLMProposals_AcceptsKnownTemplateID(t *testing.T) {
	tree := buildMergeTestTree()

	n := MergeLLMProposals(tree, []PlanProposal{{Target: "example.test", Detector: "some-real-template-id", Rationale: "x"}}, nil, map[string]bool{"some-real-template-id": true})

	assert.Equal(t, 1, n)
}

func TestMergeLLMProposals_DedupsAgainstExistingLeaf(t *testing.T) {
	tree := buildMergeTestTree() // already has (example.test, misconfig)
	caps := []registry.Capability{{Name: "misconfig"}}

	n := MergeLLMProposals(tree, []PlanProposal{{Target: "example.test", Detector: "misconfig", Rationale: "x"}}, caps, nil)

	assert.Equal(t, 0, n)
	assert.Len(t, tree.Find("host:example.test").Children, 1, "must not duplicate an existing (target, detector) leaf")
}
