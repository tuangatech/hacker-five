package orchestrator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
)

// reconResultOpenRestyOnSameHost fans out to idor+authbypass+misconfig
// (pkg/registry's techRules "openresty" entry) for the same host
// reconResultOneLiveHost() already seeded — misconfig collides with the
// existing baseline leaf's dispatch key, idor/authbypass are genuinely new.
func reconResultOpenRestyOnSameHost() *recon.ReconResult {
	return &recon.ReconResult{
		Target:    "example.test",
		TechStack: []recon.TechFact{{Name: "OpenResty", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"}},
	}
}

// reconResultSecondHost describes a host reconResultOneLiveHost() never
// mentions at all — exercises mergeReconRefresh's "brand new host" path.
func reconResultSecondHost() *recon.ReconResult {
	return &recon.ReconResult{
		Target:    "second.example.test",
		Endpoints: []recon.EndpointFact{{URL: "http://second.example.test/", StatusCode: 200, Source: "httpx"}},
	}
}

func TestMergeReconRefresh_NilTreeOrFresh_NoOp(t *testing.T) {
	if got := mergeReconRefresh(nil, reconResultSecondHost(), nil); got != 0 {
		t.Fatalf("got %d, want 0 for a nil tree", got)
	}
	tree, _ := registry.Resolve(reconResultOneLiveHost(), nil)
	if got := mergeReconRefresh(tree, nil, nil); got != 0 {
		t.Fatalf("got %d, want 0 for a nil fresh result", got)
	}
}

func TestMergeReconRefresh_NewHost_AttachesWholeSubtree(t *testing.T) {
	tree, _ := registry.Resolve(reconResultOneLiveHost(), nil)
	before := len(agenttask.Leaves(tree.Root))

	merged := mergeReconRefresh(tree, reconResultSecondHost(), nil)
	if merged == 0 {
		t.Fatal("got 0 merged, want at least 1 leaf for the newly discovered host")
	}

	hostNode := tree.Find("host:second.example.test")
	if hostNode == nil {
		t.Fatal("want a new host node for second.example.test to have been attached under root")
	}
	after := len(agenttask.Leaves(tree.Root))
	if after != before+merged {
		t.Fatalf("got %d total leaves after merge, want %d (before=%d + merged=%d)", after, before+merged, before, merged)
	}

	// The pre-existing host's own leaves must be untouched.
	original := tree.Find("host:example.test")
	if original == nil || len(agenttask.Leaves(original)) != before {
		t.Fatalf("existing host's leaves changed — want the original %d leaf/leaves left exactly as-is", before)
	}
}

func TestMergeReconRefresh_ExistingHost_AddsOnlyGenuinelyNewLeaves(t *testing.T) {
	tree, _ := registry.Resolve(reconResultOneLiveHost(), nil)
	hostNode := tree.Find("host:example.test")
	if hostNode == nil {
		t.Fatal("test fixture assumption broke: no host node for example.test")
	}
	before := len(agenttask.Leaves(hostNode))

	merged := mergeReconRefresh(tree, reconResultOpenRestyOnSameHost(), nil)
	if merged == 0 {
		t.Fatal("got 0 merged, want idor/authbypass leaves to be genuinely new (misconfig collides, those don't)")
	}

	after := len(agenttask.Leaves(hostNode))
	if after != before+merged {
		t.Fatalf("got %d leaves under the host after merge, want %d (before=%d + merged=%d)", after, before+merged, before, merged)
	}

	var sawIdor, sawAuthbypass bool
	for _, leaf := range agenttask.Leaves(hostNode) {
		switch leaf.Detector {
		case "idor":
			sawIdor = true
		case "authbypass":
			sawAuthbypass = true
		}
	}
	if !sawIdor || !sawAuthbypass {
		t.Fatalf("want both a new idor and authbypass leaf merged in, got idor=%v authbypass=%v", sawIdor, sawAuthbypass)
	}

	// Re-merging the identical fresh result a second time must be a true
	// no-op — every leaf it would produce now already exists.
	if again := mergeReconRefresh(tree, reconResultOpenRestyOnSameHost(), nil); again != 0 {
		t.Fatalf("got %d merged on a second identical recon.refresh, want 0 (idempotent)", again)
	}
}

// TestRun_ReconRefresh_MergesNewLeafAndItBecomesDispatchable is the
// end-to-end proof: a recon.refresh action that surfaces a genuinely new
// leaf makes that leaf immediately dispatchable via a later scan.leaf call
// in the same run — LT-160 item 2's whole point (docs/follow-up.md).
type sequenceRecon struct {
	results []*recon.ReconResult
	calls   int
}

func (s *sequenceRecon) Run(_ context.Context, _ string, _ recon.Depth) (*recon.ReconResult, error) {
	i := s.calls
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	s.calls++
	return s.results[i], nil
}

func TestRun_ReconRefresh_MergesNewLeafAndItBecomesDispatchable(t *testing.T) {
	refresh := llmfallback.Action{Kind: "recon.refresh", Params: json.RawMessage(`{"target":"example.test"}`)}
	client := &fakeLLMClient{actions: []llmfallback.Action{refresh, {Kind: "stop"}}}

	result, err := Run(context.Background(), Config{
		Target:        "example.test",
		Recon:         &sequenceRecon{results: []*recon.ReconResult{reconResultOneLiveHost(), reconResultOpenRestyOnSameHost()}},
		Client:        client,
		MinIterations: 1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.History) != 1 {
		t.Fatalf("got %d history entries, want 1", len(result.History))
	}
	if !strings.Contains(result.History[0].ResultSummary, "new leaf") {
		t.Fatalf("got summary %q, want it to report merged new leaf(s)", result.History[0].ResultSummary)
	}

	hostNode := result.Tree.Find("host:example.test")
	if hostNode == nil {
		t.Fatal("want the seed host node to still exist")
	}
	var sawIdor bool
	for _, leaf := range agenttask.Leaves(hostNode) {
		if leaf.Detector == "idor" {
			sawIdor = true
		}
	}
	if !sawIdor {
		t.Fatal("want the recon.refresh-discovered idor leaf to now be part of the live tree")
	}
}
