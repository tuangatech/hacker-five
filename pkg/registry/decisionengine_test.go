package registry

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func findLeaf(t *testing.T, tree *agenttask.PlanTree, host string, predicate func(*agenttask.PlanNode) bool) *agenttask.PlanNode {
	t.Helper()
	for _, leaf := range hostLeaves(t, tree, host) {
		if predicate(leaf) {
			return leaf
		}
	}
	return nil
}

// hostLeaves flattens a host node's leaves — since C7a (doc16 Phase 7 Step
// 3) registry.Resolve nests leaves one level deeper under per-vuln-class
// intermediate nodes, so hostNode.Children are class nodes, not leaves.
func hostLeaves(t *testing.T, tree *agenttask.PlanTree, host string) []*agenttask.PlanNode {
	t.Helper()
	hostNode := tree.Find("host:" + host)
	require.NotNil(t, hostNode, "expected a host node for %q", host)
	return agenttask.Leaves(hostNode)
}

func TestResolve_MatchedTechRule_ProducesPendingLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"}},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, leaf, "expected a misconfig leaf for a PHP tech fact")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
	assert.Equal(t, agenttask.ConfidenceMedium, leaf.Confidence)
	assert.Equal(t, "http://example.test", leaf.Target, "LT-93: a leaf's Target is the scheme://host recon observed, not the bare hostname")
}

// TestResolve_GroupsLeavesUnderVulnClassNodes covers C7a (doc16 Phase 7
// Step 3): a host node's direct children are now per-vuln-class intermediate
// nodes, not leaves; leaves nest one level deeper and Leaves() still
// flattens. Each leaf carries a dispatch Priority derived from its
// confidence band.
func TestResolve_GroupsLeavesUnderVulnClassNodes(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"},
			{Name: "TotallyUnknownStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	for _, cn := range hostNode.Children {
		assert.NotEmpty(t, cn.Class, "a host node's direct child is a vuln-class node with Class set")
		assert.NotEmpty(t, cn.Children, "a class node holds leaves")
		assert.Equal(t, agenttask.ClassNodeID("example.test", cn.Class), cn.ID)
	}

	classes := map[string]bool{}
	for _, cn := range hostNode.Children {
		classes[cn.Class] = true
	}
	assert.True(t, classes["misconfig"], "PHP -> misconfig class node")
	assert.True(t, classes["recon-followup"], "unmatched fact -> recon-followup class node")

	// Class nodes are ordered by descending priority: misconfig (from a
	// high-confidence fact) outranks recon-followup (low).
	assert.Equal(t, "misconfig", hostNode.Children[0].Class)

	misconfigLeaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, misconfigLeaf)
	assert.Equal(t, agenttask.PriorityHigh, misconfigLeaf.Priority, "a high-confidence leaf gets high dispatch priority")
}

// TestResolve_UnresolvedLeaf_DeadEndPriority covers LT-70: a leaf with
// nothing to dispatch (an unmatched tech fact) must sort below every real
// class node so it can't push actual scan work later in start order.
func TestResolve_UnresolvedLeaf_DeadEndPriority(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"},
			{Name: "TotallyUnknownStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"},
		},
	}
	tree, _ := Resolve(result, nil)

	unresolved := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Status == agenttask.StatusUnresolved })
	require.NotNil(t, unresolved)
	assert.Equal(t, agenttask.PriorityDeadEnd, unresolved.Priority,
		"an unresolved leaf sorts below every dispatchable class even when its source fact was high-confidence")

	misconfigLeaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, misconfigLeaf)
	assert.Greater(t, misconfigLeaf.Priority, unresolved.Priority)
}

func TestResolve_UnmatchedTechFact_ProducesUnresolvedLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "TotallyUnknownStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"}},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	require.Len(t, agenttask.Leaves(hostNode), 1, "an unmatched TechFact must produce exactly one unresolved leaf, not be dropped")
	assert.Equal(t, agenttask.StatusUnresolved, agenttask.Leaves(hostNode)[0].Status)
	assert.Empty(t, agenttask.Leaves(hostNode)[0].Detector, "an unresolved leaf has no dispatched capability")
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

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	require.Len(t, agenttask.Leaves(hostNode), 1)
	rationale := agenttask.Leaves(hostNode)[0].Rationale
	assert.Contains(t, rationale, "matched no registry capability or template tag")
	assert.Contains(t, rationale, "observed on this host:")
	assert.Contains(t, rationale, "GET /graphql (200)")
	assert.NotContains(t, rationale, "other-host.test", "an endpoint on a different host must not be correlated in")
}

// TestResolve_UnmatchedTechFact_PopulatesLeafContext confirms P2-2's second
// return value carries the originating TechFact (and correlated endpoints)
// for an unresolved leaf, keyed by leaf ID — pkg/llmfallback.ResolveLeaf
// reads this instead of regexing it back out of leaf.Rationale.
func TestResolve_UnmatchedTechFact_PopulatesLeafContext(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "TotallyUnknownStack", Host: "example.test", Source: "fingerprint-header", Confidence: "medium"}},
		Endpoints: []recon.EndpointFact{{URL: "http://example.test/graphql", Method: "GET", StatusCode: 200, Source: "wave3-crawl"}},
	}

	tree, leafContexts := Resolve(result, nil)

	leaf := agenttask.Leaves(tree.Find("host:example.test"))[0]
	require.Equal(t, agenttask.StatusUnresolved, leaf.Status)
	ctx, ok := leafContexts[leaf.ID]
	require.True(t, ok, "expected a LeafContext entry for the unresolved leaf's ID")
	require.NotNil(t, ctx.TechFact)
	assert.Equal(t, "TotallyUnknownStack", ctx.TechFact.Name)
	require.Len(t, ctx.Endpoints, 1)
	assert.Equal(t, "http://example.test/graphql", ctx.Endpoints[0].URL)
	assert.Nil(t, ctx.Port, "a tech-fact-driven leaf must not carry a Port context")
}

// TestResolve_UnmatchedTechFact_NoLeafContextForResolvedLeaf confirms the
// map only ever carries entries for StatusUnresolved leaves — a resolved
// (Pending) leaf never reaches pkg/llmfallback.ResolveLeaf, so it has no
// reason to appear here.
func TestResolve_UnmatchedTechFact_NoLeafContextForResolvedLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "GraphQL", Host: "example.test", Source: "fingerprint-header", Confidence: "medium"}},
	}

	tree, leafContexts := Resolve(result, nil)

	leaf := agenttask.Leaves(tree.Find("host:example.test"))[0]
	require.Equal(t, agenttask.StatusPending, leaf.Status, "GraphQL matches a techRule, so this leaf resolves deterministically")
	_, ok := leafContexts[leaf.ID]
	assert.False(t, ok, "a resolved leaf must not appear in leafContexts")
}

func TestResolve_UnmatchedTechFact_NoEndpoints_RationaleUnchanged(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "TotallyUnknownStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"}},
	}

	tree, _ := Resolve(result, nil)

	rationale := agenttask.Leaves(tree.Find("host:example.test"))[0].Rationale
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

	tree, _ := Resolve(result, index)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "niche-stack-default-creds" })
	require.NotNil(t, leaf, "expected a leaf whose Detector is the matched template's ID")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
}

// F3 (LT-67, docs/follow-up.md): a response-body secret/exposure template
// is dropped for a host recon shows serving no app-generated content, while
// every other template family for the same tech is kept.
func TestResolve_BodyGrepSecretTemplate_SuppressedOnStaticHost(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "shopify-app-secret", Tags: []string{"shopify", "token", "exposure", "vuln"}},
		{ID: "shopify-detect", Tags: []string{"shopify", "detect", "tech"}},
	}
	base := func() *recon.ReconResult {
		return &recon.ReconResult{
			Target:    "http://example.test",
			TechStack: []recon.TechFact{{Name: "Shopify", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"}},
		}
	}

	// catch-all wall on the host -> secret grep suppressed, control kept.
	walled := base()
	walled.UniformResponses = []recon.UniformResponseFact{{Host: "example.test", Kind: "catchall"}}
	tree, _ := Resolve(walled, index)
	assert.Nil(t, findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "shopify-app-secret" }),
		"a body-grep secret template must not be planned against a catch-all host")
	assert.NotNil(t, findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "shopify-detect" }),
		"a non-secret template for the same tech is unaffected")

	// AppSurface "none" -> same suppression.
	noApp := base()
	noApp.AppSurface = &recon.AppSurfaceFact{Verdict: "none", Reason: "nothing served real content"}
	tree, _ = Resolve(noApp, index)
	assert.Nil(t, findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "shopify-app-secret" }))

	// only sub-floor 2xx bodies on the host -> suppression.
	tiny := base()
	tiny.Endpoints = []recon.EndpointFact{{URL: "http://example.test/", Method: "GET", StatusCode: 200, BodyLen: 700, Source: "wave3-common-path-probe"}}
	tree, _ = Resolve(tiny, index)
	assert.Nil(t, findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "shopify-app-secret" }))
}

// F3: the same secret template is kept when recon shows real app content —
// the gate is a targeted suppressor, not a blanket drop (LT-67's <5%-FP
// "err toward emitting" note).
func TestResolve_BodyGrepSecretTemplate_KeptOnDynamicHost(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "shopify-app-secret", Tags: []string{"shopify", "token", "exposure", "vuln"}},
	}
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "Shopify", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"}},
		Endpoints: []recon.EndpointFact{{URL: "http://example.test/", Method: "GET", StatusCode: 200, BodyLen: 8192, Source: "wave3-common-path-probe"}},
	}
	tree, _ := Resolve(result, index)
	assert.NotNil(t, findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "shopify-app-secret" }),
		"a body-grep secret template is planned normally against a host serving real content")
}

// TestResolve_BodyGrepSecretTemplate_OtherHostWallDoesNotSuppress guards
// LT-140: a catch-all wall recorded on one host in a multi-host recon run
// must not suppress hostServesDynamicContent's verdict for a *different*
// host that plainly served real content — before the fix, a single
// first-host-wins UniformResponse fact (or its Host=="" wildcard fallback)
// could bleed a wall verdict onto a host it was never actually recorded
// against.
func TestResolve_BodyGrepSecretTemplate_OtherHostWallDoesNotSuppress(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "shopify-app-secret", Tags: []string{"shopify", "token", "exposure", "vuln"}},
	}
	result := &recon.ReconResult{
		Target:           "http://real.example.test",
		TechStack:        []recon.TechFact{{Name: "Shopify", Host: "real.example.test", Source: "httpx-tech-detect", Confidence: "high"}},
		Endpoints:        []recon.EndpointFact{{URL: "http://real.example.test/", Method: "GET", StatusCode: 200, BodyLen: 8192, Source: "wave3-common-path-probe"}},
		UniformResponses: []recon.UniformResponseFact{{Host: "walled.example.test", Kind: "catchall"}},
	}
	tree, _ := Resolve(result, index)
	assert.NotNil(t, findLeaf(t, tree, "real.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "shopify-app-secret" }),
		"a wall recorded against a different host must not suppress this host's own secret-grep leaf")
}

// TestResolve_SpecAuthRequiredRoute_ProducesAuthbypassLeaf covers LT-90: a
// parameterless api-spec route the OpenAPI doc marks auth-required flows
// through SuggestAuthBypassPathsFromRecon into an authbypass leaf.
func TestResolve_SpecAuthRequiredRoute_ProducesAuthbypassLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://api.example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://api.example.test/identity/api/v2/user/dashboard", Method: "GET", Source: "api-spec", AuthRequired: true, Confidence: "low"},
			{URL: "http://api.example.test/identity/api/v2/vehicle/{vehicleId}/location", Method: "GET", Source: "api-spec", AuthRequired: true, Confidence: "low"},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "api.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "authbypass" })
	require.NotNil(t, leaf, "a spec-declared auth-required route must yield an authbypass leaf")
}

// TestResolve_IdorEndpointCandidates_FanOutPerCandidate covers LT-91: every
// distinct ID-shaped recon endpoint becomes its own idor leaf carrying that
// {{id}} template, and the bare tech-capability idor leaf is dropped once a
// runnable per-candidate leaf exists.
func TestResolve_IdorEndpointCandidates_FanOutPerCandidate(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://api.example.test",
		// OpenResty matches the "idor" capability rule -> a bare idor leaf; the
		// three spec routes below each yield one endpoint-driven idor leaf.
		TechStack: []recon.TechFact{{Name: "OpenResty", Host: "api.example.test", Source: "httpx-tech-detect", Confidence: "medium"}},
		Endpoints: []recon.EndpointFact{
			{URL: "http://api.example.test/workshop/api/shop/orders/{order_id}", Method: "GET", Source: "api-spec", Confidence: "low"},
			{URL: "http://api.example.test/identity/api/v2/user/videos/{video_id}", Method: "GET", Source: "api-spec", Confidence: "low"},
			{URL: "http://api.example.test/community/api/v2/community/posts/{postId}", Method: "GET", Source: "api-spec", Confidence: "low"},
		},
	}

	tree, _ := Resolve(result, nil)

	var idorLeaves []*agenttask.PlanNode
	for _, leaf := range hostLeaves(t, tree, "api.example.test") {
		if leaf.Detector == "idor" {
			idorLeaves = append(idorLeaves, leaf)
		}
	}
	require.Len(t, idorLeaves, 3, "one idor leaf per ID-shaped endpoint candidate, bare capability leaf dropped")
	got := map[string]bool{}
	for _, leaf := range idorLeaves {
		assert.NotEmpty(t, leaf.EndpointTemplate, "each fanned-out idor leaf carries its own {{id}} template")
		got[leaf.EndpointTemplate] = true
	}
	assert.True(t, got["/workshop/api/shop/orders/{{id}}"])
	assert.True(t, got["/identity/api/v2/user/videos/{{id}}"])
	assert.True(t, got["/community/api/v2/community/posts/{{id}}"])
}

// TestResolve_IdorEndpointCandidates_UUIDCandidateCarriesSeed covers LT-95
// (docs/follow-up.md): a UUID-shaped candidate observed with a real,
// concrete value (an authenticated crawl, not a bare spec placeholder) must
// carry that seed on its leaf so planexec/scanner.Engine can dispatch
// idor.RandomUUIDStrategy instead of a numeric range that could never reach
// it. The sibling int-shaped candidate must not.
func TestResolve_IdorEndpointCandidates_UUIDCandidateCarriesSeed(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://api.example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://api.example.test/vehicle/1b4e28ba-2fa1-11d2-883f-0016d3cca427/location", Method: "GET", Source: "wave3-crawl", Confidence: "medium"},
			{URL: "http://api.example.test/orders/123", Method: "GET", Source: "wave3-crawl", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, nil)

	byTemplate := map[string]*agenttask.PlanNode{}
	for _, leaf := range hostLeaves(t, tree, "api.example.test") {
		if leaf.Detector == "idor" {
			byTemplate[leaf.EndpointTemplate] = leaf
		}
	}
	uuidLeaf := byTemplate["/vehicle/{{id}}/location"]
	require.NotNil(t, uuidLeaf)
	assert.True(t, uuidLeaf.EndpointIDIsUUID)
	assert.Equal(t, "1b4e28ba-2fa1-11d2-883f-0016d3cca427", uuidLeaf.EndpointSeedID)

	intLeaf := byTemplate["/orders/{{id}}"]
	require.NotNil(t, intLeaf)
	assert.False(t, intLeaf.EndpointIDIsUUID)
	assert.Empty(t, intLeaf.EndpointSeedID)
}

// TestResolve_IdorCapabilityOnly_KeepsBareLeaf: a host with a tech-matched
// idor capability but zero ID-shaped recon endpoints keeps its single bare
// idor leaf (nothing to fan out).
func TestResolve_IdorCapabilityOnly_KeepsBareLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "OpenResty", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"}},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "idor" })
	require.NotNil(t, leaf, "the bare tech-capability idor leaf stays when there is no endpoint candidate to fan out")
	assert.Empty(t, leaf.EndpointTemplate)
}

// TestResolve_LeafTarget_CarriesSchemeAndPort covers LT-93: a leaf's Target
// is the scheme://host[:port] recon observed (from a probed endpoint URL),
// not the bare hostname — the executor hands it straight to the scanner
// engine as a request base, so a bare host produced "host/path" and every
// request failed.
func TestResolve_LeafTarget_CarriesSchemeAndPort(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://127.0.0.1:8888",
		Endpoints: []recon.EndpointFact{
			{URL: "http://127.0.0.1:8888/workshop/api/shop/orders/{order_id}", Method: "GET", Source: "api-spec", Confidence: "low"},
			{URL: "http://127.0.0.1:8888/identity/api/v2/user/dashboard", Method: "GET", Source: "api-spec", AuthRequired: true, Confidence: "low"},
		},
	}

	tree, _ := Resolve(result, nil)

	for _, leaf := range hostLeaves(t, tree, "127.0.0.1") {
		assert.Equal(t, "http://127.0.0.1:8888", leaf.Target,
			"every dispatchable leaf's Target is the observed scheme://host:port, leaf %s", leaf.ID)
	}
}

func TestReconHostBaseURL(t *testing.T) {
	cases := []struct {
		name string
		host string
		res  *recon.ReconResult
		want string
	}{
		{
			name: "from a probed endpoint URL (scheme + non-default port)",
			host: "127.0.0.1",
			res:  &recon.ReconResult{Endpoints: []recon.EndpointFact{{URL: "http://127.0.0.1:8888/a"}}},
			want: "http://127.0.0.1:8888",
		},
		{
			name: "from result.Target when no endpoint names the host",
			host: "example.test",
			res:  &recon.ReconResult{Target: "https://example.test"},
			want: "https://example.test",
		},
		{
			name: "from the port list — 443 wins as https",
			host: "svc.example",
			res:  &recon.ReconResult{Hosts: []recon.HostFact{{Host: "svc.example", Ports: []recon.PortFact{{Port: 22}, {Port: 443}}}}},
			want: "https://svc.example",
		},
		{
			name: "from the port list — bare 8080 keeps its port",
			host: "svc.example",
			res:  &recon.ReconResult{Hosts: []recon.HostFact{{Host: "svc.example", Ports: []recon.PortFact{{Port: 8080}}}}},
			want: "http://svc.example:8080",
		},
		{
			name: "no signal at all — https fallback",
			host: "lonely.example",
			res:  &recon.ReconResult{},
			want: "https://lonely.example",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, reconHostBaseURL(tc.host, tc.res))
		})
	}
}

// TestResolve_EndpointDrivenAuthbypassLeaf_CarriesProtectedPaths covers
// LT-94: the endpoint-driven authbypass leaf stashes the recon-derived
// protected paths on the PlanNode so the plan→execute path is self-sufficient
// without the caller pre-filling baseCfg.
func TestResolve_EndpointDrivenAuthbypassLeaf_CarriesProtectedPaths(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://api.example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://api.example.test/identity/api/v2/user/dashboard", Method: "GET", Source: "api-spec", AuthRequired: true, Confidence: "low"},
			{URL: "http://api.example.test/community/api/v2/community/home", Method: "GET", Source: "api-spec", AuthRequired: true, Confidence: "low"},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "api.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "authbypass" })
	require.NotNil(t, leaf)
	assert.ElementsMatch(t, []string{
		"/community/api/v2/community/home",
		"/identity/api/v2/user/dashboard",
	}, leaf.ProtectedPaths, "the leaf carries the recon-derived protected paths")
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

	tree, _ := Resolve(result, index)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	templateLeaves := 0
	for _, leaf := range agenttask.Leaves(hostNode) {
		if leaf.Detector == "tmpl" {
			templateLeaves++
		}
	}
	assert.LessOrEqual(t, templateLeaves, maxTemplateLeavesPerTech)
}

// TestResolve_MultiWordTechName_MatchesSingleWordTag guards the
// 2026-09-04 fix: a real target's "Yoast SEO Premium" and "LiteSpeed
// Cache" TechFacts matched zero templates before this fix, despite the
// synced corpus holding real CVE templates tagged "yoast"/"litespeed" for
// exactly those plugins — the old whole-string-equality check could never
// match a multi-word tech name against a single-word tag.
func TestResolve_MultiWordTechName_MatchesSingleWordTag(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "yoast-fpd", Tags: []string{"wordpress", "yoast", "exposure"}},
		{ID: "litespeed-cache-xss", Tags: []string{"wordpress", "litespeed", "xss"}},
		{ID: "unrelated-template", Tags: []string{"wordpress"}},
	}
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "Yoast SEO Premium:28.4", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
			{Name: "LiteSpeed Cache", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, index)

	yoastLeaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "yoast-fpd" })
	assert.NotNil(t, yoastLeaf, "expected the yoast-tagged template to match \"Yoast SEO Premium:28.4\"")
	litespeedLeaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "litespeed-cache-xss" })
	assert.NotNil(t, litespeedLeaf, "expected the litespeed-tagged template to match \"LiteSpeed Cache\"")
}

// TestNormalizedTechWords_ShortGenericTag_DoesNotSpuriouslyMatch guards
// against the word-boundary fix over-matching: a short substring
// ("wp") that's textually contained inside a longer word ("wordpress")
// must not be treated as a match — only a whole word counts.
func TestNormalizedTechWords_ShortGenericTag_DoesNotSpuriouslyMatch(t *testing.T) {
	words := normalizedTechWords("WordPress Block Editor")
	assert.False(t, words["wp"], `"wp" must not match merely because it's a substring of "wordpress"`)
	assert.True(t, words["wordpress"])
	assert.True(t, words["block"])
	assert.True(t, words["editor"])
}

func TestResolve_GroupsMultipleHostsUnderRoot(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "a.example.test", Source: "httpx-tech-detect", Confidence: "medium"},
			{Name: "PHP", Host: "b.example.test", Source: "httpx-tech-detect", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, nil)

	require.NotNil(t, tree.Find("host:a.example.test"))
	require.NotNil(t, tree.Find("host:b.example.test"))
	assert.Len(t, tree.Root.Children, 2)
}

func TestResolve_NoTechFacts_ProducesEmptyRoot(t *testing.T) {
	tree, _ := Resolve(&recon.ReconResult{Target: "http://example.test"}, nil)
	assert.Empty(t, tree.Root.Children)
}

// TestResolve_NonActionableTech_ProducesNoLeafOrHostNode guards P0-4/P0-5
// (2026-09-04): a host whose only TechFacts are transport/posture/hosting-
// brand facts must contribute nothing to the tree — not an unresolved
// leaf, not even an empty host node.
func TestResolve_NonActionableTech_ProducesNoLeafOrHostNode(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "HTTP/3", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"},
			{Name: "HSTS", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"},
			{Name: "Hostinger CDN", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
			{Name: "WordPress Block Editor", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, nil)

	assert.Empty(t, tree.Root.Children, "a host with only non-actionable tech facts must produce no host node")
}

// TestResolve_NonActionableTech_MixedWithReal_OnlyRealSurvives confirms the
// denylist filters per-fact, not per-host: a real, actionable fact on the
// same host as denylisted ones still produces its leaf.
func TestResolve_NonActionableTech_MixedWithReal_OnlyRealSurvives(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "HTTP/3", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"},
			{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	require.Len(t, agenttask.Leaves(hostNode), 1, "only the PHP fact should produce a leaf")
	assert.Equal(t, "misconfig", agenttask.Leaves(hostNode)[0].Detector)
}

// TestResolve_GoogleAnalytics_ProducesNoLeaf is LT-10's (docs/follow-up.md)
// regression guard: a client-side analytics tag names no scannable server
// surface — left in, it matched 3 keyword-collision "analytics"-tagged
// templates. Now on the nonActionableTech denylist.
func TestResolve_GoogleAnalytics_ProducesNoLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "Google Analytics", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"},
		},
	}
	index := []templatesync.Entry{
		{ID: "piwik-unauthenticated-access", Tags: []string{"analytics", "piwik"}, Severity: "high"},
	}

	tree, _ := Resolve(result, index)

	assert.Nil(t, tree.Find("host:example.test"), "a Google Analytics fact must produce no leaf and no host node")
}

// TestResolve_DuplicateCapabilityLeaves_Deduped guards P0-4: four distinct
// TechFacts that all map to the misconfig capability must collapse to one
// misconfig leaf, and the first fact in recon order supplies its rationale.
func TestResolve_DuplicateCapabilityLeaves_Deduped(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
			{Name: "WordPress", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"},
			{Name: "MySQL", Host: "example.test", Source: "fingerprint-port", Confidence: "low"},
			{Name: "nginx", Host: "example.test", Source: "fingerprint-header", Confidence: "high"},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	misconfigLeaves := 0
	var kept *agenttask.PlanNode
	for _, leaf := range agenttask.Leaves(hostNode) {
		if leaf.Detector == "misconfig" {
			misconfigLeaves++
			kept = leaf
		}
	}
	require.Equal(t, 1, misconfigLeaves, "four misconfig-mapping tech facts must produce exactly one misconfig leaf")
	assert.Contains(t, kept.Rationale, `"PHP"`, "the first fact in recon order should supply the surviving leaf's rationale")
}

// TestResolve_DuplicateUnresolvedLeaves_DedupedByTechName guards P0-4 for
// the unresolved case: the same product seen by two recon sources is one
// unresolved leaf, not two.
func TestResolve_DuplicateUnresolvedLeaves_DedupedByTechName(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "MysteryStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"},
			{Name: "MysteryStack", Host: "example.test", Source: "fingerprint-header", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	require.Len(t, agenttask.Leaves(hostNode), 1, "the same unknown product from two sources must produce one unresolved leaf")
	assert.Equal(t, agenttask.StatusUnresolved, agenttask.Leaves(hostNode)[0].Status)
}

// TestResolve_DuplicateTemplateLeaves_Deduped guards P0-4 for template-ID
// leaves: two tech-fact name variants that match the same template tag
// produce one leaf for that template, not one per variant.
func TestResolve_DuplicateTemplateLeaves_Deduped(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "yoast-fpd", Tags: []string{"wordpress", "yoast", "exposure"}},
	}
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "Yoast SEO", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
			{Name: "Yoast SEO Premium:28.4", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, index)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	yoastLeaves := 0
	for _, leaf := range agenttask.Leaves(hostNode) {
		if leaf.Detector == "yoast-fpd" {
			yoastLeaves++
		}
	}
	assert.Equal(t, 1, yoastLeaves, "two name variants matching the same template tag must produce one leaf")
}

// --- P0-2: ranked template-tag selection + canonical map ---

// TestMatchTemplateTags_CanonicalExcludeDropsFalseFriend guards P0-2: a
// "Nginx" fact must not pull in ingress-nginx / nginx-proxy-manager
// templates that merely carry an "nginx" tag too.
func TestMatchTemplateTags_CanonicalExcludeDropsFalseFriend(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2099-0001", Name: "Nginx - Real Thing", Tags: []string{"nginx", "cve"}, Severity: "high"},
		{ID: "nginx-proxy-manager-default-login", Name: "Nginx Proxy Manager Default Login", Tags: []string{"nginx", "proxy-manager", "default-login"}, Severity: "high"},
		// Real corpus shape (LT-19, docs/follow-up.md, 2026-09-04): an
		// Ingress-Nginx-Controller CVE template carries "ingress"/
		// "kubernetes"/"k8s" tags, never a literal "ingress-nginx" tag.
		{ID: "CVE-2025-1974", Name: "Ingress-Nginx Annotation Injection", Tags: []string{"nginx", "ingress", "kubernetes", "k8s", "cve"}, Severity: "critical"},
	}
	got := matchTemplateTags("Nginx", index)

	require.Len(t, got, 1)
	assert.Equal(t, "CVE-2099-0001", got[0].ID)
}

// TestMatchTemplateTags_JQueryExcludesFileUploadPlugin is the second
// observed false-friend from the andertone.com review.
func TestMatchTemplateTags_JQueryExcludesFileUploadPlugin(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "jquery-file-upload-rce", Name: "jQuery File Upload RCE", Tags: []string{"jquery", "jquery-file-upload", "rce"}, Severity: "critical"},
		{ID: "jquery-version-detect", Name: "jQuery version", Tags: []string{"jquery", "tech"}, Severity: "info"},
	}
	got := matchTemplateTags("jQuery", index)

	require.Len(t, got, 1)
	assert.Equal(t, "jquery-version-detect", got[0].ID)
}

// TestMatchTemplateTags_CloudProviderTechFactsDispatch guards Phase 8 Step 3
// / P1-5 (docs/follow-up.md): "aws"/"s3"/"gcp" are single generic-looking
// words (all three sit in genericTechWords) that would otherwise match
// nothing via the plain word-level path — the canonicalTechTags pin is what
// lets pkg/fingerprint's new cloud-provider header signatures and
// pkg/recon/jsstatic.go's bucket-URL fingerprinting actually dispatch the
// corpus's real cloud-exposure templates.
func TestMatchTemplateTags_CloudProviderTechFactsDispatch(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "aws-object-listing", Name: "AWS bucket with Object listing", Tags: []string{"aws", "misconfig", "bucket"}, Severity: "low"},
		{ID: "s3-username-disclosure", Name: "x-amz-meta-s3cmd-attrs Header Username Disclosure", Tags: []string{"s3", "aws", "exposure"}, Severity: "low"},
		{ID: "cloud-metadata", Name: "GCP/AWS Metadata Disclosure", Tags: []string{"misconfig", "aws", "gcp"}, Severity: "low"},
		{ID: "unrelated-template", Name: "Unrelated", Tags: []string{"generic"}, Severity: "info"},
	}

	awsGot := matchTemplateTags("aws", index)
	require.NotEmpty(t, awsGot, "an 'aws' TechFact must dispatch at least one aws-tagged template")
	for _, e := range awsGot {
		assert.Contains(t, e.Tags, "aws")
	}

	s3Got := matchTemplateTags("s3", index)
	require.NotEmpty(t, s3Got, "an 's3' TechFact must dispatch at least one s3-tagged template")

	gcpGot := matchTemplateTags("gcp", index)
	require.NotEmpty(t, gcpGot, "a 'gcp' TechFact must dispatch at least one gcp-tagged template")
}

// TestMatchTemplateTags_GenericWordAloneDoesNotMatch guards P0-2: a tag
// that is only a generic word ("cache", "editor") is not a match.
func TestMatchTemplateTags_GenericWordAloneDoesNotMatch(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "some-cache-plugin-xss", Name: "Some Cache Plugin XSS", Tags: []string{"cache", "xss"}, Severity: "high"},
		{ID: "acme-widget-sqli", Name: "Acme Widget SQLi", Tags: []string{"acme", "sqli"}, Severity: "high"},
	}
	// "Acme Cache Manager" -> words {acme, cache, manager}; only "acme" is
	// non-generic, so the cache-only template must not match.
	got := matchTemplateTags("Acme Cache Manager", index)

	require.Len(t, got, 1)
	assert.Equal(t, "acme-widget-sqli", got[0].ID)
}

// TestMatchTemplateTags_RanksRecentSevereFirst guards P0-2's core: the
// most recent, most severe CVE for a product ranks first, not whatever sat
// earliest in the index file.
func TestMatchTemplateTags_RanksRecentSevereFirst(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2011-1111", Name: "WordPress old", Tags: []string{"wordpress", "cve"}, Severity: "low"},
		{ID: "CVE-2013-3333", Name: "WordPress older", Tags: []string{"wordpress", "cve"}, Severity: "medium"},
		{ID: "CVE-2024-9999", Name: "WordPress recent", Tags: []string{"wordpress", "cve"}, Severity: "critical"},
	}
	got := matchTemplateTags("WordPress", index)

	require.NotEmpty(t, got)
	assert.Equal(t, "CVE-2024-9999", got[0].ID, "recent+critical must rank first")
	// file-order-first would have returned CVE-2011-1111 first.
}

// TestMatchTemplateTags_KnownVersionDeprioritizesAncientCVE guards P0-1a:
// with an explicit current-looking version, a decade-old critical CVE
// ranks below a recent lower-severity one.
func TestMatchTemplateTags_KnownVersionDeprioritizesAncientCVE(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2012-1823", Name: "PHP CGI argument injection", Tags: []string{"php", "rce", "cve"}, Severity: "critical"},
		{ID: "CVE-2023-4444", Name: "PHP recent issue", Tags: []string{"php", "cve"}, Severity: "medium"},
	}
	got := matchTemplateTags("PHP:8.3.30", index)

	require.Len(t, got, 2)
	assert.Equal(t, "CVE-2023-4444", got[0].ID, "a modern version makes the 2012 CVE implausible — it should rank second")
}

// TestMatchTemplateTags_AffectedRangeDropsOutOfRangeVersion is LT-7/Phase 8
// Step 4's headline case: a template declaring an affected-version range
// (nginx-eol.yaml's real shape) is dropped, not just deprioritized, when
// the fingerprinted version is outside it.
func TestMatchTemplateTags_AffectedRangeDropsOutOfRangeVersion(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "nginx-eol", Name: "Nginx End-of-Life", Tags: []string{"nginx", "eol"}, Severity: "info", AffectedRange: [][]string{{"<1.28.0"}}},
	}
	assert.Empty(t, matchTemplateTags("Nginx:1.29.1", index), "1.29.1 does not satisfy <1.28.0 — the template must not be selected")
}

// TestMatchTemplateTags_AffectedRangeKeepsInRangeVersion is the same
// template with a version that DOES satisfy the declared range.
func TestMatchTemplateTags_AffectedRangeKeepsInRangeVersion(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "nginx-eol", Name: "Nginx End-of-Life", Tags: []string{"nginx", "eol"}, Severity: "info", AffectedRange: [][]string{{"<1.28.0"}}},
	}
	got := matchTemplateTags("Nginx:1.20.0", index)
	require.Len(t, got, 1)
	assert.Equal(t, "nginx-eol", got[0].ID)
}

// TestMatchTemplateTags_AffectedRangeNoFingerprintedVersionKeepsTemplate
// covers the "no fingerprinted version" case the doc explicitly calls out:
// a bare "Nginx" TechFact (no ":version" suffix) can't be compared against
// any range at all, so the template stays in scope — an absent signal must
// never suppress a candidate the way a contradicting one does.
func TestMatchTemplateTags_AffectedRangeNoFingerprintedVersionKeepsTemplate(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "nginx-eol", Name: "Nginx End-of-Life", Tags: []string{"nginx", "eol"}, Severity: "info", AffectedRange: [][]string{{"<1.28.0"}}},
	}
	got := matchTemplateTags("Nginx", index)
	require.Len(t, got, 1)
	assert.Equal(t, "nginx-eol", got[0].ID)
}

// TestMatchTemplateTags_AffectedRangeOrClauseEitherSatisfiesKeeps covers a
// two-clause (disjoint-range) AffectedRange, mirroring CVE-2022-31704.yaml's
// real shape: a version satisfying the SECOND clause alone still keeps the
// template (OR across clauses).
func TestMatchTemplateTags_AffectedRangeOrClauseEitherSatisfiesKeeps(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2022-31704", Name: "vRealize RCE", Tags: []string{"vmware", "cve", "rce"}, Severity: "critical",
			AffectedRange: [][]string{{">= 3.0", "< 4.8"}, {">= 8.0.0", "< 8.10.2"}}},
	}
	got := matchTemplateTags("VMware:8.5.0", index)
	require.Len(t, got, 1, "8.5.0 satisfies the second clause even though it fails the first")
}

func TestVersionInAffectedRange(t *testing.T) {
	cases := []struct {
		name    string
		version string
		ranges  [][]string
		want    bool
	}{
		{"no declared range", "1.0.0", nil, true},
		{"in single clause", "1.27.0", [][]string{{"<1.28.0"}}, true},
		{"out of single clause", "1.29.0", [][]string{{"<1.28.0"}}, false},
		{"satisfies second of two OR clauses", "8.5.0", [][]string{{">= 3.0", "< 4.8"}, {">= 8.0.0", "< 8.10.2"}}, true},
		{"satisfies neither OR clause", "5.0.0", [][]string{{">= 3.0", "< 4.8"}, {">= 8.0.0", "< 8.10.2"}}, false},
		{"AND clause partially satisfied fails", "9.0.0", [][]string{{">= 8.0.0", "< 8.10.2"}}, false},
		{"unparseable version can't be ruled out", "not-a-version", [][]string{{"<1.28.0"}}, true},
		{"empty version can't be ruled out", "", [][]string{{"<1.28.0"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, versionInAffectedRange(c.version, c.ranges))
		})
	}
}

// TestMatchTemplateTags_NoProductTagNoMatch is the new contract after the
// ID/Name-token tier was dropped (it pulled in product-prefixed false
// friends like "weaver-jquery-file-upload" on the live corpus): a template
// with no product tag does not match, even if its Name mentions the
// product.
func TestMatchTemplateTags_NoProductTagNoMatch(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2021-25118", Name: "Yoast SEO < 17.2 - Information Disclosure", Tags: []string{"cve", "cve2021", "exposure"}, Severity: "medium"},
	}
	assert.Empty(t, matchTemplateTags("Yoast SEO", index),
		"a template with no yoast/seo tag must not match on Name text alone")
}

// TestMatchTemplateTags_ExcludeByIDSubstring guards the excludeIDSubstr
// path: the jQuery-File-Upload plugin templates carry a bare "jquery" tag,
// so only an ID-substring exclusion catches them.
func TestMatchTemplateTags_ExcludeByIDSubstring(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "exposed-jquery-file-upload", Name: "jQuery File Upload - Exposure", Tags: []string{"jquery", "exposure", "misconfig"}, Severity: "critical"},
		{ID: "jquery-prototype-pollution", Name: "jQuery Prototype Pollution", Tags: []string{"jquery", "cve"}, Severity: "medium"},
	}
	got := matchTemplateTags("jQuery", index)

	require.Len(t, got, 1)
	assert.Equal(t, "jquery-prototype-pollution", got[0].ID)
}

// TestMatchTemplateTags_MySQLExcludesProductFalseFriends: several
// product-specific templates carry a bare "mysql" tag on the live corpus.
func TestMatchTemplateTags_MySQLExcludesProductFalseFriends(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "esafenet-mysql-fileread", Name: "Esafenet CDG mysql - File Read", Tags: []string{"esafenet", "lfi", "mysql"}, Severity: "high"},
		{ID: "eventum-panel", Name: "Eventum Login Panel - Detect", Tags: []string{"panel", "eventum", "mysql"}, Severity: "info"},
		{ID: "mysql-config-exposure", Name: "MySQL Config - Exposure", Tags: []string{"mysql", "config", "exposure"}, Severity: "medium"},
	}
	got := matchTemplateTags("MySQL", index)

	require.Len(t, got, 1)
	assert.Equal(t, "mysql-config-exposure", got[0].ID)
}

// TestMatchTemplateTags_NilIndex is the documented soft-degrade.
func TestMatchTemplateTags_NilIndex(t *testing.T) {
	assert.Nil(t, matchTemplateTags("WordPress", nil))
}

// TestMatchTemplateTags_CapReturnsBestNotFileOrder confirms the cap keeps
// the top maxTemplateLeavesPerTech by score, not the first N seen.
func TestMatchTemplateTags_CapReturnsBestNotFileOrder(t *testing.T) {
	var index []templatesync.Entry
	// maxTemplateLeavesPerTech+3 low-value entries first...
	for i := 0; i < maxTemplateLeavesPerTech+3; i++ {
		index = append(index, templatesync.Entry{ID: fmt.Sprintf("CVE-2010-%04d", i), Tags: []string{"wordpress", "cve"}, Severity: "low"})
	}
	// ...then one clearly best entry last.
	index = append(index, templatesync.Entry{ID: "CVE-2025-0001", Tags: []string{"wordpress", "cve"}, Severity: "critical"})

	got := matchTemplateTags("WordPress", index)

	require.Len(t, got, maxTemplateLeavesPerTech)
	assert.Equal(t, "CVE-2025-0001", got[0].ID, "the best entry must survive the cap even though it was last in file order")
}

// --- LT-48 (docs/follow-up.md): relevance-score floor, not just a count cap ---

// TestMatchTemplateTags_WeakSecondaryWordMatchBelowFloorDropped: a template
// that shares only a non-primary word with the tech name, carries no
// severity and is not a CVE, scores 50 — below minTemplateLeafScore. It must
// not become a leaf; when it's the only candidate the whole fan-out is
// dropped (the LT-30/LT-31 shape).
func TestMatchTemplateTags_WeakSecondaryWordMatchBelowFloorDropped(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "generic-bar-check", Name: "Bar check", Tags: []string{"bar"}, Severity: ""},
	}
	got := matchTemplateTags("Foo Bar", index) // primary word "foo"; only "bar" matches this entry
	assert.Empty(t, got, "a lone score-50 coincidental-word match must not become a leaf")
}

// TestMatchTemplateTags_WeakWordMatchWithHighSeverityKept: the same weak word
// overlap, but the template is high severity (50 + 15 = 65 >= 60) — kept, so
// the floor removes only the genuinely low-value tail.
func TestMatchTemplateTags_WeakWordMatchWithHighSeverityKept(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "serious-bar-rce", Name: "Bar RCE", Tags: []string{"bar"}, Severity: "high"},
	}
	got := matchTemplateTags("Foo Bar", index)
	require.Len(t, got, 1)
	assert.Equal(t, "serious-bar-rce", got[0].ID)
}

// TestMatchTemplateTags_ScoreFloorTrimsTailKeepsStrong: a mix — one strong
// primary-tag hit plus several weak below-floor entries — keeps only the
// strong one.
func TestMatchTemplateTags_ScoreFloorTrimsTailKeepsStrong(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "weak-1", Tags: []string{"bar"}, Severity: ""},
		{ID: "weak-2", Tags: []string{"bar"}, Severity: "low"},
		{ID: "strong", Tags: []string{"foo"}, Severity: "high"},
		{ID: "weak-3", Tags: []string{"bar"}, Severity: ""},
	}
	got := matchTemplateTags("Foo Bar", index)
	require.Len(t, got, 1)
	assert.Equal(t, "strong", got[0].ID)
}

// --- LT-51 (docs/follow-up.md): status-weighted /api endpoint confidence ---

func TestAPIRouteConfidence(t *testing.T) {
	assert.Equal(t, agenttask.ConfidenceHigh, apiRouteConfidence([]recon.EndpointFact{
		{URL: "https://h.test/api/customer/order-history", StatusCode: 400},
	}), "a 400 on an /api path confirms the route exists")
	assert.Equal(t, agenttask.ConfidenceHigh, apiRouteConfidence([]recon.EndpointFact{
		{URL: "https://h.test/api/x", StatusCode: 401},
	}))
	assert.Equal(t, agenttask.ConfidenceMedium, apiRouteConfidence([]recon.EndpointFact{
		{URL: "https://h.test/api/x", StatusCode: 404},
	}), "a 404 does not confirm anything")
	assert.Equal(t, agenttask.ConfidenceMedium, apiRouteConfidence([]recon.EndpointFact{
		{URL: "https://h.test/products/1", StatusCode: 400},
	}), "a non-/api path is not weighted")
}

// TestResolve_APIEndpoint400_IdorLeafAtHighConfidence: an ID-shaped /api
// endpoint that returned 400 unauthenticated produces an idor leaf at
// ConfidenceHigh, not the ConfidenceMedium a bare URL-shape match gets.
func TestResolve_APIEndpoint400_IdorLeafAtHighConfidence(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/api/customer/report?report_id=482", Method: "GET", StatusCode: 400, Source: "wave3-crawl"},
		},
	}
	tree, _ := Resolve(result, nil)
	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "idor" })
	require.NotNil(t, leaf)
	assert.Equal(t, agenttask.ConfidenceHigh, leaf.Confidence, "LT-51: a live-confirmed /api route lifts the endpoint-driven leaf to High")
}

// --- LT-16 (docs/follow-up.md): TechStackTags ---

// TestTechStackTags_UnionsRelevantEntryTags confirms the basic shape: the
// tags of every entry matchTemplateTags ranks as relevant to a detected
// tech are unioned into one deduped, sorted allowlist.
// TestDetectorTemplateTags covers the doc15 Step 6a category floor: a
// stable, non-empty tag set per built-in detector, nil for an unknown name
// or businesslogic (native-only), and a copy the caller can't mutate.
func TestDetectorTemplateTags(t *testing.T) {
	assert.Equal(t, []string{"misconfig", "exposure", "config", "default-login", "panel"}, DetectorTemplateTags("misconfig"))
	assert.Equal(t, []string{"auth-bypass", "default-login", "panel", "exposure"}, DetectorTemplateTags("authbypass"))
	assert.Equal(t, []string{"ssrf", "redirect", "oob"}, DetectorTemplateTags("ssrf"))
	assert.NotEmpty(t, DetectorTemplateTags("idor"))

	assert.Nil(t, DetectorTemplateTags("businesslogic"), "businesslogic is native-only — no corpus floor")
	assert.Nil(t, DetectorTemplateTags("nonsense"), "unknown detector name → nil (caller falls back to the full corpus)")

	got := DetectorTemplateTags("misconfig")
	got[0] = "mutated"
	assert.Equal(t, "misconfig", DetectorTemplateTags("misconfig")[0], "must return a fresh copy, not the shared backing slice")
}

// TestDetectorTemplateTagsForRecon covers LT-43(1): misconfig's "panel" floor
// tag is gated on recon showing an admin/login/protected surface.
func TestDetectorTemplateTagsForRecon(t *testing.T) {
	noAdmin := &recon.ReconResult{Endpoints: []recon.EndpointFact{
		{URL: "https://spa.test/", StatusCode: 200, Source: "httpx"},
		{URL: "https://spa.test/static/js/main.js", StatusCode: 200, Source: "katana-crawl"},
	}}
	assert.Equal(t, []string{"misconfig", "exposure", "config", "default-login"},
		DetectorTemplateTagsForRecon("misconfig", noAdmin), "no admin surface → drop panel")

	for _, ep := range []recon.EndpointFact{
		{URL: "https://app.test/admin/", StatusCode: 200, Source: "katana-crawl"},
		{URL: "https://app.test/x", StatusCode: 401, Source: "katana-crawl"},
		{URL: "https://app.test/", StatusCode: 200, Source: "wave3-auth-boundary-heuristic"},
	} {
		r := &recon.ReconResult{Endpoints: []recon.EndpointFact{ep}}
		assert.Contains(t, DetectorTemplateTagsForRecon("misconfig", r), "panel",
			"admin/login/401 surface (%s / %d / %s) → keep panel", ep.URL, ep.StatusCode, ep.Source)
	}

	// nil result and non-misconfig detectors are untouched.
	assert.Equal(t, DetectorTemplateTags("misconfig"), DetectorTemplateTagsForRecon("misconfig", nil))
	assert.Equal(t, DetectorTemplateTags("authbypass"), DetectorTemplateTagsForRecon("authbypass", noAdmin))

	// D6 / LT-58: when recon classified the host as a WAF block wall, a bare
	// 401/403 on every path is a blanket intercept, not an admin surface —
	// "panel" is dropped. A path-discriminating signal (an admin-shaped URL,
	// an auth-boundary heuristic hit) still keeps it even behind the wall.
	wafWalled := func(eps ...recon.EndpointFact) *recon.ReconResult {
		return &recon.ReconResult{
			Endpoints:        eps,
			UniformResponses: []recon.UniformResponseFact{{Host: "walled.test", Kind: "waf-block", CanaryStatus: 403}},
		}
	}
	assert.NotContains(t,
		DetectorTemplateTagsForRecon("misconfig", wafWalled(recon.EndpointFact{URL: "https://walled.test/x", StatusCode: 403, Source: "katana-crawl"})),
		"panel", "blanket WAF 403 → drop panel (LT-58)")
	assert.Contains(t,
		DetectorTemplateTagsForRecon("misconfig", wafWalled(recon.EndpointFact{URL: "https://walled.test/admin/", StatusCode: 403, Source: "katana-crawl"})),
		"panel", "admin-shaped path even behind a WAF → keep panel")
	assert.Contains(t,
		DetectorTemplateTagsForRecon("misconfig", wafWalled(recon.EndpointFact{URL: "https://walled.test/", StatusCode: 403, Source: "wave3-auth-boundary-heuristic"})),
		"panel", "auth-boundary heuristic hit even behind a WAF → keep panel")

	// LT-140: a multi-host result with one WAF-walled host must not
	// suppress a genuine 401/403 admin signal on a *different*, unwalled
	// host in the same run — reconShowsAdminSurface now checks the wall
	// per endpoint host, not once for the whole result.
	multiHost := &recon.ReconResult{
		Endpoints: []recon.EndpointFact{
			{URL: "https://walled.test/x", StatusCode: 403, Source: "katana-crawl"},
			{URL: "https://open.test/x", StatusCode: 403, Source: "katana-crawl"},
		},
		UniformResponses: []recon.UniformResponseFact{{Host: "walled.test", Kind: "waf-block", CanaryStatus: 403}},
	}
	assert.Contains(t, DetectorTemplateTagsForRecon("misconfig", multiHost), "panel",
		"a bare 403 on an unwalled host in a multi-host run must still count as an admin signal (LT-140) — the WAF wall on the other host must not suppress it")
}

func TestTechStackTags_UnionsRelevantEntryTags(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "wordpress-panel", Name: "WordPress Login Panel", Tags: []string{"wordpress", "panel"}, Severity: "info"},
		{ID: "nginx-cve", Name: "Nginx - Real CVE", Tags: []string{"nginx", "cve"}, Severity: "high"},
		{ID: "unrelated-panel", Name: "Some Unrelated Panel", Tags: []string{"acme", "panel"}, Severity: "info"},
	}
	techStack := []recon.TechFact{
		{Name: "WordPress", Host: "example.com", Confidence: recon.ConfidenceHigh},
		{Name: "Nginx", Host: "example.com", Confidence: recon.ConfidenceMedium},
	}

	got := TechStackTags(techStack, index)

	// Only the product-identifying tag of each matched entry is harvested
	// (LT-26): "wordpress" and "nginx", never the "panel" behaviour tag the
	// WordPress-panel template also carries (that would re-widen the
	// allowlist to every panel template) nor the corpus-wide "cve" tag.
	assert.ElementsMatch(t, []string{"wordpress", "nginx"}, got, "must harvest each matched entry's product tag from both techs, and only that tag")
}

// TestTechStackTags_FalseFriendExclusionApplies confirms canonicalTechTags'
// exclusions (already proven for matchTemplateTags itself) carry through:
// an "Nginx" fact must not pull in an Ingress-Nginx-Controller CVE's tags.
func TestTechStackTags_FalseFriendExclusionApplies(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2099-0001", Name: "Nginx - Real Thing", Tags: []string{"nginx", "cve"}, Severity: "high"},
		// Real corpus shape (LT-19, docs/follow-up.md, 2026-09-04) — see the
		// matching matchTemplateTags fixture above.
		{ID: "CVE-2025-1974", Name: "Ingress-Nginx Annotation Injection", Tags: []string{"nginx", "ingress", "kubernetes", "k8s", "cve"}, Severity: "critical"},
	}
	got := TechStackTags([]recon.TechFact{{Name: "Nginx", Host: "example.com"}}, index)

	assert.ElementsMatch(t, []string{"nginx"}, got, "the Ingress-Nginx-Controller entry must never have contributed its \"ingress\"/\"kubernetes\"/\"k8s\" tags to the allowlist; the corpus-wide \"cve\" meta tag is dropped too (LT-26)")
}

// TestTechStackTags_DropsMetaAndBehaviourTags is LT-26 (docs/follow-up.md):
// a legitimately-matched entry contributes only its product-identifying tag,
// never the provenance / issue-category tags (edb, cve, cve2021, disclosure)
// nor the vuln-class / behaviour tags (rce, panel) that ride along on the
// same template — those match most of the corpus and collapse the
// narrowing. This is what let nettix.com.pe still load 9,049 of 9,451
// templates: one WordPress-CVE entry contributed "rce"/"kev"/"wpscan".
func TestTechStackTags_DropsMetaAndBehaviourTags(t *testing.T) {
	index := []templatesync.Entry{
		{
			ID:       "CVE-2021-0001",
			Name:     "phpMyAdmin - Some CVE",
			Tags:     []string{"phpmyadmin", "cve", "cve2021", "edb", "disclosure", "panel", "rce"},
			Severity: "high",
		},
	}
	got := TechStackTags([]recon.TechFact{{Name: "phpMyAdmin", Host: "example.com"}}, index)

	assert.Equal(t, []string{"phpmyadmin"}, got,
		"only the product tag survives; the meta (cve/cve2021/edb/disclosure) and behaviour (panel/rce) tags on the same entry are all dropped")
	for _, drop := range []string{"cve", "cve2021", "edb", "disclosure", "panel", "rce"} {
		assert.NotContains(t, got, drop)
	}
}

// TestTechStackTags_DedupsRepeatedTechAcrossHosts confirms the same tech
// name observed on multiple host variants (LT-14's own www./case dedup
// gap, upstream of this) is only matched once, not once per occurrence —
// purely a performance/no-duplicate-work guard, not a correctness one
// (map-based tagSet already dedups the actual output regardless).
func TestTechStackTags_DedupsRepeatedTechAcrossHosts(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "wordpress-panel", Tags: []string{"wordpress"}, Severity: "info"},
	}
	techStack := []recon.TechFact{
		{Name: "WordPress", Host: "www.example.com"},
		{Name: "wordpress", Host: "example.com"},
	}
	got := TechStackTags(techStack, index)
	assert.Equal(t, []string{"wordpress"}, got)
}

// TestTechStackTags_NonActionableTechContributesNothing confirms a
// hosting/CDN-brand fact (nonActionableTech) never contributes tags — it
// has no real template surface, matching resolveTechFact's own gate.
func TestTechStackTags_NonActionableTechContributesNothing(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "some-template", Tags: []string{"cloudflare"}, Severity: "info"},
	}
	got := TechStackTags([]recon.TechFact{{Name: "Cloudflare", Host: "example.com"}}, index)
	assert.Nil(t, got)
}

// TestTechStackTags_EmptyInputsReturnNil locks in the documented
// full-corpus-unchanged fallback: no TechStack and no index both degrade
// to nil, never an empty-but-non-nil allowlist that would accidentally
// filter out every template.
func TestTechStackTags_EmptyInputsReturnNil(t *testing.T) {
	assert.Nil(t, TechStackTags(nil, []templatesync.Entry{{ID: "x", Tags: []string{"wordpress"}}}))
	assert.Nil(t, TechStackTags([]recon.TechFact{{Name: "WordPress"}}, nil))
}

// TestTechStackTags_NoRelevantTemplatesReturnsNil confirms a detected tech
// with no matching template in the index degrades to nil too (same
// full-corpus fallback), not an allowlist that matches nothing.
func TestTechStackTags_NoRelevantTemplatesReturnsNil(t *testing.T) {
	index := []templatesync.Entry{{ID: "unrelated", Tags: []string{"acme"}, Severity: "info"}}
	got := TechStackTags([]recon.TechFact{{Name: "WordPress", Host: "example.com"}}, index)
	assert.Nil(t, got)
}

// TestMatchTemplateTags_FullSlugMatchesHyphenatedCompoundTag is P1-3's
// unlock: the real synced corpus tags plugin templates by the literal
// hyphenated slug ("contact-form-7"), but the word-decomposed matchWords
// path alone (primary="contact") would never equal that compound tag.
// Fixture tags mirror the real wp-contact-form-7-fpd entry (2026-09-04).
func TestMatchTemplateTags_FullSlugMatchesHyphenatedCompoundTag(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "wp-contact-form-7-fpd", Name: "Contact Form 7 Plugin - Full Path Disclosure", Tags: []string{"debug", "wordpress", "wp", "wp-plugin", "contact-form-7", "fpd"}, Severity: "low"},
		// Shares no word with "contact"/"form" (matchWords), so this entry
		// only matters as a negative control against the fullSlug tier
		// specifically, not against the pre-existing word-level path too.
		{ID: "unrelated-panel-template", Name: "Unrelated Admin Panel - Detect", Tags: []string{"panel", "builder"}, Severity: "info"},
	}
	got := matchTemplateTags("contact-form-7:5.7.1", index)

	require.Len(t, got, 1, "only the entry carrying the literal contact-form-7 slug tag should match")
	assert.Equal(t, "wp-contact-form-7-fpd", got[0].ID)
}

// TestMatchTemplateTags_FullSlugSingleWordNameUnaffected is a regression
// guard: a plain, non-hyphenated name's matching must be unchanged by the
// fullSlug addition (fullSlug is "" whenever normalized has no hyphen).
func TestMatchTemplateTags_FullSlugSingleWordNameUnaffected(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2021-25118", Name: "Yoast SEO < 17.2 - Information Disclosure", Tags: []string{"cve", "cve2021", "wordpress", "yoast"}, Severity: "medium"},
	}
	got := matchTemplateTags("Yoast SEO", index)
	require.Len(t, got, 1)
	assert.Equal(t, "CVE-2021-25118", got[0].ID)
}

// --- P1-1: endpoint-driven leaf emission ---

// TestResolve_EndpointOnlyHost_ProducesHostNode locks in the host-set fix:
// a host that never appears in TechStack, only in Endpoints, must still get
// a host node when it has real endpoint-driven signal — the root-cause gap
// docs/follow-up.md named ("Resolve reasons only over TechStack").
func TestResolve_EndpointOnlyHost_ProducesHostNode(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://api.example.test/report/482", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:api.example.test")
	require.NotNil(t, hostNode, "an endpoint-only host must still produce a host node")
}

func TestResolve_IDShapedEndpoint_ProducesIdorLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/mechanic_report?report_id=482", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "idor" })
	require.NotNil(t, leaf, "an ID-shaped endpoint must produce an idor leaf even with no matching TechFact")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
}

func TestResolve_ProtectedEndpoint_ProducesAuthbypassLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/admin", Method: "GET", StatusCode: 401, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "authbypass" })
	require.NotNil(t, leaf, "a 401/403 endpoint must produce an authbypass leaf")
}

func TestResolve_SSRFParamEndpoint_ProducesSsrfLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/fetch?callback=http://internal", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "ssrf" })
	require.NotNil(t, leaf, "a URL-shaped query param must produce an ssrf leaf")
}

// TestResolve_SSRFBodyParamEndpoint_ProducesSsrfLeafWithBodyParams covers
// LT-96 (docs/follow-up.md): an api-spec fact's requestBody schema property
// name, not a query param, must still produce a dispatchable ssrf leaf.
func TestResolve_SSRFBodyParamEndpoint_ProducesSsrfLeafWithBodyParams(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/merchant/contact_mechanic", Method: "POST", Source: "api-spec", BodyParamKeys: []string{"repair_url"}},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "ssrf" })
	require.NotNil(t, leaf, "a URL-shaped requestBody property must produce an ssrf leaf")
	assert.Equal(t, []string{"repair_url"}, leaf.SSRFBodyParams)
}

func TestResolve_CartEndpoint_ProducesBusinessLogicLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/checkout", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "businesslogic" })
	require.NotNil(t, leaf, "a checkout-shaped endpoint must produce a businesslogic leaf")
	assert.Contains(t, leaf.Rationale, "--allow-writes", "the leaf's own rationale must be honest that a human gate still applies")
}

// TestResolve_CouponEndpoint_ProducesEndpointDrivenBusinessLogicLeaf is
// LT-135's regression: a spec-derived ReconResult.CouponEndpoint produces a
// businesslogic leaf carrying the real mint/apply paths and field names, and
// supersedes the generic cart-keyword-only leaf a plain endpoint on the same
// host would otherwise also produce (dropBareCapabilityLeavesSupersededByEndpointDriven).
func TestResolve_CouponEndpoint_ProducesEndpointDrivenBusinessLogicLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			// a generic cart-keyword endpoint on the same host — would produce
			// its own low-confidence bare leaf if the coupon fact didn't
			// supersede it.
			{URL: "http://example.test/cart", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
		CouponEndpoint: &recon.CouponFact{
			MintURL: "http://example.test/api/v2/promo/new", MintMethod: "POST",
			ApplyURL: "http://example.test/api/v1/promo/apply", ApplyMethod: "POST",
			CodeField: "voucher_code", AmountField: "value",
		},
	}

	tree, _ := Resolve(result, nil)

	var leaves []*agenttask.PlanNode
	for _, l := range hostLeaves(t, tree, "example.test") {
		if l.Detector == "businesslogic" {
			leaves = append(leaves, l)
		}
	}
	require.Len(t, leaves, 1, "the spec-derived leaf must supersede the generic cart-keyword leaf, not add a second one")

	leaf := leaves[0]
	assert.Equal(t, "/api/v2/promo/new", leaf.CouponMintPath)
	assert.Equal(t, "/api/v1/promo/apply", leaf.CouponApplyPath)
	assert.Equal(t, "voucher_code", leaf.CouponCodeField)
	assert.Equal(t, "value", leaf.CouponAmountField)
	assert.Equal(t, agenttask.ConfidenceMedium, leaf.Confidence)
	assert.Contains(t, leaf.Rationale, "--allow-writes")
}

// TestResolve_HostnameProductHint_ProducesLeaves is LT-9's (docs/follow-up.md)
// regression guard: a host whose first DNS label names a known product
// (guacamole01 -> guacamole) gets that product's template-tag leaves even
// with no fingerprint on the host at all.
func TestResolve_HostnameProductHint_ProducesLeaves(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://guacamole01.example.com",
		Endpoints: []recon.EndpointFact{
			// an endpoint so the host node exists; it carries no idor/ssrf/etc. signal itself
			{URL: "http://guacamole01.example.com/", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
	}
	index := []templatesync.Entry{
		{ID: "apache-guacamole-default-login", Tags: []string{"guacamole", "default-login"}, Severity: "high"},
		{ID: "unrelated-wordpress-thing", Tags: []string{"wordpress"}, Severity: "info"},
	}

	tree, _ := Resolve(result, index)

	leaf := findLeaf(t, tree, "guacamole01.example.com", func(n *agenttask.PlanNode) bool {
		return n.Detector == "apache-guacamole-default-login"
	})
	require.NotNil(t, leaf, "a guacamole-named host must dispatch guacamole-tagged templates")
	assert.Equal(t, agenttask.ConfidenceLow, leaf.Confidence, "a hostname is weaker evidence than a live fingerprint")
}

// TestResolve_UnhintedHostname_NoHintLeaves confirms the hint map is an exact
// first-label token match, not a loose substring — an arbitrary host name
// must not trip it.
func TestResolve_UnhintedHostname_NoHintLeaves(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://myjira-notes.example.com",
		Endpoints: []recon.EndpointFact{{URL: "http://myjira-notes.example.com/", Method: "GET", StatusCode: 200, Source: "wave3-crawl"}},
	}
	index := []templatesync.Entry{{ID: "jira-unauth", Tags: []string{"jira"}, Severity: "high"}}

	tree, _ := Resolve(result, index)

	assert.Nil(t, tree.Find("host:myjira-notes.example.com"), "'myjira-notes' must not match the 'jira' hint (exact first-label token only)")
}

// TestResolve_CartShapedStaticAsset_NoBusinessLogicLeaf is LT-20's
// (docs/follow-up.md) regression guard: a purely cosmetic static asset
// (real example: a WordPress theme's "cart-header-element-lazy.min.css")
// can match businessLogicPathKeywords on its filename alone — must not
// produce a businesslogic leaf, mirroring suggest.go's own established
// IsStaticAssetPath guard for the same false-positive class.
func TestResolve_CartShapedStaticAsset_NoBusinessLogicLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/wp-content/themes/blocksy/static/bundle/cart-header-element-lazy.min.css", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil)

	// The endpoint produces no leaf at all once the static-asset guard drops
	// it (not even an idor candidate — it's not {{id}}-shaped either), so no
	// host node exists at all, same "no empty host node" behavior
	// TestResolve_NonSignalEndpoint_NoExtraLeaf already establishes.
	assert.Nil(t, tree.Find("host:example.test"), "a static-asset filename that merely contains \"cart\" must not produce a businesslogic leaf (or any other)")
}

func TestResolve_NonSignalEndpoint_NoExtraLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/about-us", Method: "GET", StatusCode: 200, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil)

	assert.Nil(t, tree.Find("host:example.test"), "an endpoint with no idor/authbypass/ssrf/businesslogic/endpointSignal signal must produce no host node at all")
}

// TestResolve_LiveHostNonActionableTechOnly_GetsBaselineMisconfigLeaf is
// LT-32's (docs/follow-up.md) regression guard, mirroring www.valmo.in: a
// host recon directly confirmed serving HTTP (an "httpx" EndpointFact)
// whose only tech facts are all nonActionableTech must still get one
// ConfidenceLow misconfig leaf so misconfig's baseline header/CORS/
// exposed-path checks run against it.
func TestResolve_LiveHostNonActionableTechOnly_GetsBaselineMisconfigLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://www.example.test",
		TechStack: []recon.TechFact{
			{Name: "Google Cloud", Host: "www.example.test", Source: "httpx-tech-detect", Confidence: "high"},
			{Name: "HSTS", Host: "www.example.test", Source: "httpx-tech-detect", Confidence: "high"},
		},
		Endpoints: []recon.EndpointFact{
			{URL: "http://www.example.test/", Method: "GET", StatusCode: 200, Source: "httpx", Confidence: "high"},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "www.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, leaf, "a live HTTP host with only non-actionable tech must still get a baseline misconfig leaf")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
	assert.Equal(t, agenttask.ConfidenceLow, leaf.Confidence, "a bare 'nothing else fired' baseline leaf is low-confidence")
}

// TestResolve_BaselineMisconfigLeaf_DedupsAgainstRealMisconfigLeaf confirms
// LT-32's leaf never doubles a misconfig leaf another pass already produced
// for the same host.
func TestResolve_BaselineMisconfigLeaf_DedupsAgainstRealMisconfigLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "PHP", Host: "example.test", Source: "httpx-tech-detect", Confidence: "medium"}},
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/", Method: "GET", StatusCode: 200, Source: "httpx", Confidence: "high"},
		},
	}

	tree, _ := Resolve(result, nil)

	misconfigLeaves := 0
	for _, l := range agenttask.Leaves(tree.Find("host:example.test")) {
		if l.Detector == "misconfig" {
			misconfigLeaves++
		}
	}
	assert.Equal(t, 1, misconfigLeaves, "the PHP-driven misconfig leaf and LT-32's baseline leaf must dedup to one")
}

// TestResolve_KatanaOnlyEndpoint_NoBaselineMisconfigLeaf confirms LT-32
// keys off a *direct* live probe (httpx / wave3 common-path / auth-boundary)
// — a katana-crawl link alone (the host maybe never directly hit) is not
// enough, so the "endpoint with no signal ⇒ no host node" behavior other
// tests rely on is unchanged for crawl-only facts.
func TestResolve_KatanaOnlyEndpoint_NoBaselineMisconfigLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/about", Method: "GET", StatusCode: 200, Source: "katana-crawl", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, nil)

	assert.Nil(t, tree.Find("host:example.test"), "a katana-only endpoint with no vuln-shaped signal must still produce no host node")
}

// TestResolve_WAFBlockedHost_GetsBaselineMisconfigLeaf is LT-57's regression
// guard (docs/follow-up.md), mirroring www.valmo.in behind Akamai: a host
// recon directly probed (an "httpx" EndpointFact) that answers 403 on every
// path — no 2xx anywhere, only non-actionable tech facts — must still get one
// ConfidenceLow misconfig leaf. Before LT-57 the 2xx/3xx-only gate excluded
// it and Resolve produced a completely empty tree for a reachable target.
func TestResolve_WAFBlockedHost_GetsBaselineMisconfigLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "https://www.example.test",
		TechStack: []recon.TechFact{
			{Name: "HSTS", Host: "www.example.test", Source: "httpx-tech-detect", Confidence: "medium"},
			{Name: "HTTP/3", Host: "www.example.test", Source: "httpx-tech-detect", Confidence: "medium"},
		},
		Endpoints: []recon.EndpointFact{
			{URL: "https://www.example.test", Method: "GET", StatusCode: 403, Source: "httpx", Confidence: "high"},
			{URL: "https://www.example.test", Method: "GET", StatusCode: 403, Source: "katana-crawl", Confidence: "high"},
		},
	}

	tree, _ := Resolve(result, nil)

	require.NotNil(t, tree.Find("host:www.example.test"), "a 403-on-every-path WAF wall is still a live host — the tree must not be empty")
	leaf := findLeaf(t, tree, "www.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, leaf, "a directly-probed host answering 403 must still get a baseline misconfig leaf (LT-57)")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
	assert.Equal(t, agenttask.ConfidenceLow, leaf.Confidence)
}

// TestResolve_WAFBlockedHost_KatanaOnlyRoot403_NoLeaf confirms LT-57 still
// keys off a *direct* probe: a 403 on the bare root seen only via a
// katana-crawl link (no path for resolveEndpointFacts' authbypass check to
// bite on, and katana-crawl is not a liveBaselineEndpointSources source) is
// not enough on its own — mirrors www.valmo.in's own katana-crawl endpoint.
func TestResolve_WAFBlockedHost_KatanaOnlyRoot403_NoLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "https://www.example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "https://www.example.test", Method: "GET", StatusCode: 403, Source: "katana-crawl", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, nil)

	assert.Nil(t, tree.Find("host:www.example.test"), "a katana-only root 403 with no direct probe must produce no host node")
}

func TestLiveBaselineStatus(t *testing.T) {
	for _, code := range []int{200, 204, 301, 302, 399, 401, 403, 429} {
		assert.True(t, liveBaselineStatus(code), "status %d should count as a live server", code)
	}
	for _, code := range []int{0, 400, 404, 405, 500, 502, 503} {
		assert.False(t, liveBaselineStatus(code), "status %d should not trip the baseline leaf on its own", code)
	}
}

func TestResolve_XmlrpcEndpoint_ProducesKnownTemplateLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/xmlrpc.php", Method: "POST", StatusCode: 200, Source: "wave3-crawl"},
		},
	}
	index := []templatesync.Entry{
		{ID: "wordpress-xmlrpc-detect", Tags: []string{"wordpress"}, Severity: "info"},
	}

	tree, _ := Resolve(result, index)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "wordpress-xmlrpc-detect" })
	require.NotNil(t, leaf, "a directly-observed xmlrpc.php endpoint must produce the known template leaf")
	assert.Equal(t, agenttask.ConfidenceHigh, leaf.Confidence, "a directly-observed endpoint signature is high-confidence evidence")
}

func TestResolve_EndpointSignal_TemplateNotInIndex_NoLeafForIt(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/xmlrpc.php", Method: "POST", StatusCode: 200, Source: "wave3-crawl"},
		},
	}

	tree, _ := Resolve(result, nil) // nil index — this install's corpus doesn't carry wordpress-xmlrpc-detect

	assert.Nil(t, tree.Find("host:example.test"), "a signal whose template isn't in the index must not produce a guaranteed-skip leaf")
}

func TestResolve_WooCommerceTechFact_ProducesMisconfigLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "WooCommerce", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"}},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, leaf, "P1-5: a WooCommerce tech fact must dispatch misconfig, same as the existing wordpress techRule")
}

// --- P1-2: port-driven visibility leaves ---

func TestResolve_InterestingPortOpen_ProducesUnresolvedLeaf(t *testing.T) {
	// Port 23 (telnet) has no netservice check (netserviceCheckedPorts) and
	// isn't expected to get one — still the plain visibility-only path. See
	// TestResolve_NetserviceCheckedPortOpen_ProducesDispatchableLeaf below
	// for the covered-port (21/3306/5432/6379/27017) counterpart.
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "staging.example.test", Ports: []recon.PortFact{{Port: 23, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:staging.example.test")
	require.NotNil(t, hostNode, "a naabu-only host (no TechFact/Endpoint) must still produce a host node")
	require.Len(t, agenttask.Leaves(hostNode), 1)
	leaf := agenttask.Leaves(hostNode)[0]
	assert.Equal(t, agenttask.StatusUnresolved, leaf.Status)
	assert.Empty(t, leaf.Detector, "a port-visibility leaf must never dispatch — no loadable check exists for it")
	assert.Contains(t, leaf.Rationale, "23")
	assert.Contains(t, leaf.Rationale, "telnet")
}

// TestResolve_NetserviceCheckedPortOpen_ProducesDispatchableLeaf is Phase 8
// Step 1's counterpart to the visibility-only test above: a port
// netserviceCheckedPorts covers (21/3306/5432/6379/27017 —
// pkg/detectors/netservice) gets promoted straight to a real dispatchable
// "netservice" leaf, Target carrying the port directly, not just a
// StatusUnresolved note. Closes LT-23 (docs/follow-up.md).
func TestResolve_NetserviceCheckedPortOpen_ProducesDispatchableLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "staging.example.test", Ports: []recon.PortFact{{Port: 3306, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:staging.example.test")
	require.NotNil(t, hostNode)
	require.Len(t, agenttask.Leaves(hostNode), 1)
	leaf := agenttask.Leaves(hostNode)[0]
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
	assert.Equal(t, "netservice", leaf.Detector)
	assert.Equal(t, "tcp://staging.example.test:3306", leaf.Target)
	assert.Contains(t, leaf.Rationale, "3306")
	assert.Contains(t, leaf.Rationale, "mysql")
}

// TestResolve_NetserviceCheckedPortOpen_PostgresAndMongo is LT-142's
// counterpart to the MySQL case above, covering the two ports it added to
// netserviceCheckedPorts (PostgreSQL's trust-auth check, MongoDB's
// unauthenticated-listDatabases check) — each on its own host so the two
// dispatchable leaves don't collide.
func TestResolve_NetserviceCheckedPortOpen_PostgresAndMongo(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "pg.example.test", Ports: []recon.PortFact{{Port: 5432, Protocol: "tcp", Source: "naabu"}}},
			{Host: "mongo.example.test", Ports: []recon.PortFact{{Port: 27017, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	pgLeaf := agenttask.Leaves(tree.Find("host:pg.example.test"))[0]
	assert.Equal(t, agenttask.StatusPending, pgLeaf.Status)
	assert.Equal(t, "netservice", pgLeaf.Detector)
	assert.Equal(t, "tcp://pg.example.test:5432", pgLeaf.Target)

	mongoLeaf := agenttask.Leaves(tree.Find("host:mongo.example.test"))[0]
	assert.Equal(t, agenttask.StatusPending, mongoLeaf.Status)
	assert.Equal(t, "netservice", mongoLeaf.Detector)
	assert.Equal(t, "tcp://mongo.example.test:27017", mongoLeaf.Target)
}

// TestResolve_InterestingPortOpen_PopulatesLeafContext confirms P2-2's
// leafContexts map carries the originating PortFact for a port-visibility
// leaf — the real, live gap this closes: resolvePortFacts' Rationale
// sentence ("port %d/%s (%s) open...") never matched
// pkg/llmfallback's old tech-fact-only regex at all, so ResolveLeaf's
// tag-relevance ranking got zero signal for every port leaf before this.
func TestResolve_InterestingPortOpen_PopulatesLeafContext(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "staging.example.test", Ports: []recon.PortFact{{Port: 3306, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, leafContexts := Resolve(result, nil)

	leaf := agenttask.Leaves(tree.Find("host:staging.example.test"))[0]
	ctx, ok := leafContexts[leaf.ID]
	require.True(t, ok, "expected a LeafContext entry for the port leaf's ID")
	require.NotNil(t, ctx.Port)
	assert.Equal(t, 3306, ctx.Port.Port)
	assert.Nil(t, ctx.TechFact, "a port-driven leaf must not carry a TechFact context")
}

func TestResolve_UninterestingPortOpen_NoLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "example.test", Ports: []recon.PortFact{{Port: 80, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	assert.Nil(t, tree.Find("host:example.test"), "port 80 isn't in interestingPorts — must produce no leaf, not noise for every open port")
}

func TestResolve_PortService_PrefersObservedOverStaticTable(t *testing.T) {
	// Port 9200 (elasticsearch) — no netservice check yet, still the
	// plain visibility-only path. See
	// TestResolve_NetservicePortService_PrefersObservedOverStaticTable for
	// the covered-port counterpart.
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "example.test", Ports: []recon.PortFact{{Port: 9200, Protocol: "tcp", Service: "elasticsearch-7.10", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Status == agenttask.StatusUnresolved })
	require.NotNil(t, leaf)
	assert.Contains(t, leaf.Rationale, "elasticsearch-7.10", "naabu's own service string should be used when present, not just the static table's generic name")
}

// TestResolve_NetservicePortService_PrefersObservedOverStaticTable is the
// netservice-dispatched-leaf counterpart (Phase 8 Step 1): the same
// observed-service-string preference applies whether or not the port is
// promoted to a dispatchable leaf.
func TestResolve_NetservicePortService_PrefersObservedOverStaticTable(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "example.test", Ports: []recon.PortFact{{Port: 6379, Protocol: "tcp", Service: "redis-server-6.2", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool {
		return n.Status == agenttask.StatusPending && n.Detector == "netservice"
	})
	require.NotNil(t, leaf)
	assert.Contains(t, leaf.Rationale, "redis-server-6.2", "naabu's own service string should be used when present, not just the static table's generic name")
}

// TestResolve_NetserviceLeaf_TargetSurvivesHTTPBaseURLUpgrade is a
// regression guard for a real bug this test caught (Phase 8 Step 1): the
// LT-93 pass at the end of Resolve's per-host loop upgrades every leaf's
// Target from the bare host to the real scheme://host[:port] HTTP base URL
// recon observed — unconditionally, before the netservice leaf's own
// carefully-built "tcp://host:port" Target existed as a special case. Left
// unguarded, a host with BOTH a real HTTP TechFact (any other detector)
// AND a netservice-covered open port would have its netservice leaf's
// Target silently clobbered back to the HTTP base URL, making the
// detector dial the wrong host:port entirely.
func TestResolve_NetserviceLeaf_TargetSurvivesHTTPBaseURLUpgrade(t *testing.T) {
	result := &recon.ReconResult{
		Target: "https://staging.example.test",
		Hosts: []recon.HostFact{
			{Host: "staging.example.test", Ports: []recon.PortFact{{Port: 21, Protocol: "tcp", Source: "naabu"}}},
		},
		TechStack: []recon.TechFact{{Name: "Nginx", Host: "staging.example.test", Source: "httpx-tech-detect", Confidence: "high"}},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:staging.example.test")
	require.NotNil(t, hostNode)
	netserviceLeaf := findLeaf(t, tree, "staging.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "netservice" })
	require.NotNil(t, netserviceLeaf)
	assert.Equal(t, "tcp://staging.example.test:21", netserviceLeaf.Target)

	misconfigLeaf := findLeaf(t, tree, "staging.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, misconfigLeaf, "the Nginx TechFact must still dispatch a misconfig leaf")
	assert.Equal(t, "https://staging.example.test", misconfigLeaf.Target, "a non-netservice leaf must still get the real HTTP base URL upgrade")
}

// TestResolve_TLSSignal_OpenPort443_ProducesDispatchableLeaf is Phase 8
// Step 2's counterpart to the netservice tests above: a bare open 443 port
// (even with no HTTP-layer probe at all — a naabu-only host, same shape as
// LT-23) is enough on its own to dispatch a "tls" leaf, since
// pkg/detectors/tls dials the port directly.
func TestResolve_TLSSignal_OpenPort443_ProducesDispatchableLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "vpn.example.test", Ports: []recon.PortFact{{Port: 443, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "vpn.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "tls" })
	require.NotNil(t, leaf)
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
	assert.Equal(t, agenttask.ConfidenceHigh, leaf.Confidence)
}

func TestResolve_TLSSignal_OpenPort8443_ProducesDispatchableLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "admin.example.test", Ports: []recon.PortFact{{Port: 8443, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "admin.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "tls" })
	require.NotNil(t, leaf)
}

// TestResolve_TLSSignal_HTTPSEndpoint_ProducesDispatchableLeaf confirms a
// directly-observed https:// EndpointFact alone (no port-scan data at all)
// is also sufficient — the "any host with a live https:// endpoint" half
// of doc17 Step 2's dispatch condition.
func TestResolve_TLSSignal_HTTPSEndpoint_ProducesDispatchableLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "https://example.test",
		Endpoints: []recon.EndpointFact{{URL: "https://example.test/", Method: "GET", StatusCode: 200, Source: "httpx"}},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "tls" })
	require.NotNil(t, leaf)
	assert.Equal(t, "https://example.test", leaf.Target, "must get the real HTTP base URL upgrade like every other non-netservice leaf")
}

// TestResolve_TLSSignal_HTTPOnlyHost_NoLeaf is the negative case: a host
// recon only ever saw on plain HTTP (port 80, an http:// endpoint) gets no
// "tls" leaf at all — there is no real signal this host speaks TLS
// anywhere to justify one.
func TestResolve_TLSSignal_HTTPOnlyHost_NoLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "example.test", Ports: []recon.PortFact{{Port: 80, Protocol: "tcp", Source: "naabu"}}},
		},
		TechStack: []recon.TechFact{{Name: "Nginx", Host: "example.test", Source: "httpx-tech-detect", Confidence: "high"}},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "tls" })
	assert.Nil(t, leaf)
}

// TestResolve_TLSSignal_PortAndEndpointBothPresent_OneLeafOnly guards
// pendingDedupKey's role here: a host with both an open 443 port *and* a
// directly-observed https:// endpoint (the common case) must still
// produce exactly one "tls" leaf, not two.
func TestResolve_TLSSignal_PortAndEndpointBothPresent_OneLeafOnly(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "https://example.test",
		Hosts:     []recon.HostFact{{Host: "example.test", Ports: []recon.PortFact{{Port: 443, Protocol: "tcp", Source: "naabu"}}}},
		Endpoints: []recon.EndpointFact{{URL: "https://example.test/", Method: "GET", StatusCode: 200, Source: "httpx"}},
	}

	tree, _ := Resolve(result, nil)

	tlsLeaves := 0
	for _, l := range hostLeaves(t, tree, "example.test") {
		if l.Detector == "tls" {
			tlsLeaves++
		}
	}
	assert.Equal(t, 1, tlsLeaves)
}

// TestResolve_MultipleInterestingPorts_AllProduceLeaves is a regression
// guard for a real bug caught against the saved andertone.com recon data
// (staging.andertone.com has both 21 and 3306 open): unresolvedDedupKey
// normalizes via NormalizeTechName, which strips everything after the
// first ':' — an earlier "port:<N>" synthetic name collapsed every port on
// one host down to whichever came first. Must use a separator
// NormalizeTechName doesn't split on.
func TestResolve_MultipleInterestingPorts_AllProduceLeaves(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "staging.example.test", Ports: []recon.PortFact{
				{Port: 21, Protocol: "tcp", Source: "naabu"},
				{Port: 3306, Protocol: "tcp", Source: "naabu"},
				{Port: 80, Protocol: "tcp", Source: "naabu"}, // not in interestingPorts — must not produce a leaf
			}},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:staging.example.test")
	require.NotNil(t, hostNode)
	require.Len(t, agenttask.Leaves(hostNode), 2, "both port 21 and port 3306 must produce their own leaf")
	var rationales []string
	for _, l := range agenttask.Leaves(hostNode) {
		rationales = append(rationales, l.Rationale)
	}
	assert.Contains(t, strings.Join(rationales, "|"), "21")
	assert.Contains(t, strings.Join(rationales, "|"), "3306")
}

func TestResolve_PortLeafAndUnrelatedUnresolvedTechFact_BothSurvive(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "example.test", Ports: []recon.PortFact{{Port: 21, Protocol: "tcp", Source: "naabu"}}},
		},
		TechStack: []recon.TechFact{{Name: "SomeUnknownStack", Host: "example.test", Source: "httpx-tech-detect", Confidence: "low"}},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	// The port leaf's synthetic dedup name ("port:21") must never collide
	// with a real unmatched TechFact's own unresolvedDedupKey — both are
	// genuinely different findings and must both survive as distinct leaves.
	assert.Len(t, agenttask.Leaves(hostNode), 2)
}

// --- LT-3 (docs/follow-up.md): APISpec now dispatches like a TechFact ---

func TestResolve_OpenAPISpec_ProducesMisconfigAndIdorLeaves(t *testing.T) {
	result := &recon.ReconResult{
		Target:  "http://example.test",
		APISpec: &recon.APISpecFact{Kind: "openapi", URL: "http://example.test/swagger.json"},
	}

	tree, _ := Resolve(result, nil)

	misconfig := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, misconfig, "a real swagger.json hit must dispatch misconfig, same as the 'swagger' techRule")
	assert.Equal(t, agenttask.StatusPending, misconfig.Status)
	assert.Equal(t, agenttask.ConfidenceHigh, misconfig.Confidence)
	assert.Contains(t, misconfig.Rationale, "swagger.json")

	idor := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "idor" })
	require.NotNil(t, idor, "the 'swagger' techRule also maps to idor")
}

func TestResolve_GraphQLSpec_ReusesGraphQLTechRule(t *testing.T) {
	result := &recon.ReconResult{
		Target:  "http://example.test",
		APISpec: &recon.APISpecFact{Kind: "graphql-sdl", URL: "http://example.test/graphql"},
	}

	tree, _ := Resolve(result, nil)

	misconfig := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "misconfig" })
	require.NotNil(t, misconfig, "graphql-sdl must reuse the 'graphql' techRule's capabilities")
}

func TestResolve_APISpec_UnrecognizedKind_NoLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:  "http://example.test",
		APISpec: &recon.APISpecFact{Kind: "something-new", URL: "http://example.test/spec"},
	}

	tree, _ := Resolve(result, nil)

	assert.Nil(t, tree.Find("host:example.test"), "an unrecognized Kind must produce no leaf and no empty host node (P0-5), not a guess")
}

// TestResolve_APISpec_HostOnlyKnownViaSpec_StillGetsHostNode guards the
// defensive addHost call: an APISpecFact whose host never appears in
// TechStack/Endpoints/Hosts must still surface a host node, not be silently
// dropped from the tree.
func TestResolve_APISpec_HostOnlyKnownViaSpec_StillGetsHostNode(t *testing.T) {
	result := &recon.ReconResult{
		Target:  "http://example.test",
		APISpec: &recon.APISpecFact{Kind: "openapi", URL: "http://spec-only.example.test/swagger.json"},
	}

	tree, _ := Resolve(result, nil)

	assert.NotNil(t, tree.Find("host:spec-only.example.test"))
}

// TestResolve_APISpec_DoesNotLeakOntoUnrelatedHost guards addAPISpec's
// "first one wins, global, not per-host" storage (pkg/recon/aggregate.go):
// a multi-host recon run must dispatch the spec-derived leaves only to the
// host its URL actually names, never to every host in the tree.
func TestResolve_APISpec_DoesNotLeakOntoUnrelatedHost(t *testing.T) {
	result := &recon.ReconResult{
		Target: "http://example.test",
		TechStack: []recon.TechFact{
			{Name: "TotallyUnknownStack", Host: "other.example.test", Source: "httpx-tech-detect", Confidence: "low"},
		},
		APISpec: &recon.APISpecFact{Kind: "openapi", URL: "http://example.test/swagger.json"},
	}

	tree, _ := Resolve(result, nil)

	otherHost := tree.Find("host:other.example.test")
	require.NotNil(t, otherHost)
	for _, leaf := range agenttask.Leaves(otherHost) {
		assert.NotEqual(t, "misconfig", leaf.Detector, "the api spec belongs to example.test, not other.example.test")
	}
}

// TestResolve_APISpec_DedupsAgainstExistingTechFactLeaf guards P0-4 for this
// new path: a host that already has a real "Swagger UI" TechFact (fingerprint
// matched the UI page) plus a swagger.json APISpecFact must still produce
// exactly one misconfig leaf, not two.
func TestResolve_APISpec_DedupsAgainstExistingTechFactLeaf(t *testing.T) {
	result := &recon.ReconResult{
		Target:    "http://example.test",
		TechStack: []recon.TechFact{{Name: "Swagger UI", Host: "example.test", Source: "fingerprint-body", Confidence: "high"}},
		APISpec:   &recon.APISpecFact{Kind: "openapi", URL: "http://example.test/swagger.json"},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	misconfigLeaves := 0
	for _, leaf := range agenttask.Leaves(hostNode) {
		if leaf.Detector == "misconfig" {
			misconfigLeaves++
		}
	}
	assert.Equal(t, 1, misconfigLeaves, "a TechFact-driven and an APISpec-driven misconfig leaf on the same host must dedup to one")
}

func TestResolve_APISpec_MatchesTemplateTags(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "swagger-api-docs", Tags: []string{"swagger", "exposure"}},
		{ID: "unrelated-template", Tags: []string{"wordpress"}},
	}
	result := &recon.ReconResult{
		Target:  "http://example.test",
		APISpec: &recon.APISpecFact{Kind: "openapi", URL: "http://example.test/swagger.json"},
	}

	tree, _ := Resolve(result, index)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "swagger-api-docs" })
	require.NotNil(t, leaf, "an openapi spec should also rank synced templates tagged 'swagger', same as a real swagger TechFact would")
}

// TestResolve_RedirectFlowEndpoint_DispatchesOpenRedirectCheck guards LT-77
// (Phase 8 Step 5): a redirect/OAuth-flow-shaped endpoint dispatches the
// corpus's generic open-redirect check against the host.
func TestResolve_RedirectFlowEndpoint_DispatchesOpenRedirectCheck(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "open-redirect-generic", Tags: []string{"redirect"}},
	}
	result := &recon.ReconResult{
		Target: "http://example.test",
		Endpoints: []recon.EndpointFact{
			{URL: "http://example.test/accounts/bounce", Method: "GET", StatusCode: 302, Source: "sitemap-xml", Confidence: "low"},
			{URL: "http://example.test/about", Method: "GET", StatusCode: 200, Source: "katana-crawl", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, index)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "open-redirect-generic" })
	require.NotNil(t, leaf, "a */bounce endpoint must dispatch the generic open-redirect template (LT-77)")
	assert.Equal(t, agenttask.StatusPending, leaf.Status)
	assert.Contains(t, leaf.Rationale, "LT-77")
}

func TestResolve_NoRedirectFlowEndpoint_NoOpenRedirectLeaf(t *testing.T) {
	index := []templatesync.Entry{{ID: "open-redirect-generic", Tags: []string{"redirect"}}}
	result := &recon.ReconResult{
		Target:    "http://example.test",
		Endpoints: []recon.EndpointFact{{URL: "http://example.test/products/42", Method: "GET", StatusCode: 200, Source: "katana-crawl", Confidence: "medium"}},
	}
	tree, _ := Resolve(result, index)
	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "open-redirect-generic" })
	assert.Nil(t, leaf, "a plain product path must not dispatch the open-redirect check")
}

// TestResolve_TechEndpointSignature_PromotesConfidence guards LT-50 (Phase 8
// Step 6): a product-distinctive endpoint on the same host as its tech fact
// promotes that host's pending product leaves to ConfidenceHigh.
func TestResolve_TechEndpointSignature_PromotesConfidence(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "jira-unauth-dashboards", Tags: []string{"jira", "exposure"}},
	}
	result := &recon.ReconResult{
		Target:    "http://jira.example.test",
		TechStack: []recon.TechFact{{Name: "Jira", Host: "jira.example.test", Source: "httpx-tech-detect", Confidence: "low"}},
		Endpoints: []recon.EndpointFact{
			{URL: "http://jira.example.test/secure/Dashboard.jspa", Method: "GET", StatusCode: 200, Source: "katana-crawl", Confidence: "medium"},
		},
	}

	tree, _ := Resolve(result, index)

	leaf := findLeaf(t, tree, "jira.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "jira-unauth-dashboards" })
	require.NotNil(t, leaf)
	assert.Equal(t, agenttask.ConfidenceHigh, leaf.Confidence, "an observed Jira-distinctive endpoint must promote the Jira leaf (LT-50)")
	assert.Contains(t, leaf.Rationale, "LT-50")
}

func TestResolve_TechEndpointSignature_NoHitLeavesConfidenceAlone(t *testing.T) {
	index := []templatesync.Entry{{ID: "jira-unauth-dashboards", Tags: []string{"jira", "exposure"}}}
	result := &recon.ReconResult{
		Target:    "http://jira.example.test",
		TechStack: []recon.TechFact{{Name: "Jira", Host: "jira.example.test", Source: "httpx-tech-detect", Confidence: "low"}},
		Endpoints: []recon.EndpointFact{
			{URL: "http://jira.example.test/some/unrelated/path", Method: "GET", StatusCode: 200, Source: "katana-crawl", Confidence: "medium"},
		},
	}
	tree, _ := Resolve(result, index)
	leaf := findLeaf(t, tree, "jira.example.test", func(n *agenttask.PlanNode) bool { return n.Detector == "jira-unauth-dashboards" })
	require.NotNil(t, leaf)
	assert.Equal(t, agenttask.ConfidenceLow, leaf.Confidence, "no signature endpoint -> the fingerprint's own confidence stands")
}
