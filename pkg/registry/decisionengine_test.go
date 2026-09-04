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

	tree, _ := Resolve(result, nil)

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

	tree, _ := Resolve(result, nil)

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

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:example.test")
	require.NotNil(t, hostNode)
	require.Len(t, hostNode.Children, 1)
	rationale := hostNode.Children[0].Rationale
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

	leaf := tree.Find("host:example.test").Children[0]
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

	leaf := tree.Find("host:example.test").Children[0]
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

	tree, _ := Resolve(result, index)

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

	tree, _ := Resolve(result, index)

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
	require.Len(t, hostNode.Children, 1, "only the PHP fact should produce a leaf")
	assert.Equal(t, "misconfig", hostNode.Children[0].Detector)
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
	for _, leaf := range hostNode.Children {
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
	require.Len(t, hostNode.Children, 1, "the same unknown product from two sources must produce one unresolved leaf")
	assert.Equal(t, agenttask.StatusUnresolved, hostNode.Children[0].Status)
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
	for _, leaf := range hostNode.Children {
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
		{ID: "ingress-nginx-CVE-2023-5044", Name: "Ingress-Nginx Annotation Injection", Tags: []string{"nginx", "ingress-nginx", "cve"}, Severity: "critical"},
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

// --- LT-16 (docs/follow-up.md): TechStackTags ---

// TestTechStackTags_UnionsRelevantEntryTags confirms the basic shape: the
// tags of every entry matchTemplateTags ranks as relevant to a detected
// tech are unioned into one deduped, sorted allowlist.
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

	assert.ElementsMatch(t, []string{"wordpress", "panel", "nginx", "cve"}, got, "must union both relevant entries' tags, not just the first tech's")
}

// TestTechStackTags_FalseFriendExclusionApplies confirms canonicalTechTags'
// exclusions (already proven for matchTemplateTags itself) carry through:
// an "Nginx" fact must not pull in the ingress-nginx-only tag.
func TestTechStackTags_FalseFriendExclusionApplies(t *testing.T) {
	index := []templatesync.Entry{
		{ID: "CVE-2099-0001", Name: "Nginx - Real Thing", Tags: []string{"nginx", "cve"}, Severity: "high"},
		{ID: "ingress-nginx-CVE-2023-5044", Name: "Ingress-Nginx Annotation Injection", Tags: []string{"nginx", "ingress-nginx", "cve"}, Severity: "critical"},
	}
	got := TechStackTags([]recon.TechFact{{Name: "Nginx", Host: "example.com"}}, index)

	assert.ElementsMatch(t, []string{"nginx", "cve"}, got, "the ingress-nginx-only entry must never have contributed \"ingress-nginx\" to the allowlist")
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
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "staging.example.test", Ports: []recon.PortFact{{Port: 3306, Protocol: "tcp", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	hostNode := tree.Find("host:staging.example.test")
	require.NotNil(t, hostNode, "a naabu-only host (no TechFact/Endpoint) must still produce a host node")
	require.Len(t, hostNode.Children, 1)
	leaf := hostNode.Children[0]
	assert.Equal(t, agenttask.StatusUnresolved, leaf.Status)
	assert.Empty(t, leaf.Detector, "a port-visibility leaf must never dispatch — no loadable check exists for it")
	assert.Contains(t, leaf.Rationale, "3306")
	assert.Contains(t, leaf.Rationale, "mysql")
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

	leaf := tree.Find("host:staging.example.test").Children[0]
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
	result := &recon.ReconResult{
		Target: "http://example.test",
		Hosts: []recon.HostFact{
			{Host: "example.test", Ports: []recon.PortFact{{Port: 6379, Protocol: "tcp", Service: "redis-server-6.2", Source: "naabu"}}},
		},
	}

	tree, _ := Resolve(result, nil)

	leaf := findLeaf(t, tree, "example.test", func(n *agenttask.PlanNode) bool { return n.Status == agenttask.StatusUnresolved })
	require.NotNil(t, leaf)
	assert.Contains(t, leaf.Rationale, "redis-server-6.2", "naabu's own service string should be used when present, not just the static table's generic name")
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
	require.Len(t, hostNode.Children, 2, "both port 21 and port 3306 must produce their own leaf")
	var rationales []string
	for _, l := range hostNode.Children {
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
	assert.Len(t, hostNode.Children, 2)
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
	for _, leaf := range otherHost.Children {
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
	for _, leaf := range hostNode.Children {
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
