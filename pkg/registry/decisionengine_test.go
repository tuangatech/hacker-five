package registry

import (
	"fmt"
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

	tree := Resolve(result, index)

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

	tree := Resolve(result, nil)

	require.NotNil(t, tree.Find("host:a.example.test"))
	require.NotNil(t, tree.Find("host:b.example.test"))
	assert.Len(t, tree.Root.Children, 2)
}

func TestResolve_NoTechFacts_ProducesEmptyRoot(t *testing.T) {
	tree := Resolve(&recon.ReconResult{Target: "http://example.test"}, nil)
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

	tree := Resolve(result, nil)

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

	tree := Resolve(result, nil)

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

	tree := Resolve(result, nil)

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

	tree := Resolve(result, nil)

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

	tree := Resolve(result, index)

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
