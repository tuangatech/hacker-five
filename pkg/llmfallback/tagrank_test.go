package llmfallback

import (
	"strconv"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func TestTechNameFromRationale(t *testing.T) {
	got := techNameFromRationale(`tech fact "GraphQL" (source: fingerprint-header) matched no registry capability or template tag`)
	if got != "GraphQL" {
		t.Fatalf("got %q, want %q", got, "GraphQL")
	}
}

func TestTechNameFromRationale_NoMatch(t *testing.T) {
	if got := techNameFromRationale("some unrelated rationale"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestRankRelevantTags_ExactBeatsSubstringBeatsWordOverlap(t *testing.T) {
	templates := []templatesync.Entry{
		{ID: "t1", Tags: []string{"graphql"}},                       // exact
		{ID: "t2", Tags: []string{"graphql-introspection"}},         // substring
		{ID: "t3", Tags: []string{"misconfig"}},                     // no relation
		{ID: "t4", Tags: []string{"api", "introspection-endpoint"}}, // word overlap via "introspection" isn't in techName, so no match expected
	}
	got := rankRelevantTags("GraphQL", templates, 10)
	if len(got) < 2 {
		t.Fatalf("expected at least 2 relevant tags, got %v", got)
	}
	if got[0] != "graphql" {
		t.Fatalf("expected exact match \"graphql\" ranked first, got %v", got)
	}
	found := false
	for _, tag := range got {
		if tag == "graphql-introspection" {
			found = true
		}
		if tag == "misconfig" {
			t.Fatalf("unrelated tag %q should not be ranked as relevant, got %v", tag, got)
		}
	}
	if !found {
		t.Fatalf("expected substring match \"graphql-introspection\" present, got %v", got)
	}
}

func TestRankRelevantTags_WordOverlap(t *testing.T) {
	templates := []templatesync.Entry{
		{ID: "t1", Tags: []string{"apache"}},
		{ID: "t2", Tags: []string{"unrelated"}},
	}
	got := rankRelevantTags("Apache HTTP Server", templates, 10)
	if len(got) != 1 || got[0] != "apache" {
		t.Fatalf("expected word-overlap match [\"apache\"], got %v", got)
	}
}

func TestRankRelevantTags_EmptyTechNameReturnsNil(t *testing.T) {
	templates := []templatesync.Entry{{ID: "t1", Tags: []string{"graphql"}}}
	if got := rankRelevantTags("", templates, 10); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestRankRelevantTags_RespectsLimit(t *testing.T) {
	templates := []templatesync.Entry{
		{ID: "t1", Tags: []string{"wordpress"}},
		{ID: "t2", Tags: []string{"wordpress-plugin"}},
		{ID: "t3", Tags: []string{"wordpress-theme"}},
	}
	got := rankRelevantTags("wordpress", templates, 1)
	if len(got) != 1 {
		t.Fatalf("got %d tags, want exactly 1 (limit)", len(got))
	}
	if got[0] != "wordpress" {
		t.Fatalf("got %v, want exact match ranked first within the limit", got)
	}
}

// TestRankRelevantTemplates_DedupsByIDAcrossTags confirms a template with
// several tags appears once, ranked by its best-scoring tag, and a template
// with no relevant tag at all is dropped (P2-3: buildLeafPrompt shows the
// model dispatchable template IDs, so a duplicate ID would be misleading).
func TestRankRelevantTemplates_DedupsByIDAcrossTags(t *testing.T) {
	templates := []templatesync.Entry{
		{ID: "t1", Tags: []string{"graphql", "misconfig"}},
		{ID: "t2", Tags: []string{"graphql-introspection"}},
		{ID: "t3", Tags: []string{"unrelated"}},
	}
	got := rankRelevantTemplates("GraphQL", templates, 10)
	if len(got) != 2 {
		t.Fatalf("got %d templates, want 2 (t3 has no relevant tag), got %+v", len(got), got)
	}
	if got[0].ID != "t1" {
		t.Fatalf("expected exact tag match t1 ranked first, got %+v", got)
	}
}

// TestBuildLeafPrompt_SurfacesRelevantTemplateEvenWhenNotInFixedOrderPrefix
// locks in the real bug this fix addresses: a relevant template that would
// previously never appear in the prompt (parked past the old
// fixed-order-only 200-tag cutoff) now surfaces regardless of its position
// in the underlying slice. Each filler entry needs its own distinct ID —
// buildLeafPrompt dedups by template ID (P2-3: it lists dispatchable
// template IDs, not shared tags), so entries sharing one ID would collapse
// to a single line and trivially leave room for "real" regardless of
// ranking, defeating the point of this test.
func TestBuildLeafPrompt_SurfacesRelevantTemplateEvenWhenNotInFixedOrderPrefix(t *testing.T) {
	templates := make([]templatesync.Entry, 0, 250)
	for i := 0; i < 249; i++ {
		templates = append(templates, templatesync.Entry{ID: "filler-" + strconv.Itoa(i), Tags: []string{padTag(i)}})
	}
	templates = append(templates, templatesync.Entry{ID: "real-graphql-introspection", Name: "GraphQL Introspection Enabled", Tags: []string{"graphql-introspection"}})

	leaf := &agenttask.PlanNode{
		Target:    "example.com",
		Rationale: `tech fact "GraphQL" (source: fingerprint-header) matched no registry capability or template tag`,
	}
	prompt := buildLeafPrompt(leaf, registry.LeafContext{}, nil, templates)
	if !strings.Contains(prompt, "real-graphql-introspection") {
		t.Fatalf("expected the relevant template's id to be surfaced in the prompt despite being last in the underlying slice")
	}
}

// TestTechNameForRanking_PrefersLeafContextOverRationale confirms P2-2's
// structured LeafContext wins over the Rationale-regex fallback whenever
// both are present — a deliberately mismatched Rationale here proves which
// source actually won.
func TestTechNameForRanking_PrefersLeafContextOverRationale(t *testing.T) {
	leaf := &agenttask.PlanNode{Rationale: `tech fact "WrongName" matched no registry capability or template tag`}
	ctx := registry.LeafContext{TechFact: &recon.TechFact{Name: "RightName"}}
	if got := techNameForRanking(leaf, ctx); got != "RightName" {
		t.Fatalf("got %q, want %q (LeafContext.TechFact must win over Rationale)", got, "RightName")
	}
}

// TestTechNameForRanking_PortContextUsesServiceName confirms a port leaf's
// LeafContext (no TechFact at all) ranks by the port's own service name —
// the real gap P2-2 closes: the old Rationale-regex path never matched a
// port leaf's sentence shape, so this used to always be "".
func TestTechNameForRanking_PortContextUsesServiceName(t *testing.T) {
	leaf := &agenttask.PlanNode{Rationale: "port 3306/tcp (mysql) open (source: naabu) — no automated check exists yet for this protocol; manually verify"}
	ctx := registry.LeafContext{Port: &recon.PortFact{Port: 3306, Service: "mysql"}}
	if got := techNameForRanking(leaf, ctx); got != "mysql" {
		t.Fatalf("got %q, want %q", got, "mysql")
	}
}

// TestTechNameForRanking_FallsBackToRationaleWhenNoContext confirms a
// zero-value LeafContext (a caller with nothing to hand, e.g. a cached tree
// with no context alongside it — see pkg/webui/handlers_plan.go) still
// resolves a usable tech name via the old regex path, not "".
func TestTechNameForRanking_FallsBackToRationaleWhenNoContext(t *testing.T) {
	leaf := &agenttask.PlanNode{Rationale: `tech fact "GraphQL" (source: fingerprint-header) matched no registry capability or template tag`}
	if got := techNameForRanking(leaf, registry.LeafContext{}); got != "GraphQL" {
		t.Fatalf("got %q, want %q", got, "GraphQL")
	}
}

func padTag(i int) string {
	return "filler-tag-" + strconv.Itoa(i)
}
