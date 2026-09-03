package llmfallback

import (
	"strconv"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
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

// TestBuildLeafPrompt_SurfacesRelevantTagEvenWhenNotInFixedOrderPrefix locks
// in the real bug this fix addresses: a relevant tag that would previously
// never appear in the prompt (parked past the old fixed-order-only 200-tag
// cutoff) now surfaces regardless of its position in the underlying slice.
func TestBuildLeafPrompt_SurfacesRelevantTagEvenWhenNotInFixedOrderPrefix(t *testing.T) {
	templates := make([]templatesync.Entry, 0, 250)
	for i := 0; i < 249; i++ {
		templates = append(templates, templatesync.Entry{ID: "filler", Tags: []string{padTag(i)}})
	}
	templates = append(templates, templatesync.Entry{ID: "real", Tags: []string{"graphql-introspection"}})

	leaf := &agenttask.PlanNode{
		Target:    "example.com",
		Rationale: `tech fact "GraphQL" (source: fingerprint-header) matched no registry capability or template tag`,
	}
	prompt := buildLeafPrompt(leaf, nil, templates)
	if !strings.Contains(prompt, "graphql-introspection") {
		t.Fatalf("expected the relevant tag to be surfaced in the prompt despite being last in the underlying slice")
	}
}

func padTag(i int) string {
	return "filler-tag-" + strconv.Itoa(i)
}
