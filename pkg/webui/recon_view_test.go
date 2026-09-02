package webui

import (
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/recon"
)

func TestNewReconView_Nil(t *testing.T) {
	if v := newReconView(nil); v != nil {
		t.Fatalf("newReconView(nil) = %v, want nil", v)
	}
}

func TestCollapseEndpoints_SamePathDifferentQuery_Collapses(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://example.com/img/abc?w=96", Method: "GET", Source: "katana-crawl"},
		{URL: "https://example.com/img/abc?h=48&dpr=3", Method: "GET", Source: "katana-crawl"},
		{URL: "https://example.com/img/abc?w=32", Method: "GET", Source: "katana-crawl"},
	}

	rows := collapseEndpoints(facts)

	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].VariantCount != 3 {
		t.Fatalf("VariantCount = %d, want 3", rows[0].VariantCount)
	}
	if rows[0].URL != "https://example.com/img/abc" {
		t.Fatalf("URL = %q, want query stripped once collapsed", rows[0].URL)
	}
}

func TestCollapseEndpoints_DistinctPaths_NotCollapsed(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://example.com/a", Method: "GET"},
		{URL: "https://example.com/b", Method: "GET"},
	}

	rows := collapseEndpoints(facts)

	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	for _, row := range rows {
		if row.VariantCount != 1 {
			t.Errorf("VariantCount for %s = %d, want 1", row.URL, row.VariantCount)
		}
	}
}

func TestCollapseEndpoints_SamePathDifferentMethod_NotCollapsed(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://example.com/a", Method: "GET"},
		{URL: "https://example.com/a", Method: "POST"},
	}

	rows := collapseEndpoints(facts)

	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
}

func TestCollapseEndpoints_SingleOccurrence_KeepsQuery(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://example.com/reset?token=abc", Method: "GET"},
	}

	rows := collapseEndpoints(facts)

	if len(rows) != 1 || rows[0].URL != "https://example.com/reset?token=abc" {
		t.Fatalf("rows = %+v, want the single fact's query preserved", rows)
	}
}

func TestTruncateForDisplay_ShortURL_Unchanged(t *testing.T) {
	short := "https://example.com/a"
	if got := truncateForDisplay(short); got != short {
		t.Fatalf("truncateForDisplay(%q) = %q, want unchanged", short, got)
	}
}

func TestTruncateForDisplay_LongURL_Truncated(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", 80)

	got := truncateForDisplay(long)

	if len(got) != maxDisplayURLLen-1+len("…") {
		t.Fatalf("truncateForDisplay result length = %d, want %d", len(got), maxDisplayURLLen-1+len("…"))
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("truncateForDisplay(%q) = %q, want an ellipsis suffix", long, got)
	}
	if !strings.HasPrefix(long, strings.TrimSuffix(got, "…")) {
		t.Fatalf("truncateForDisplay(%q) = %q, want a prefix of the original URL", long, got)
	}
}

func TestCollapseEndpoints_LongURL_DisplayURLTruncated_FullURLPreserved(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", 80)
	facts := []recon.EndpointFact{{URL: long, Method: "GET"}}

	rows := collapseEndpoints(facts)

	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1", len(rows))
	}
	if rows[0].URL != long {
		t.Fatalf("URL = %q, want the full, untruncated value preserved", rows[0].URL)
	}
	if rows[0].DisplayURL == long {
		t.Fatalf("DisplayURL should be truncated for a URL this long")
	}
}
