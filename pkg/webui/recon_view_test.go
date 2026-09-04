package webui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	rows, _ := collapseEndpoints(facts)

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

	rows, _ := collapseEndpoints(facts)

	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	for _, row := range rows {
		if row.VariantCount != 1 {
			t.Errorf("VariantCount for %s = %d, want 1", row.URL, row.VariantCount)
		}
	}
}

// TestCollapseEndpoints_WwwAndCaseHostVariants_Collapses guards the LT-14
// fix (docs/follow-up.md): this table's dedup key used the raw, un-
// normalized host, so the same path crawled via www./bare/mixed-case host
// variants (real example: www.nettix.com.pe, Nettix.com.pe, nettix.com.pe)
// produced separate rows instead of one collapsed row with a VariantCount
// — the identical latent gap aggregator.addTech had for the Tech Stack
// table (see pkg/recon/aggregate_test.go's matching test).
func TestCollapseEndpoints_WwwAndCaseHostVariants_Collapses(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://www.nettix.com.pe/a", Method: "GET"},
		{URL: "https://Nettix.com.pe/a", Method: "GET"},
		{URL: "https://nettix.com.pe/a", Method: "GET"},
	}

	rows, _ := collapseEndpoints(facts)

	require.Len(t, rows, 1, "www./bare/mixed-case host variants of the same site must collapse into one row")
	assert.Equal(t, 3, rows[0].VariantCount)
}

func TestCollapseEndpoints_SamePathDifferentMethod_NotCollapsed(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://example.com/a", Method: "GET"},
		{URL: "https://example.com/a", Method: "POST"},
	}

	rows, _ := collapseEndpoints(facts)

	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
}

func TestCollapseEndpoints_SingleOccurrence_KeepsQuery(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://example.com/reset?token=abc", Method: "GET"},
	}

	rows, _ := collapseEndpoints(facts)

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

// TestCollapseEndpoints_StaticAssets_CountedNotRendered guards the
// Endpoints table declutter fix (2026-09-04): a real target's hashed JS/CSS
// bundle chunks made up 44% of its raw Endpoints — indistinguishable from a
// real application route in the table. Static-asset facts must still be
// counted (AssetEndpointCount, via the second return value here) but not
// turned into a row.
func TestCollapseEndpoints_StaticAssets_CountedNotRendered(t *testing.T) {
	facts := []recon.EndpointFact{
		{URL: "https://example.com/_next/static/chunks/a325368d458362b0.js", Method: "GET"},
		{URL: "https://example.com/_next/static/chunks/aee6c7720838f8a2.css", Method: "GET"},
		{URL: "https://example.com/en/about", Method: "GET"},
	}

	rows, assetCount := collapseEndpoints(facts)

	require.Len(t, rows, 1)
	assert.Equal(t, "https://example.com/en/about", rows[0].URL)
	assert.Equal(t, 2, assetCount)
}

// TestCollapseEndpoints_RootPath_NotTreatedAsJunk guards against a
// classifier regression: the homepage root ("/", no file extension, no
// alphanumeric path content) must still render as a row — it's real
// signal, not noise, unlike SuggestAuthBypassPathsFromRecon's own narrower
// "protected-path candidate" classifier, which can afford to drop it.
func TestCollapseEndpoints_RootPath_NotTreatedAsJunk(t *testing.T) {
	facts := []recon.EndpointFact{{URL: "https://example.com/", Method: "GET", Source: "httpx"}}

	rows, assetCount := collapseEndpoints(facts)

	require.Len(t, rows, 1, "the homepage root must still be displayed, not miscategorized as junk")
	assert.Equal(t, 0, assetCount)
}

func TestCollapseEndpoints_LongURL_DisplayURLTruncated_FullURLPreserved(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", 80)
	facts := []recon.EndpointFact{{URL: long, Method: "GET"}}

	rows, _ := collapseEndpoints(facts)

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
