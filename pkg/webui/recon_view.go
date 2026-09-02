package webui

import (
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/recon"
)

// ReconResultView wraps a *recon.ReconResult for display purposes only —
// fillReconFields and every other pkg/webui consumer still reads the real
// recon.ReconResult directly; this exists solely so fragment_recon_results
// doesn't have to render EndpointFacts one-for-one (docs/14-implementation-
// plan-ph5.md Step 7's UI-polish pass, prompted by a real recon run against
// an external target: the same CDN image path showed up as 18 near-
// identical Endpoints rows, differing only by a cosmetic resize query
// string — noise a human operator has to scroll past for zero benefit).
type ReconResultView struct {
	*recon.ReconResult
	DisplayEndpoints []EndpointRow
}

// EndpointRow is one collapsed row: the first-seen EndpointFact matching
// its group, plus how many query-string variants of the same scheme+host+
// path+method were folded into it.
type EndpointRow struct {
	recon.EndpointFact
	VariantCount int
	DisplayURL   string // URL, truncated for the table — see maxDisplayURLLen
}

// maxDisplayURLLen caps how much of a URL the Endpoints table shows inline —
// found live against a real external target: long CDN/bundler paths and
// hashed JS chunk filenames pushed the table wider than any reasonably-sized
// viewport for zero benefit. The full value is never lost: it's still in the
// row's own `title` attribute (hover to see it) and in the real
// recon.ReconResult everything else (fillReconFields, the JSON export) reads
// — this only shortens what's inlined into the table cell.
const maxDisplayURLLen = 60

func truncateForDisplay(s string) string {
	if len(s) <= maxDisplayURLLen {
		return s
	}
	return s[:maxDisplayURLLen-1] + "…"
}

// newReconView returns nil for a nil result so fragment_recon_results'
// {{if .}} guard still sees "recon hasn't produced anything yet", not an
// empty-but-non-nil wrapper.
func newReconView(r *recon.ReconResult) *ReconResultView {
	if r == nil {
		return nil
	}
	return &ReconResultView{ReconResult: r, DisplayEndpoints: collapseEndpoints(r.Endpoints)}
}

// collapseEndpoints groups facts by scheme+host+path+method, ignoring the
// query string — the same "query params are cosmetic noise, not a distinct
// endpoint" call pkg/recon/suggest.go's idShapedPathCandidate already makes
// for IDOR-candidate generation, applied here to the raw display table too.
// A row's displayed URL drops its query string once a second variant
// arrives, so the surviving representative doesn't imply that one
// particular variant was special.
func collapseEndpoints(facts []recon.EndpointFact) []EndpointRow {
	type key struct{ scheme, host, path, method string }

	order := make([]key, 0, len(facts))
	rows := make(map[key]*EndpointRow, len(facts))

	for _, ep := range facts {
		k := key{method: ep.Method}
		if u, err := url.Parse(ep.URL); err == nil && u.Host != "" {
			k.scheme, k.host, k.path = u.Scheme, u.Host, u.Path
		} else {
			k.path = ep.URL // fallback: dedupe by the raw string verbatim
		}

		if row, ok := rows[k]; ok {
			row.VariantCount++
			if row.VariantCount == 2 {
				row.URL = stripQuery(row.URL)
			}
			continue
		}
		row := &EndpointRow{EndpointFact: ep, VariantCount: 1}
		rows[k] = row
		order = append(order, k)
	}

	result := make([]EndpointRow, 0, len(order))
	for _, k := range order {
		row := *rows[k]
		row.DisplayURL = truncateForDisplay(row.URL)
		result = append(result, row)
	}
	return result
}

func stripQuery(rawURL string) string {
	if i := strings.IndexByte(rawURL, '?'); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}
