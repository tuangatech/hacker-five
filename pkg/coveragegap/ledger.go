// Package coveragegap implements LT-107 (docs/16-implementation-plan-ph7.md
// Step 7, rung 1 of the end-of-scan re-plan ladder): a deterministic, no-LLM
// post-scan pass that reports which fingerprinted (host, product) pairs
// nothing actually covered — no native detector rule, no loaded
// template-tag match.
package coveragegap

import (
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// ReasonNoCoverage is the only Reason value Ledger currently emits: neither
// a native detector rule nor a loaded template tag matched the fact.
const ReasonNoCoverage = "no-coverage"

// GapRow is one uncovered (host, product) pair.
type GapRow struct {
	Host    string `json:"host"`
	Product string `json:"product"`
	Reason  string `json:"reason"`
}

// Ledger cross-references a recon-fingerprinted tech stack against a job's
// loaded template set and returns one GapRow per (host, product) that
// nothing covered. Pure function — no I/O, no LLM call. A TechFact
// registry.CoverageStatus reports as non-actionable (a transport/protocol
// fact, a CDN brand, ...) never produces a row: it legitimately has no
// scannable surface of its own, not a gap.
func Ledger(techStack []recon.TechFact, loaded []templatesync.Entry) []GapRow {
	var rows []GapRow
	for _, fact := range techStack {
		hasNative, hasTemplate, nonActionable := registry.CoverageStatus(fact.Name, loaded)
		if nonActionable || hasNative || hasTemplate {
			continue
		}
		rows = append(rows, GapRow{Host: fact.Host, Product: fact.Name, Reason: ReasonNoCoverage})
	}
	return rows
}
