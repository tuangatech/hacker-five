package scanner

import (
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/coveragegap"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/template/native"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// loadedTemplateEntries adapts the job's actual loaded (post tag/ID-filter)
// template set into the minimal shape pkg/coveragegap.Ledger needs — ID and
// Tags only, mirroring templatesync.Entry so the ledger never has to import
// pkg/template/nuclei or pkg/template/native directly. Nuclei's tags are a
// single comma-separated Info.Tags string; native's are already []string.
func loadedTemplateEntries(nucleiTemplates []*nuclei.Template, nativeTemplates []*native.Template) []templatesync.Entry {
	entries := make([]templatesync.Entry, 0, len(nucleiTemplates)+len(nativeTemplates))
	for _, t := range nucleiTemplates {
		var tags []string
		for _, tag := range strings.Split(t.Info.Tags, ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				tags = append(tags, tag)
			}
		}
		entries = append(entries, templatesync.Entry{ID: t.ID, Tags: tags})
	}
	for _, t := range nativeTemplates {
		entries = append(entries, templatesync.Entry{ID: t.ID, Tags: t.Tags})
	}
	return entries
}

// coverageGapSlug builds a stable, unique-per-(host,product) Finding.ID
// suffix — same "replace the awkward characters" idiom as
// llmfallback/resolve.go's writeProposedTemplate uses for a proposed
// template's filename.
var coverageGapSlugReplacer = strings.NewReplacer(
	" ", "-", "/", "-", ":", "-", "_", "-",
)

func coverageGapSlug(s string) string {
	return strings.ToLower(coverageGapSlugReplacer.Replace(strings.TrimSpace(s)))
}

// coverageGapFindings runs LT-107's end-of-scan coverage-gap ledger
// (docs/16-implementation-plan-ph7.md Step 7) and converts each GapRow into
// an ordinary info-severity Finding — no new report/exporter shape needed,
// it flows through reporter.Dedup and every Exporter exactly like a real
// finding, and `hackerfive suggest` (LT-108) reads it back out of a scan
// output file by its "coverage-gap-" ID prefix.
func coverageGapFindings(techStack []recon.TechFact, loaded []templatesync.Entry) []detectors.Finding {
	rows := coveragegap.Ledger(techStack, loaded)
	findings := make([]detectors.Finding, 0, len(rows))
	for _, row := range rows {
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("coverage-gap-%s-%s", coverageGapSlug(row.Host), coverageGapSlug(row.Product)),
			Type:        "info",
			Severity:    "info",
			Confidence:  "high",
			Target:      row.Host,
			Description: fmt.Sprintf("recon fingerprinted %q on %s but no native detector rule and no loaded template tag covers it — this scan did not actually check it", row.Product, row.Host),
			Evidence:    map[string]string{"product": row.Product, "reason": row.Reason},
		})
	}
	return findings
}
