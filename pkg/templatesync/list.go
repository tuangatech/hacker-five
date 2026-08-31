package templatesync

import (
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/template/native"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// Entry is one loaded template, flattened for display — no Category field:
// neither nuclei.Info nor native.Info has one (confirmed against
// pkg/template/{nuclei,native}/schema.go), so a template's "category" is
// whichever source directory it loaded from, not something parseable from
// its info: block. See docs/12-implementation-plan-ph3.md's "Template sync
// command" §2 note.
type Entry struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Format   string   `json:"format"` // "nuclei" | "native"
	Severity string   `json:"severity"`
	Tags     []string `json:"tags"`
	Source   string   `json:"source"` // caller-supplied label for the dir this entry loaded from, e.g. "bundled" | "synced"
}

// List loads every template under each of dirs (same nuclei.LoadDirDetailed/
// native.LoadDirDetailed this project's scanner.Engine.loadTemplates already
// uses), labels each entry with sourceLabels[i] (must be the same length as
// dirs), and — when tags is non-empty — keeps only entries carrying at
// least one requested tag (OR match, same semantics as scanner.Engine's
// --tags filtering, reimplemented locally here rather than shared: the two
// packages' tag shapes already differ per-format, and this is a handful of
// lines, not worth a new shared package for one internal reuse).
// rejected counts only files that failed to parse under *both* formats — a
// file that's valid Nuclei YAML fails native's own parser too (it has no
// requests: block native expects), and vice versa; counting either loader's
// raw error count on its own would flag every legitimately-loaded template
// as "also rejected," which is exactly what a prior version of this
// function did (see git history / the corrected test cases in
// list_test.go) and is misleading in the Web UI's own template count.
func List(dirs, sourceLabels, tags []string) (entries []Entry, rejected int, err error) {
	if len(dirs) != len(sourceLabels) {
		return nil, 0, fmt.Errorf("templatesync: List got %d dirs but %d sourceLabels", len(dirs), len(sourceLabels))
	}

	for i, dir := range dirs {
		if dir == "" {
			continue
		}
		source := sourceLabels[i]

		nt, nErrs := nuclei.LoadDirDetailed(dir)
		for _, t := range nt {
			entries = append(entries, Entry{
				ID:       t.ID,
				Name:     t.Info.Name,
				Format:   "nuclei",
				Severity: t.Info.Severity,
				Tags:     splitTags(t.Info.Tags),
				Source:   source,
			})
		}

		vt, vErrs := native.LoadDirDetailed(dir)
		for _, t := range vt {
			entries = append(entries, Entry{
				ID:       t.ID,
				Name:     t.Info.Name,
				Format:   "native",
				Severity: t.Info.Severity,
				Tags:     t.Tags,
				Source:   source,
			})
		}

		rejected += countRejectedByBothFormats(nErrs, vErrs)
	}

	if len(tags) > 0 {
		entries = filterByTags(entries, tags)
	}
	return entries, rejected, nil
}

// countRejectedByBothFormats returns how many distinct paths appear in both
// nErrs and vErrs — a file neither loader could parse, i.e. a genuine
// problem rather than simply "written in the other format."
func countRejectedByBothFormats(nErrs []nuclei.LoadError, vErrs []native.LoadError) int {
	nFailed := make(map[string]bool, len(nErrs))
	for _, e := range nErrs {
		nFailed[e.Path] = true
	}
	count := 0
	for _, e := range vErrs {
		if nFailed[e.Path] {
			count++
		}
	}
	return count
}

func splitTags(commaSeparated string) []string {
	if commaSeparated == "" {
		return nil
	}
	var tags []string
	for _, t := range strings.Split(commaSeparated, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

func filterByTags(entries []Entry, wanted []string) []Entry {
	set := make(map[string]bool, len(wanted))
	for _, t := range wanted {
		if t = normalizeTag(t); t != "" {
			set[t] = true
		}
	}

	var kept []Entry
	for _, e := range entries {
		for _, tag := range e.Tags {
			if set[normalizeTag(tag)] {
				kept = append(kept, e)
				break
			}
		}
	}
	return kept
}

func normalizeTag(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}
