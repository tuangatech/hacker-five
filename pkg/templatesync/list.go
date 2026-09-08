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

// LoadByIDs is List narrowed to a small, explicit set of template IDs — F4
// (docs/follow-up.md LT-71). It uses nuclei.LoadDirByIDs' id:-peek fast path
// (parse only the wanted files, not the whole ~9,500-file corpus) for the
// nuclei format and a normal full load for native (a few dozen bundled
// files, no corpus cost). ids == nil / empty returns nothing. Unlike List
// it takes no tags argument: the caller has already resolved its tag/leaf
// set down to concrete IDs. The returned entries carry the same shape List
// produces, so a caller can treat the two interchangeably.
func LoadByIDs(dirs, sourceLabels []string, ids []string) (entries []Entry, err error) {
	if len(dirs) != len(sourceLabels) {
		return nil, fmt.Errorf("templatesync: LoadByIDs got %d dirs but %d sourceLabels", len(dirs), len(sourceLabels))
	}
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return nil, nil
	}

	for i, dir := range dirs {
		if dir == "" {
			continue
		}
		source := sourceLabels[i]

		nt, _ := nuclei.LoadDirByIDs(dir, want)
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

		vt, _ := native.LoadDirDetailed(dir)
		for _, t := range vt {
			if !want[t.ID] {
				continue
			}
			entries = append(entries, Entry{
				ID:       t.ID,
				Name:     t.Info.Name,
				Format:   "native",
				Severity: t.Info.Severity,
				Tags:     t.Tags,
				Source:   source,
			})
		}
	}
	return entries, nil
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
