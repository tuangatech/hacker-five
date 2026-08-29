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
	ID       string
	Name     string
	Format   string // "nuclei" | "native"
	Severity string
	Tags     []string
	Source   string // caller-supplied label for the dir this entry loaded from, e.g. "bundled" | "synced"
}

// List loads every template under each of dirs (same nuclei.LoadDir/
// native.LoadDir this project's scanner.Engine.loadTemplates already uses),
// labels each entry with sourceLabels[i] (must be the same length as dirs),
// and — when tags is non-empty — keeps only entries carrying at least one
// requested tag (OR match, same semantics as scanner.Engine's --tags
// filtering, reimplemented locally here rather than shared: the two
// packages' tag shapes already differ per-format, and this is a handful of
// lines, not worth a new shared package for one internal reuse).
// rejected is the count of files LoadDir couldn't parse, across every dir.
func List(dirs, sourceLabels, tags []string) (entries []Entry, rejected int, err error) {
	if len(dirs) != len(sourceLabels) {
		return nil, 0, fmt.Errorf("templatesync: List got %d dirs but %d sourceLabels", len(dirs), len(sourceLabels))
	}

	for i, dir := range dirs {
		if dir == "" {
			continue
		}
		source := sourceLabels[i]

		nt, nErrs := nuclei.LoadDir(dir)
		rejected += len(nErrs)
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

		vt, vErrs := native.LoadDir(dir)
		rejected += len(vErrs)
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
	}

	if len(tags) > 0 {
		entries = filterByTags(entries, tags)
	}
	return entries, rejected, nil
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
