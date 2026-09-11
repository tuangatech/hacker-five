package nuclei

import (
	"regexp"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// AffectedVersionRanges returns this template's affected-version gate, if
// one can be statically and safely extracted from its own matchers: a
// []AND-clause where each clause is itself a list of compare_versions()-
// style constraint strings ("< 8.10.2", ">= 8.0.0", ...) that must ALL hold;
// the template is potentially applicable to a given version when ANY clause
// is fully satisfied. nil means "no static gate" — pkg/registry's
// matchTemplateTags (LT-7, Phase 8 Step 4) treats that as unconditionally
// in-scope, same as before this existed.
//
// Real corpus measurement (2026-09-11, 9,651 synced templates) found the
// documented nuclei metadata: max-version/min-version convention entirely
// unused (0 hits) — the only real machine-readable affected-version signal
// lives in a dsl: matcher's own compare_versions() call(s), so extraction
// parses that instead. 388 templates call compare_versions() at least once,
// but they split sharply into two populations:
//   - ~150 real standalone CVE templates with a literal constraint, e.g.
//     compare_versions(version, '>= 8.0.0', '< 8.10.2') — of these, 28
//     survive AffectedVersionRanges' conservative shape-gate (below) once
//     the "or" / multi-matcher / multi-request ones that can't be safely
//     reduced are excluded. This is the population LT-7's own evidence
//     named: real Nginx/product hosts at different patch levels that today
//     all get the identical CVE template list.
//   - 237 WordPress-plugin/theme templates using the idiom
//     compare_versions(internal_detected_version, concat("< ",
//     last_version)) (last_version a file-based payloads: entry) — measured
//     live: EVERY single one of these pairs that dsl matcher with
//     matchers-condition: or against a second, bare "plugin is present"
//     regex matcher (a discovery/detect template, not a hard CVE gate — the
//     dsl matcher is a *named* sub-check for Finding labeling, not the sole
//     reportability condition). Extracting a range from it would therefore
//     be actively wrong, not just unrealized: matchers-condition: or already
//     excludes multi-matcher templates below, so this population is
//     correctly never gated, not a gap. Deliberately not special-cased for
//     concat()/payload-file resolution — there is no real-corpus template
//     where doing so would produce a different, still-correct outcome.
//
// Extraction is deliberately conservative rather than exhaustive: anything
// shaped differently (a compare_versions() call mixed with unrelated DSL
// logic, a multi-request template, a matcher whose failure can't rule the
// template out because matchers-condition: or lets some OTHER, unrelated
// matcher fire the template anyway) returns nil for that matcher/template
// rather than risk silently dropping a template that's actually still
// applicable — a missed CVE is a worse failure mode than an unnecessary
// scan, see CLAUDE.md's detection-coverage posture.
func (t *Template) AffectedVersionRanges() [][]string {
	if len(t.HTTP) != 1 {
		return nil // ambiguous which request block "the" fingerprinted version applies to
	}
	req := t.HTTP[0]
	if len(req.Matchers) == 0 {
		return nil
	}
	// Only safe to gate on a subset of matchers when EVERY matcher must
	// hold for the template to fire (matchers-condition: and) — otherwise
	// an unrelated matcher could still fire the template independent of
	// version, and dropping the template on a version mismatch would be
	// wrong. A single matcher has no such ambiguity regardless of the
	// stated condition.
	if req.MatchersCondition != matcher.And && len(req.Matchers) > 1 {
		return nil
	}

	ranges := [][]string{{}} // identity clause for the cross-product fold below
	found := false
	for _, m := range req.Matchers {
		if m.Type != "dsl" || len(m.DSL) == 0 {
			continue
		}
		clauses, ok := dslMatcherVersionClauses(m)
		if !ok {
			continue // this matcher isn't (entirely) a version gate — leave it out, don't reject the whole template
		}
		found = true
		ranges = crossProductClauses(ranges, clauses)
	}
	if !found {
		return nil
	}
	return ranges
}

// dslMatcherVersionClauses returns the OR'd AND-clauses one dsl: matcher
// encodes, and whether at least a version constraint could be safely pulled
// out of it.
//
//   - condition: and (2+ DSL entries): every entry must hold simultaneously
//     for the matcher to fire, so a non-compare_versions() entry alongside
//     it (upstream's real nginx-eol.yaml/apache-httpd-eol.yaml pattern:
//     `compare_versions(version, '<1.28.0')` ANDed with `contains(server,
//     'nginx')`, the latter just corroborating which product the header
//     belongs to) doesn't invalidate the version constraint — it's still a
//     *necessary* condition either way, so it's kept and the unrecognized
//     entry is simply left out of the extracted range (this project's own
//     gate ends up looser than the template's, never stricter — the safe
//     direction, see AffectedVersionRanges' doc comment).
//   - Default (unset) / "or": each entry is an independent way to fire the
//     matcher, so EVERY entry must be a bare compare_versions() call (with
//     only literal quoted constraint arguments — the concat()/payload-file
//     idiom is deliberately never resolved, see AffectedVersionRanges) or
//     the whole matcher is dropped — a single entry falls through this same
//     strict path (no "and" siblings to be lenient about).
func dslMatcherVersionClauses(m matcher.Matcher) (clauses [][]string, ok bool) {
	lenient := m.Condition == "and" && len(m.DSL) > 1
	var entryClauses [][]string
	for _, expr := range m.DSL {
		constraints, ok2 := parseCompareVersionsCall(strings.TrimSpace(expr))
		if !ok2 {
			if lenient {
				continue
			}
			return nil, false
		}
		entryClauses = append(entryClauses, constraints)
	}
	if len(entryClauses) == 0 {
		return nil, false
	}
	if lenient {
		// Fold every recognized entry's constraints into one AND-clause
		// (each compare_versions() call already ANDs its own constraint
		// args the same way, so this is the same fold one level up).
		var union []string
		for _, c := range entryClauses {
			union = append(union, c...)
		}
		return [][]string{union}, true
	}
	// "or": each entry is its own alternative clause — the real corpus's
	// dominant multi-entry-OR shape (e.g. VMware vRealize Log Insight's
	// CVE-2022-31704.yaml: two disjoint vulnerable ranges, '>= 3.0','< 4.8'
	// OR '>= 8.0.0','< 8.10.2').
	return entryClauses, true
}

// compareVersionsCallRe recognizes a DSL string that is ENTIRELY one bare
// compare_versions(ident, constraint[, constraint...]) call — nothing else
// combined in via &&/||. Group 1 is everything after the identifier's
// leading comma, up to the final close-paren.
var compareVersionsCallRe = regexp.MustCompile(`^compare_versions\(\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*(.+)\)$`)

// parseCompareVersionsCall parses expr as a whole-string compare_versions()
// call and returns its constraint list, each already in the "<op><version>"
// shape pkg/template/dsl.SatisfiesVersionConstraint accepts — false if expr
// isn't shaped that way, or any individual constraint argument isn't a bare
// quoted literal (see this file's package doc comment for why a non-literal
// argument, e.g. concat()-built, is deliberately not resolved).
func parseCompareVersionsCall(expr string) ([]string, bool) {
	m := compareVersionsCallRe.FindStringSubmatch(expr)
	if m == nil {
		return nil, false
	}
	args, ok := splitCallArgs(m[1])
	if !ok || len(args) == 0 {
		return nil, false
	}
	constraints := make([]string, 0, len(args))
	for _, a := range args {
		lit, ok := unquoteLiteral(strings.TrimSpace(a))
		if !ok {
			return nil, false
		}
		constraints = append(constraints, strings.TrimSpace(lit))
	}
	return constraints, true
}

// unquoteLiteral strips a single layer of matching '...'/"..." quoting,
// reporting false if s isn't quoted that way.
func unquoteLiteral(s string) (string, bool) {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1], true
		}
	}
	return "", false
}

// splitCallArgs splits s on top-level commas — respecting nested
// parentheses and quoted strings, so a nested call's internal comma doesn't
// get mistaken for an argument separator one level up.
func splitCallArgs(s string) ([]string, bool) {
	var args []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth < 0 {
				return nil, false
			}
		case c == ',' && depth == 0:
			args = append(args, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if depth != 0 || quote != 0 {
		return nil, false
	}
	args = append(args, strings.TrimSpace(s[start:]))
	return args, true
}

// crossProductClauses distributes add (an OR-group of AND-clauses) across
// existing (the accumulated OR-group so far), so a template whose version
// gate is split across more than one qualifying matcher (all required, per
// AffectedVersionRanges' matchers-condition: and gate) still reduces to one
// flat OR-of-AND-clauses shape. existing starts as [{}] (one clause with no
// constraints — an identity element: AND-ing it with anything changes
// nothing), so the first fold just becomes add's own clauses unchanged.
func crossProductClauses(existing, add [][]string) [][]string {
	out := make([][]string, 0, len(existing)*len(add))
	for _, e := range existing {
		for _, n := range add {
			combined := make([]string, 0, len(e)+len(n))
			combined = append(combined, e...)
			combined = append(combined, n...)
			out = append(out, combined)
		}
	}
	return out
}
