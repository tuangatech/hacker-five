package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// loadOneTemplate is affectedversion_test.go's own thin wrapper around
// writeTemplate/nuclei.LoadDir (nuclei_loader_test.go) for the common case
// here: exactly one template file, expected to load cleanly.
func loadOneTemplate(t *testing.T, yamlBody string) *nuclei.Template {
	t.Helper()
	dir := t.TempDir()
	writeTemplate(t, dir, "tmpl.yaml", yamlBody)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	return templates[0]
}

func TestAffectedVersionRanges_LiteralSingleClause(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: single-range
info:
  name: Single Range
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '>= 8.0.0', '< 8.10.2')"
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        regex:
          - "version=([0-9.]+)"
`)
	got := tmpl.AffectedVersionRanges()
	require.Len(t, got, 1)
	assert.ElementsMatch(t, []string{">= 8.0.0", "< 8.10.2"}, got[0])
}

func TestAffectedVersionRanges_BareEqualityConstraint(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: bare-equality
info:
  name: Bare Equality
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '9.0.0')"
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        regex:
          - "version=([0-9.]+)"
`)
	got := tmpl.AffectedVersionRanges()
	require.Len(t, got, 1)
	assert.Equal(t, []string{"9.0.0"}, got[0])
}

// TestAffectedVersionRanges_OrConditionDisjointRanges mirrors the real
// upstream shape (VMware vRealize Log Insight, CVE-2022-31704.yaml): one
// dsl: matcher, two compare_versions() entries, "condition: or" between
// them — two disjoint vulnerable ranges, not one contiguous one.
func TestAffectedVersionRanges_OrConditionDisjointRanges(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: disjoint-ranges
info:
  name: Disjoint Ranges
  severity: critical
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '>= 3.0', '< 4.8')"
          - "compare_versions(version, '>= 8.0.0', '< 8.10.2')"
        condition: or
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        regex:
          - "version=([0-9.]+)"
`)
	got := tmpl.AffectedVersionRanges()
	require.Len(t, got, 2)
	assert.ElementsMatch(t, []string{">= 3.0", "< 4.8"}, got[0])
	assert.ElementsMatch(t, []string{">= 8.0.0", "< 8.10.2"}, got[1])
}

// TestAffectedVersionRanges_AndConditionToleratesNonVersionSibling mirrors
// the real upstream nginx-eol.yaml/apache-httpd-eol.yaml shape: one dsl:
// matcher combining a compare_versions() entry with an unrelated
// corroborating entry (contains(server, ...)) via "condition: and". Since
// both must hold for the matcher to fire, the version constraint is still a
// necessary (if not sufficient) condition — safely extractable even though
// the sibling entry isn't itself a version check.
func TestAffectedVersionRanges_AndConditionToleratesNonVersionSibling(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: nginx-eol-like
info:
  name: Nginx EOL Like
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '<1.28.0')"
          - "contains(server, 'nginx')"
        condition: and
    extractors:
      - type: regex
        part: header
        name: version
        group: 1
        regex:
          - "Server: nginx/([0-9.]+)"
`)
	got := tmpl.AffectedVersionRanges()
	require.Len(t, got, 1)
	assert.Equal(t, []string{"<1.28.0"}, got[0])
}

// TestAffectedVersionRanges_OrConditionMultiMatcher_NotExtracted mirrors the
// real upstream WordPress-plugin "outdated version" idiom (e.g.
// forminator.yaml): matchers-condition: or between a compare_versions()-only
// dsl matcher and an unrelated bare-presence regex matcher. The template
// fires on EITHER — a plugin merely being installed is enough — so gating
// template *selection* on the version constraint would incorrectly drop it
// for an unaffected version that's still worth a "plugin present" leaf.
func TestAffectedVersionRanges_OrConditionMultiMatcher_NotExtracted(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: wp-plugin-discovery-like
info:
  name: WP Plugin Discovery Like
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/example/readme.txt"
    payloads:
      last_version:
        - "5.0.0"
    matchers-condition: or
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(internal_detected_version, concat('< ', last_version))"
      - type: regex
        part: body
        regex:
          - "Stable tag:"
    extractors:
      - type: regex
        part: body
        name: internal_detected_version
        group: 1
        regex:
          - "Stable tag:\\s?([\\w.]+)"
`)
	assert.Nil(t, tmpl.AffectedVersionRanges())
}

// TestAffectedVersionRanges_MixedDSLLogic_NotExtracted covers a
// compare_versions() call combined with unrelated DSL logic in the SAME
// entry — not a bare call, so not statically reducible to a version-only
// range at all, regardless of matcher condition.
func TestAffectedVersionRanges_MixedDSLLogic_NotExtracted(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: mixed-dsl
info:
  name: Mixed DSL
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '<1.0') && contains(body, 'foo')"
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        regex:
          - "version=([0-9.]+)"
`)
	assert.Nil(t, tmpl.AffectedVersionRanges())
}

// TestAffectedVersionRanges_MultiRequestTemplate_NotExtracted covers a
// template with more than one http: request block — ambiguous which
// block's matcher "the" fingerprinted version should gate, so left
// unextracted.
func TestAffectedVersionRanges_MultiRequestTemplate_NotExtracted(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: multi-request
info:
  name: Multi Request
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/a"
    matchers:
      - type: status
        status:
          - 200
  - method: GET
    path:
      - "{{BaseURL}}/b"
    matchers:
      - type: dsl
        dsl:
          - "compare_versions(version, '<1.0')"
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        regex:
          - "version=([0-9.]+)"
`)
	assert.Nil(t, tmpl.AffectedVersionRanges())
}

// TestAffectedVersionRanges_AndConditionMultiMatcher_Extracted covers two
// SIBLING matchers (not two dsl: entries within one) combined via the
// request-level matchers-condition: and — both required, so the version
// gate living in one of them is still safely extractable, the sibling
// word/status matcher simply contributing nothing to the extracted range.
func TestAffectedVersionRanges_AndConditionMultiMatcher_Extracted(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: and-multi-matcher
info:
  name: And Multi Matcher
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: dsl
        dsl:
          - "compare_versions(version, '<= 2.4.4')"
    extractors:
      - type: regex
        name: version
        part: body
        group: 1
        regex:
          - "version=([0-9.]+)"
`)
	got := tmpl.AffectedVersionRanges()
	require.Len(t, got, 1)
	assert.Equal(t, []string{"<= 2.4.4"}, got[0])
}

// TestAffectedVersionRanges_NoDSLMatcher_Nil covers the ordinary common case
// (most of the ~9,600-template corpus): no compare_versions() usage at all.
func TestAffectedVersionRanges_NoDSLMatcher_Nil(t *testing.T) {
	tmpl := loadOneTemplate(t, `
id: no-version-gate
info:
  name: No Version Gate
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "hello"
`)
	assert.Nil(t, tmpl.AffectedVersionRanges())
}
