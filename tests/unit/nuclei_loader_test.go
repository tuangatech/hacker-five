package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

func writeTemplate(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

func TestNucleiLoadDir_ValidTemplate(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "valid.yaml", `
id: valid-template
info:
  name: Valid Template
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "hello"
      - type: status
        status:
          - 200
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	assert.Equal(t, "valid-template", templates[0].ID)
	assert.Len(t, templates[0].HTTP[0].Matchers, 2)
}

func TestNucleiLoadDir_DisallowedBlock(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "code-block.yaml", `
id: bad-template
info:
  name: Bad Template
  severity: info
code:
  - engine: py3
    source: "print('hi')"
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "disallowed block")
	assert.Contains(t, errs[0].Error(), "code")
}

func TestNucleiLoadDir_HeadlessBlock(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "headless.yaml", `
id: bad-headless
info:
  name: Bad Headless
  severity: info
headless:
  - steps: []
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "disallowed block")
	assert.Contains(t, errs[0].Error(), "headless")
}

func TestNucleiLoadDir_UnknownDSLExpression(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "bad-dsl.yaml", `
id: bad-dsl
info:
  name: Bad DSL
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - "some_undefined_func(x) == 1"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "invalid dsl expression")
}

// TestNucleiLoadDir_RawPayloadsLoad locks in the v1-supported shape: a
// single raw: entry, one inline-list payload key — modeled on real
// upstream's apache-mod-negotiation-listing.yaml.
func TestNucleiLoadDir_RawPayloadsLoad(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "raw-style.yaml", `
id: raw-payload-style
info:
  name: Raw Payload Style
  severity: info
http:
  - raw:
      - |
        GET {{path}} HTTP/1.1
        Host: {{Hostname}}
        Origin: {{cors_origin}}
    payloads:
      cors_origin:
        - "https://evil.example"
    matchers:
      - type: dsl
        dsl:
          - "contains(body, 'x')"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	assert.Equal(t, "raw-payload-style", templates[0].ID)
	assert.Len(t, templates[0].HTTP[0].Raw, 1)
}

// TestNucleiLoadDir_MultiKeyPayloadsLoad is modeled on real upstream's
// zabbix-default-login.yaml (clusterbomb, 3 keys). Previously rejected at
// load time — see tests/unit/nuclei_executor_test.go for the end-to-end
// proof each attack mode actually iterates correctly, not just that it
// loads.
func TestNucleiLoadDir_MultiKeyPayloadsLoad(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "multi-key.yaml", `
id: multi-key-style
info:
  name: Multi Key Style
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-A: {{a}}
        X-B: {{b}}
    attack: clusterbomb
    payloads:
      a:
        - "1"
      b:
        - "2"
    matchers:
      - type: status
        status:
          - 200
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

// TestNucleiLoadDir_UnsupportedAttackModeRejected locks in that "sniper" (and
// any other unrecognized attack: value) is still rejected — it's valid
// Nuclei syntax but not expressible via nuclei's map-shaped payloads:, and 0
// real corpus templates use it.
func TestNucleiLoadDir_UnsupportedAttackModeRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "sniper.yaml", `
id: sniper-style
info:
  name: Sniper Style
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-A: {{a}}
        X-B: {{b}}
    attack: sniper
    payloads:
      a:
        - "1"
      b:
        - "2"
    matchers:
      - type: status
        status:
          - 200
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "sniper")
}

// TestNucleiLoadDir_FileBasedPayloadRejected locks in the v1 boundary: a
// payload value that's a bare string (a wordlist file path) rather than an
// inline list is rejected at load time — see schema.go's resolvePayloads.
func TestNucleiLoadDir_FileBasedPayloadRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "file-payload.yaml", `
id: file-payload-style
info:
  name: File Payload Style
  severity: info
http:
  - raw:
      - |
        GET {{path}} HTTP/1.1
        Host: {{Hostname}}
    payloads:
      path: helpers/wordlists/adminer-paths.txt
    matchers:
      - type: status
        status:
          - 200
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "file-based payload")
}

// TestNucleiLoadDir_AbsoluteURIRawRejected locks in the v1 boundary: a raw:
// entry whose request line names an absolute URI (the open-proxy-relay
// technique) is rejected at load time rather than risking a connection to
// a template-controlled host — see schema.go's hasAbsoluteRequestLine.
func TestNucleiLoadDir_AbsoluteURIRawRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "absolute-uri.yaml", `
id: absolute-uri-style
info:
  name: Absolute URI Style
  severity: info
http:
  - raw:
      - |
        GET http://192.168.0.1/ HTTP/1.1
        Host: 192.168.0.1
    matchers:
      - type: status
        status:
          - 200
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "absolute-URI")
}

// TestNucleiLoadDir_MultiRawEntry locks in the other v1-supported shape:
// multiple raw: entries in one http: block (no payloads) — modeled on
// real upstream's open-proxy-internal.yaml's overall structure, scaled
// down.
func TestNucleiLoadDir_MultiRawEntry(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "multi-raw.yaml", `
id: multi-raw-style
info:
  name: Multi Raw Style
  severity: high
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /internal HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 != 404"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	assert.Len(t, templates[0].HTTP[0].Raw, 2)
}

// TestNucleiLoadDir_MultiRawEntry_ContentTypeAndDurationLoad is
// TestNucleiLoadDir_MultiRawEntry extended with content_type_N/duration_N —
// real upstream examples: CVE-2015-2755.yaml (content_type_2),
// CVE-2015-2196.yaml (duration_1) — both previously rejected at load time as
// "unknown identifier" since rawIndexedDSLContext only seeded body_N/
// header_N/status_code_N.
func TestNucleiLoadDir_MultiRawEntry_ContentTypeAndDurationLoad(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "multi-raw-content-duration.yaml", `
id: multi-raw-content-duration-style
info:
  name: Multi Raw Content/Duration Style
  severity: high
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /slow HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: dsl
        dsl:
          - "contains(content_type_1, \"json\") && duration_2 >= 6"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

// TestNucleiLoadDir_BareDurationOnPlainPathTemplateLoads is modeled on real
// upstream's CVE-2023-2130.yaml: a bare "duration" DSL identifier on a plain
// path:-based request, no raw: at all. Previously rejected — the pre-fix
// rawIndexedDSLContext returned a fully empty dsl.Context whenever raw was
// empty, so "duration" had no entry to resolve against.
func TestNucleiLoadDir_BareDurationOnPlainPathTemplateLoads(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "bare-duration-style.yaml", `
id: bare-duration-style
info:
  name: Bare Duration Style
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q=1) OR SLEEP(6)-- -"
    matchers:
      - type: dsl
        dsl:
          - "duration>=6"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

func TestNucleiLoadDir_MultiPathPanelTemplate(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "panel.yaml", `
id: adminer-panel-style
info:
  name: Adminer Login Panel
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/adminer.php"
      - "{{BaseURL}}/_adminer.php"
      - "{{BaseURL}}/adminer/"
    stop-at-first-match: true
    matchers:
      - type: word
        words:
          - "Adminer</title>"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	require.Len(t, templates[0].HTTP[0].Path, 3, "every path entry must parse, not just the first")
	assert.True(t, templates[0].HTTP[0].StopAtFirstMatch)
}

// TestNucleiLoadDir_FlowLoads is modeled on upstream's real
// apache-server-status-localhost.yaml — a 403/404/401 "is it blocked" gate
// check (marked internal: true, meaning "never a standalone result")
// followed by a bypass attempt, connected via flow: http(1) && http(2).
// Before flow: support, running both requests unconditionally/independently
// reported the gate's own 403 match as a false "Server Status Disclosure"
// finding, backwards from what it meant (403 = correctly blocked) — see
// docs/10-implementation-plan-ph1b.md's flow: note. Now this grammar (a
// boolean composition of http(N) calls, matching 36 of 38 real sampled
// flow: templates) is parsed and internal: true is allowed when flow: is
// set. See tests/unit/nuclei_executor_test.go for the actual end-to-end
// false-positive-fixed proof; this test only confirms it loads.
func TestNucleiLoadDir_FlowLoads(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "flow-style.yaml", `
id: apache-server-status-style
info:
  name: Server Status Disclosure
  severity: low
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    matchers:
      - type: status
        status:
          - 403
          - 404
        internal: true
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    matchers:
      - type: word
        words:
          - "Apache Server Status"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

// TestNucleiLoadDir_FlowMixedBooleanLoads is modeled on the one real
// sampled flow: template that mixes && and || with explicit parens
// (upstream's citrix-xenmobile-version.yaml-style shape) — confirms the
// parser handles grouping, not just a flat chain.
func TestNucleiLoadDir_FlowMixedBooleanLoads(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "flow-mixed.yaml", `
id: flow-mixed-boolean
info:
  name: Flow Mixed Boolean
  severity: info
flow: http(1) && (http(2) || http(3))
http:
  - method: GET
    path: ["{{BaseURL}}/a"]
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: ["{{BaseURL}}/b"]
    matchers:
      - type: status
        status: [200]
  - method: GET
    path: ["{{BaseURL}}/c"]
    matchers:
      - type: status
        status: [200]
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

// TestNucleiLoadDir_FlowOutOfRangeRejected rejects a flow: expression
// referencing an http: index the template doesn't actually have.
func TestNucleiLoadDir_FlowOutOfRangeRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "flow-oor.yaml", `
id: flow-out-of-range
info:
  name: Flow Out Of Range
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [200]
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "http(2)")
}

// TestNucleiLoadDir_FlowJavascriptRejected keeps a javascript()-based flow:
// script rejected — this project's minimal grammar only covers boolean
// composition of http(N) calls, not a JS engine (same category as the
// code:/headless: disallowed blocks). Real upstream has 2 of these among
// the 38 sampled flow: templates (e.g. cookies-without-secure.yaml).
func TestNucleiLoadDir_FlowJavascriptRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "flow-js.yaml", `
id: flow-javascript
info:
  name: Flow Javascript
  severity: info
flow: |
  http()
  javascript()
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: status
        status: [200]
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "flow:")
}

// TestNucleiLoadDir_InternalMatcherRejected is the belt-and-suspenders
// counterpart: even without a top-level flow: field, a matcher marked
// internal: true is rejected — it's never meant to produce standalone
// output regardless of context.
func TestNucleiLoadDir_InternalMatcherRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "internal-matcher.yaml", `
id: internal-matcher-style
info:
  name: Internal Matcher Style
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
        internal: true
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "internal:")
}

func TestNucleiLoadDir_MalformedYAMLIsolated(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "broken.yaml", "id: broken\ninfo: [this is not valid: yaml structure\n")
	writeTemplate(t, dir, "valid.yaml", `
id: still-valid
info:
  name: Still Valid
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Len(t, errs, 1, "only the broken file should error")
	require.Len(t, templates, 1, "the valid file next to it still loads")
	assert.Equal(t, "still-valid", templates[0].ID)
}

// TestNucleiLoadDir_PreviouslyRejectedDSLGapsNowLoad is a regression test
// for real templates that used to fail matcher validation before the DSL
// builtins/tokenizer fix (see docs/10-implementation-plan-ph1b.md's
// "Post-v0.1.0 DSL/part expansion" note) — modeled directly on real
// upstream shapes: activemq-panel.yaml's `contains_any(to_lower(body), ...)`
// and appwrite-panel.yaml's `mmh3(base64_py(body))` favicon-hash check,
// both of which failed to even parse before this fix.
func TestNucleiLoadDir_PreviouslyRejectedDSLGapsNowLoad(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "dsl-gap-style.yaml", `
id: dsl-gap-style
info:
  name: DSL Gap Style
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'contains_any(to_lower(body), "welcome to the apache activemq!", "manage activemq broker")'
      - type: dsl
        dsl:
          - '"-1787112514" == mmh3(base64_py(body))'
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	assert.Equal(t, "dsl-gap-style", templates[0].ID)
}

func TestNucleiLoadDir_RecursesSubdirectories(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "adobe")
	require.NoError(t, os.Mkdir(vendorDir, 0o755))
	writeTemplate(t, vendorDir, "adobe-panel.yaml", `
id: adobe-panel
info:
  name: Adobe Panel
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/adobe/"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1, "templates nested under a vendor subdirectory must still be found")
}

// TestNucleiLoadDir_SameRequestExtractorBindingLoads is modeled on real
// upstream's apache-httpd-eol.yaml: a matcher's dsl: expression references
// an extractor's Name from the SAME request block
// (compare_versions(version, ...) where "version" is extracted by that
// same request) — previously rejected as "unknown identifier", since
// load-time validation only knew about same-block raw: N-indexed
// identifiers, never extractor Names. See docs/10-implementation-plan-ph1b.md's
// extractor->DSL binding note.
func TestNucleiLoadDir_SameRequestExtractorBindingLoads(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "eol-style.yaml", `
id: apache-httpd-eol-style
info:
  name: Apache HTTP Server EOL
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - compare_versions(version, '<=2.2.34')
        condition: and
    extractors:
      - type: regex
        part: header
        name: version
        group: 1
        regex:
          - 'Server: Apache/([0-9.]+)'
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

// TestNucleiLoadDir_CrossRequestExtractorBindingLoads is modeled on real
// upstream's google-iap-detect.yaml: request 2's extractor references
// "email", extracted by request 1 — a chain-scoped (not same-block-raw:)
// reference, connected via flow: so the binding is meaningful regardless of
// evaluation order.
func TestNucleiLoadDir_CrossRequestExtractorBindingLoads(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "iap-style.yaml", `
id: google-iap-detect-style
info:
  name: Google IAP Detect
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    extractors:
      - type: regex
        part: body
        name: email
        group: 1
        regex:
          - "owner:\\s*([^;]+)"
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "X-Goog-Iap-Generated-Response"
    extractors:
      - type: dsl
        name: contact_email
        dsl:
          - "email"
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
}

// TestNucleiLoadDir_ForwardExtractorReferenceRejected keeps a genuinely
// unresolvable reference rejected: request 1's matcher references "token",
// which is only extracted by a LATER request (request 2) — real Nuclei
// templates never do this (extraction only flows forward), and this
// project's knownExtractorNames accumulation deliberately doesn't look
// ahead, so this should still fail exactly like before.
func TestNucleiLoadDir_ForwardExtractorReferenceRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "forward-ref.yaml", `
id: forward-ref-style
info:
  name: Forward Reference Style
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/a"
    matchers:
      - type: dsl
        dsl:
          - 'token != ""'
  - method: GET
    path:
      - "{{BaseURL}}/b"
    extractors:
      - type: regex
        name: token
        regex:
          - 'token=(\w+)'
`)

	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), `unknown identifier "token"`)
}
