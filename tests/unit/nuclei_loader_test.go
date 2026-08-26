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

// TestNucleiLoadDir_MultiKeyPayloadsRejected locks in the v1 boundary: more
// than one payload key (real Nuclei's sniper/pitchfork/clusterbomb "attack
// modes") is rejected at load time — see schema.go's resolvePayload.
func TestNucleiLoadDir_MultiKeyPayloadsRejected(t *testing.T) {
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
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "2 payload keys")
	assert.Contains(t, errs[0].Error(), "clusterbomb")
}

// TestNucleiLoadDir_FileBasedPayloadRejected locks in the v1 boundary: a
// payload value that's a bare string (a wordlist file path) rather than an
// inline list is rejected at load time — see schema.go's resolvePayload.
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

// TestNucleiLoadDir_FlowRejected locks in a fix for a real, live false
// positive: upstream's apache-server-status-localhost.yaml uses `flow:` to
// run a 403/404/401 "is it blocked" gate check (marked `internal: true`,
// meaning "never a standalone result") before a second request that
// actually attempts the bypass. Without flow: support, this project's
// executor used to run both requests unconditionally and independently —
// so the gate's own 403 match got reported as a false "Server Status
// Disclosure" finding, backwards from what it meant (403 = correctly
// blocked). Now rejected at load time instead of silently mis-evaluated.
func TestNucleiLoadDir_FlowRejected(t *testing.T) {
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
