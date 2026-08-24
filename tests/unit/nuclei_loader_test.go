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

func TestNucleiLoadDir_RawPayloadsRejected(t *testing.T) {
	dir := t.TempDir()
	writeTemplate(t, dir, "cors-style.yaml", `
id: cors-misconfig-style
info:
  name: CORS Misconfiguration
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
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
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "raw:/payloads:")
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
