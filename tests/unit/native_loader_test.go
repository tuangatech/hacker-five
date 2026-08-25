package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/native"
)

func writeNativeTemplate(t *testing.T, dir, name, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
}

func TestNativeLoadDir_ValidGenericTemplate(t *testing.T) {
	dir := t.TempDir()
	writeNativeTemplate(t, dir, "chain.yaml", `
id: login-then-probe
info:
  name: Login then probe
  severity: info
tags:
  - example
variables:
  base_path: /api/users
requests:
  - method: POST
    path: "{{BaseURL}}/api/auth/login"
    extractors:
      - type: json
        name: auth_token
        json:
          - token
  - method: GET
    path: "{{BaseURL}}{{base_path}}/42"
    headers:
      Authorization: "Bearer {{auth_token}}"
    condition: auth_token != ""
    matchers:
      - type: status
        status:
          - 200
`)

	templates, errs := native.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	assert.Equal(t, "login-then-probe", templates[0].ID)
	assert.Len(t, templates[0].Requests, 2)
}

func TestNativeLoadDir_IDORValidTemplate(t *testing.T) {
	dir := t.TempDir()
	writeNativeTemplate(t, dir, "idor.yaml", `
id: idor-example
info:
  name: IDOR example
  severity: high
tags:
  - idor
requests:
  - path: "{{BaseURL}}/api/orders?id={{RangeInt(1|50)}}"
`)

	templates, errs := native.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)
	assert.Equal(t, "idor-example", templates[0].ID)
}

func TestNativeLoadDir_IDORRejectsMultipleRequests(t *testing.T) {
	dir := t.TempDir()
	writeNativeTemplate(t, dir, "idor-chain.yaml", `
id: idor-chain-style
info:
  name: Bad IDOR chain
  severity: high
tags:
  - idor
requests:
  - path: "{{BaseURL}}/api/login"
  - path: "{{BaseURL}}/api/orders?id={{RangeInt(1|50)}}"
`)

	templates, errs := native.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "expected exactly 1")
}

func TestNativeLoadDir_IDORRejectsMatchers(t *testing.T) {
	dir := t.TempDir()
	writeNativeTemplate(t, dir, "idor-matchers.yaml", `
id: idor-matchers-style
info:
  name: Bad IDOR with matchers
  severity: high
tags:
  - idor
requests:
  - path: "{{BaseURL}}/api/orders?id={{RangeInt(1|50)}}"
    matchers:
      - type: status
        status:
          - 200
`)

	templates, errs := native.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "matchers:")
}

func TestNativeLoadDir_IDORRejectsMissingRangeMarker(t *testing.T) {
	dir := t.TempDir()
	writeNativeTemplate(t, dir, "idor-no-range.yaml", `
id: idor-no-range-style
info:
  name: Bad IDOR without a range
  severity: high
tags:
  - idor
requests:
  - path: "{{BaseURL}}/api/orders?id=1"
`)

	templates, errs := native.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "RangeInt")
}

func TestNativeLoadDir_ConditionTypoRejected(t *testing.T) {
	dir := t.TempDir()
	writeNativeTemplate(t, dir, "bad-condition.yaml", `
id: bad-condition
info:
  name: Bad condition
  severity: info
tags:
  - example
requests:
  - path: "{{BaseURL}}/"
    condition: totally_undefined_variable != ""
    matchers:
      - type: status
        status:
          - 200
`)

	templates, errs := native.LoadDir(dir)
	require.Empty(t, templates)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "invalid condition expression")
}

func TestNativeLoadDir_MalformedYAMLIsolated(t *testing.T) {
	dir := t.TempDir()
	writeNativeTemplate(t, dir, "broken.yaml", "id: broken\ninfo: [this is not valid: yaml structure\n")
	writeNativeTemplate(t, dir, "valid.yaml", `
id: still-valid
info:
  name: Still Valid
  severity: info
requests:
  - path: "{{BaseURL}}/"
`)

	templates, errs := native.LoadDir(dir)
	require.Len(t, errs, 1, "only the broken file should error")
	require.Len(t, templates, 1, "the valid file next to it still loads")
	assert.Equal(t, "still-valid", templates[0].ID)
}

func TestNativeLoadDir_RecursesSubdirectories(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "custom")
	require.NoError(t, os.Mkdir(vendorDir, 0o755))
	writeNativeTemplate(t, vendorDir, "nested.yaml", `
id: nested-template
info:
  name: Nested
  severity: info
requests:
  - path: "{{BaseURL}}/"
`)

	templates, errs := native.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1, "templates nested under a subdirectory must still be found")
}
