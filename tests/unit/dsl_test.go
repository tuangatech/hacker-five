package unit

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/dsl"
)

// TestDSLEval_VarsFallback locks in the Vars addition to dsl.Context — added
// for the native template engine's condition: field (Step 3), which
// evaluates against already-bound template variables, not an HTTP response.
func TestDSLEval_VarsFallback(t *testing.T) {
	ctx := dsl.Context{Vars: map[string]string{"auth_token": "tok-abc"}}

	val, err := dsl.Eval(`auth_token != ""`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = dsl.Eval(`auth_token == "tok-abc"`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

func TestDSLEval_UnboundVarStillErrors(t *testing.T) {
	_, err := dsl.Eval(`nonexistent_var != ""`, dsl.Context{Vars: map[string]string{}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown identifier "nonexistent_var"`)
}

// TestDSLEval_BuiltinsTakePriorityOverVars confirms a bound var named the
// same as a built-in (status_code/body/header) can't shadow it — Context's
// doc comment on Vars states this ordering explicitly.
func TestDSLEval_BuiltinsTakePriorityOverVars(t *testing.T) {
	ctx := dsl.Context{StatusCode: 200, Vars: map[string]string{"status_code": "should-not-be-used"}}
	val, err := dsl.Eval(`status_code == 200`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_IntVarsFallback locks in the IntVars addition to dsl.Context —
// added for a raw:-request block with more than one Raw entry, whose
// matcher needs status_code_N as a real int (e.g. real upstream's
// open-proxy-internal.yaml: "status_code_1 != 404"), not a string —
// compare() only compares matching types, so a string wouldn't type-check
// against a numeric literal.
func TestDSLEval_IntVarsFallback(t *testing.T) {
	ctx := dsl.Context{IntVars: map[string]int{"status_code_2": 404}}

	val, err := dsl.Eval(`status_code_2 == 404`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = dsl.Eval(`status_code_2 != 200`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_EscapedQuoteInStringLiteral locks in the tokenizer fix for a
// backslash-escaped quote inside a DSL string literal — found live against
// real upstream templates (e.g. airbyte-panel.yaml's
// `contains_any(to_lower(body), "<title>airbyte", "name=\"airbyte:\"")`),
// which previously failed to even tokenize, let alone evaluate.
func TestDSLEval_EscapedQuoteInStringLiteral(t *testing.T) {
	val, err := dsl.Eval(`body == "name=\"airbyte\""`, dsl.Context{Body: `name="airbyte"`})
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

func TestDSLEval_ContainsAny(t *testing.T) {
	ctx := dsl.Context{Body: "hello world"}
	val, err := dsl.Eval(`contains_any(body, "xyz", "world")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = dsl.Eval(`contains_any(body, "xyz", "abc")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, false, val)
}

func TestDSLEval_ContainsAll(t *testing.T) {
	ctx := dsl.Context{Body: "hello world"}
	val, err := dsl.Eval(`contains_all(body, "hello", "world")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = dsl.Eval(`contains_all(body, "hello", "xyz")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, false, val)
}

func TestDSLEval_ToLowerBothSpellings(t *testing.T) {
	ctx := dsl.Context{Body: "ABC"}
	for _, fn := range []string{"to_lower", "tolower"} {
		val, err := dsl.Eval(fn+`(body) == "abc"`, ctx)
		require.NoError(t, err)
		assert.Equal(t, true, val, fn)
	}
}

// TestDSLEval_Trim mirrors real upstream's etcd-version.yaml extractor use:
// `trim(body,"{}")`.
func TestDSLEval_Trim(t *testing.T) {
	val, err := dsl.Eval(`trim(body,"{}")`, dsl.Context{Body: "{etcd}"})
	require.NoError(t, err)
	assert.Equal(t, "etcd", val)
}

func TestDSLEval_MD5AndSHA1(t *testing.T) {
	val, err := dsl.Eval(`md5(body)`, dsl.Context{Body: "roxyfileman-fileupload"})
	require.NoError(t, err)
	assert.Equal(t, "99acb46eabd01958e22fae1792e83ca9", val)

	val, err = dsl.Eval(`sha1(body)`, dsl.Context{Body: ""})
	require.NoError(t, err)
	assert.Equal(t, "da39a3ee5e6b4b0d3255bfef95601890afd80709", val)
}

// TestDSLEval_ContentTypeAndResponseIdentifiers mirrors two real upstream
// shapes found only after the initial DSL fix: redoc-api-docs.yaml's
// `contains(content_type, "text/html")` and jetty-directory-listing.yaml's
// `contains_all(response, "Jetty", "jetty-dir.css")` — both use these names
// as bare DSL identifiers, not just matcher `part:` values.
func TestDSLEval_ContentTypeAndResponseIdentifiers(t *testing.T) {
	ctx := dsl.Context{ContentType: "text/html; charset=utf-8", Header: "X-App: Jetty\n", Body: "jetty-dir.css"}

	val, err := dsl.Eval(`contains(content_type, "text/html")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = dsl.Eval(`contains_all(response, "Jetty", "jetty-dir.css")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_MMH3ReferenceVector checks the hand-rolled MurmurHash3 x86_32
// implementation against a canonical published test vector (seed 0,
// "hello" -> 0x248bfa47), from spaolacci/murmur3's own test suite — not a
// value derived from this project's own implementation, which would prove
// nothing about correctness.
func TestDSLEval_MMH3ReferenceVector(t *testing.T) {
	val, err := dsl.Eval(`mmh3("hello")`, dsl.Context{})
	require.NoError(t, err)
	assert.Equal(t, "613153351", val) // int32(0x248bfa47) == 613153351
}

// TestDSLEval_MMH3Base64PyFaviconHash mirrors real upstream's
// appwrite-panel.yaml matcher shape: `mmh3(base64_py(body))` compared
// against a quoted decimal string, including a negative one — confirming
// mmh3() returns a signed-decimal string (not a bare int, which couldn't
// compare equal to a quoted string under this project's typed compare()).
// Every value here (this one, plus two more in
// TestDSLEval_Base64PyMMH3PythonCrossCheck below) is cross-checked against
// a real, executed Python 3.12 `base64.encodebytes` + `mmh3.hash` run, not
// just this project's own implementation or documentation — see
// docs/10-implementation-plan-ph1b.md's "Post-v0.1.0 DSL/part expansion"
// note for how (a local venv + pip install, no sudo needed).
func TestDSLEval_MMH3Base64PyFaviconHash(t *testing.T) {
	val, err := dsl.Eval(`"-1787112514" == mmh3(base64_py(body))`, dsl.Context{Body: "hello world"})
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_Base64PyMMH3PythonCrossCheck adds the empty-string and
// multi-line-wrap edge cases to the same real Python cross-check — the
// multi-line case (>76 encoded chars, forcing base64_py's line-wrapping to
// actually wrap more than once) is the one most likely to reveal an
// off-by-one in a hand-rolled port, so it's the one that matters most here.
func TestDSLEval_Base64PyMMH3PythonCrossCheck(t *testing.T) {
	val, err := dsl.Eval(`mmh3(base64_py(body))`, dsl.Context{Body: ""})
	require.NoError(t, err)
	assert.Equal(t, "0", val)

	longBody := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 3)
	val, err = dsl.Eval(`mmh3(base64_py(body))`, dsl.Context{Body: longBody})
	require.NoError(t, err)
	assert.Equal(t, "545616131", val)
}
