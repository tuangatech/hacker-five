package unit

import (
	"net/http"
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

// TestDSLEval_BareHeaderNameFallback is the regression guard for LT-15
// (docs/follow-up.md): real Nuclei exposes every response header as a bare
// DSL identifier (lowercased name, hyphens folded to underscores) — a real
// rejected template, webp-server-lfi.yaml, used exactly this form
// (contains(server, "Webp-Server-Go")), which this evaluator had no
// fallback for at all before resolveIdent's Headers lookup.
func TestDSLEval_BareHeaderNameFallback(t *testing.T) {
	ctx := dsl.Context{Headers: http.Header{"Server": []string{"Webp-Server-Go/1.0"}, "X-Powered-By": []string{"PHP/8.1"}}}

	val, err := dsl.Eval(`contains(server, "Webp-Server-Go")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)

	val, err = dsl.Eval(`contains(x_powered_by, "PHP")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_UnknownHeaderStillErrors_WhenHeadersSet confirms the header
// fallback only resolves a header that's actually present — a genuinely
// unknown identifier still errors during real (non-validation) evaluation,
// same as before this change.
func TestDSLEval_UnknownHeaderStillErrors_WhenHeadersSet(t *testing.T) {
	ctx := dsl.Context{Headers: http.Header{"Server": []string{"nginx"}}}
	_, err := dsl.Eval(`nonexistent_var != ""`, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown identifier "nonexistent_var"`)
}

// TestDSLEval_AssumeUnknownIsHeader_ResolvesEmpty locks in the load-time-only
// escape hatch nuclei/loader.go's indexedDSLContext uses (LT-15): which
// headers a live target will actually send back is unknowable at load
// time, so with AssumeUnknownIsHeader set, an otherwise-unresolved bare
// identifier evaluates to an empty string rather than erroring — this is
// what lets a template referencing an arbitrary header name validate
// successfully at load time.
func TestDSLEval_AssumeUnknownIsHeader_ResolvesEmpty(t *testing.T) {
	ctx := dsl.Context{AssumeUnknownIsHeader: true}
	val, err := dsl.Eval(`contains(server, "Webp-Server-Go")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, false, val, "the assumed-empty stand-in value must not itself satisfy the check")
}

// TestDSLEval_OrderingOperators locks in <, <=, >, >= as top-level DSL
// comparison operators against IntVars — none of the four had a test before
// this one (only == and != were previously exercised at this level).
// duration>=6-shaped expressions (real upstream CVE templates using
// time-based checks) previously failed at the tokenizer with "unexpected
// character '=' at ..." since <=/>= were never tokenized as two-char
// operators, only bare < and >.
func TestDSLEval_OrderingOperators(t *testing.T) {
	ctx := dsl.Context{IntVars: map[string]int{"duration": 6}}

	cases := []struct {
		expr string
		want bool
	}{
		{"duration < 7", true},
		{"duration < 6", false},
		{"duration <= 6", true},
		{"duration <= 5", false},
		{"duration > 5", true},
		{"duration > 6", false},
		{"duration >= 6", true},
		{"duration >= 7", false},
	}
	for _, tc := range cases {
		val, err := dsl.Eval(tc.expr, ctx)
		require.NoError(t, err, tc.expr)
		assert.Equal(t, tc.want, val, tc.expr)
	}
}

// TestDSLEval_OrderingOperatorsRejectedForStrings confirms <=/>= fall into
// the same "operator not supported between strings" rejection ==/!= already
// exempt from — ordering has no defined meaning for this DSL's string type.
func TestDSLEval_OrderingOperatorsRejectedForStrings(t *testing.T) {
	ctx := dsl.Context{Vars: map[string]string{"v": "a"}}
	_, err := dsl.Eval(`v <= "b"`, ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported between strings")
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

// TestDSLEval_CompareVersions mirrors real corpus usage (grep across
// .nuclei-templates-cache/http): single-constraint checks like real
// upstream's apache-httpd-eol.yaml (compare_versions(version, '<=2.2.34'))
// and confluence-eol.yaml, plus the one real dual-constraint range check
// (">= 12.0.0", "< 14.0.0") — ANDed, both must hold.
func TestDSLEval_CompareVersions(t *testing.T) {
	tests := []struct {
		expr string
		want bool
	}{
		{`compare_versions("2.2.34", "<=2.2.34")`, true},
		{`compare_versions("2.2.35", "<=2.2.34")`, false},
		{`compare_versions("8.8.99", "<= 8.8.99")`, true},
		{`compare_versions("13.0.0", ">= 12.0.0", "< 14.0.0")`, true},
		{`compare_versions("14.0.0", ">= 12.0.0", "< 14.0.0")`, false}, // fails the second constraint
		{`compare_versions("11.0.0", ">= 12.0.0", "< 14.0.0")`, false}, // fails the first constraint
		{`compare_versions("2.2", "<=2.2.34")`, true},                 // short version, padded with 0 -> 2.2.0 <= 2.2.34
		{`compare_versions("2.2.34", "==2.2.34")`, true},
		{`compare_versions("2.2.34", "!=2.2.35")`, true},
		{`compare_versions("2.2.34", ">2.2.0")`, true},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			val, err := dsl.Eval(tt.expr, dsl.Context{})
			require.NoError(t, err)
			assert.Equal(t, tt.want, val)
		})
	}
}

func TestDSLEval_CompareVersionsInvalidSegment(t *testing.T) {
	_, err := dsl.Eval(`compare_versions("2.2.x", "<=2.2.34")`, dsl.Context{})
	require.Error(t, err)
}

// TestDSLEval_Base64Decode mirrors real upstream usage
// (base64_decode(base64_content)) — a single-arg decode, paired with the
// same-request extractor binding this function was added alongside (see
// docs/10-implementation-plan-ph1b.md's extractor->DSL binding note).
func TestDSLEval_Base64Decode(t *testing.T) {
	val, err := dsl.Eval(`base64_decode("aGVsbG8gd29ybGQ=")`, dsl.Context{})
	require.NoError(t, err)
	assert.Equal(t, "hello world", val)
}

func TestDSLEval_Base64DecodeInvalidInput(t *testing.T) {
	_, err := dsl.Eval(`base64_decode("not valid base64!!")`, dsl.Context{})
	require.Error(t, err)
}

// TestDSLEval_ExtractorNameAsIdentifier locks in the mechanism itself (not
// just the two new functions): an extractor's Name, bound via Context.Vars
// exactly like a native-format chain var, resolves as a bare DSL
// identifier — this is what nuclei.Executor's tryPath/tryRawIteration now
// populate from chainVars + a request's own freshly extracted values.
func TestDSLEval_ExtractorNameAsIdentifier(t *testing.T) {
	ctx := dsl.Context{Vars: map[string]string{"version": "2.2.34"}}
	val, err := dsl.Eval(`compare_versions(version, "<=2.2.34")`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_PlusConcatStrings is LT-22's (docs/follow-up.md) regression
// guard: "+" was entirely unimplemented before this, the single largest
// real-corpus rejection bucket (59/320, ~18%).
func TestDSLEval_PlusConcatStrings(t *testing.T) {
	val, err := dsl.Eval(`"foo" + "bar" == "foobar"`, dsl.Context{})
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_PlusAddsInts confirms "+" stays numeric addition when both
// operands are int, not string concatenation of their digits.
func TestDSLEval_PlusAddsInts(t *testing.T) {
	val, err := dsl.Eval(`1 + 2 == 3`, dsl.Context{})
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_PlusMixedStringAndIntConcatenates matches concat()'s own
// existing int-stringification behavior, for consistency between the two
// mechanisms.
func TestDSLEval_PlusMixedStringAndIntConcatenates(t *testing.T) {
	val, err := dsl.Eval(`"count:" + 5 == "count:5"`, dsl.Context{})
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_PlusBindsTighterThanComparison guards parseAdditive's
// precedence: "a + b == c" must parse as "(a + b) == c", not error out on a
// bare "b == c" sub-expression fed back into "+".
func TestDSLEval_PlusBindsTighterThanComparison(t *testing.T) {
	ctx := dsl.Context{Vars: map[string]string{"a": "foo", "b": "bar"}}
	val, err := dsl.Eval(`a + b == "foobar"`, ctx)
	require.NoError(t, err)
	assert.Equal(t, true, val)
}

// TestDSLEval_PlusInsideFunctionCall confirms function arguments (parseCall)
// also parse through the new additive level, e.g. contains(a + b, ...).
func TestDSLEval_PlusInsideFunctionCall(t *testing.T) {
	val, err := dsl.Eval(`contains("foo" + "bar", "oob")`, dsl.Context{})
	require.NoError(t, err)
	assert.Equal(t, true, val)
}
