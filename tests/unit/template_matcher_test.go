package unit

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

func TestMatcherEvaluate_Status(t *testing.T) {
	m := matcher.Matcher{Type: "status", Status: []int{200, 204}}
	assert.True(t, m.Evaluate(matcher.Response{StatusCode: 200}))
	assert.True(t, m.Evaluate(matcher.Response{StatusCode: 204}))
	assert.False(t, m.Evaluate(matcher.Response{StatusCode: 404}))
}

func TestMatcherEvaluate_Word(t *testing.T) {
	resp := matcher.Response{Body: []byte("Adminer</title>")}

	orMatcher := matcher.Matcher{Type: "word", Words: []string{"nope", "Adminer</title>"}}
	assert.True(t, orMatcher.Evaluate(resp), "or condition matches if any word is present")

	andMatcher := matcher.Matcher{Type: "word", Condition: "and", Words: []string{"Adminer</title>", "nope"}}
	assert.False(t, andMatcher.Evaluate(resp), "and condition requires every word present")
}

func TestMatcherEvaluate_WordPartHeader(t *testing.T) {
	resp := matcher.Response{Headers: http.Header{"X-Powered-By": []string{"PHP/8.1"}}}
	m := matcher.Matcher{Type: "word", Part: "header", Words: []string{"PHP/8.1"}}
	assert.True(t, m.Evaluate(resp))
}

func TestMatcherEvaluate_Regex(t *testing.T) {
	resp := matcher.Response{Body: []byte(`ng-version="17.0.1"`)}
	m := matcher.Matcher{Type: "regex", Regex: []string{`ng-version="[0-9.]+"`}}
	assert.True(t, m.Evaluate(resp))

	miss := matcher.Matcher{Type: "regex", Regex: []string{`ng-version="99\.`}}
	assert.False(t, miss.Evaluate(resp))
}

func TestMatcherEvaluate_Size(t *testing.T) {
	resp := matcher.Response{Body: []byte("12345")}
	assert.True(t, matcher.Matcher{Type: "size", Size: []int{5}}.Evaluate(resp))
	assert.False(t, matcher.Matcher{Type: "size", Size: []int{6}}.Evaluate(resp))
}

func TestMatcherEvaluate_DSL(t *testing.T) {
	resp := matcher.Response{StatusCode: 200, Body: []byte("hello world")}
	m := matcher.Matcher{Type: "dsl", DSL: []string{`status_code == 200 && contains(body, "world")`}}
	assert.True(t, m.Evaluate(resp))

	falseM := matcher.Matcher{Type: "dsl", DSL: []string{`status_code == 404`}}
	assert.False(t, falseM.Evaluate(resp))
}

// TestMatcherEvaluate_DSL_UnaryNegationAndHeader locks in the fix for a real
// gap found via upstream's http-missing-security-headers.yaml: unary "!"
// negation and the "header" built-in variable, both used by that template
// (e.g. "!regex('(?i)strict-transport-security', header)") and previously
// unsupported.
func TestMatcherEvaluate_DSL_UnaryNegationAndHeader(t *testing.T) {
	resp := matcher.Response{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": []string{"text/html"}},
	}

	missingCSP := matcher.Matcher{Type: "dsl", DSL: []string{`!regex('(?i)content-security-policy', header)`}}
	assert.True(t, missingCSP.Evaluate(resp), "CSP header is absent, so !regex(...) should be true")

	present := matcher.Matcher{Type: "dsl", DSL: []string{`!regex('(?i)content-type', header)`}}
	assert.False(t, present.Evaluate(resp), "Content-Type header is present, so !regex(...) should be false")

	// "!" must bind tighter than "&&" — !(a) && b, not !(a && b).
	precedence := matcher.Matcher{Type: "dsl", DSL: []string{`!regex('(?i)csp', header) && status_code == 200`}}
	assert.True(t, precedence.Evaluate(resp))
}

func TestMatcherEvaluate_Negative(t *testing.T) {
	resp := matcher.Response{StatusCode: 200}
	m := matcher.Matcher{Type: "status", Status: []int{404}, Negative: true}
	assert.True(t, m.Evaluate(resp), "negative flips a non-match into a match")
}

func TestEvaluateAll_Condition(t *testing.T) {
	resp := matcher.Response{StatusCode: 200, Body: []byte("Adminer</title>")}
	matchers := []matcher.Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "word", Words: []string{"Adminer</title>"}},
	}
	assert.True(t, matcher.EvaluateAll(matchers, matcher.And, resp))

	mismatched := []matcher.Matcher{
		{Type: "status", Status: []int{404}},
		{Type: "word", Words: []string{"Adminer</title>"}},
	}
	assert.False(t, matcher.EvaluateAll(mismatched, matcher.And, resp))
	assert.True(t, matcher.EvaluateAll(mismatched, matcher.Or, resp))
}

// TestEvaluateAll_Empty locks in a fix for a real, live false positive: an
// empty matchers slice used to trivially return true. Real templates like
// upstream's herokuapp-detect.yaml and vmware-horizon-version.yaml carry
// only Extractors and no Matchers at all (a passive-fingerprint pattern —
// "report what this regex captured, if anything"), and the old "true"
// behavior meant every such template unconditionally produced a Finding
// against every target, regardless of whether its extractor found anything.
// Confirmed against real Nuclei's own source (pkg/protocols/protocols.go):
// an extractor-only result has Matched=false and is skipped from output.
func TestEvaluateAll_Empty(t *testing.T) {
	assert.False(t, matcher.EvaluateAll(nil, matcher.And, matcher.Response{}), "no matchers must not be treated as a match")
	assert.False(t, matcher.EvaluateAll([]matcher.Matcher{}, matcher.Or, matcher.Response{}), "same for an explicit empty slice, either condition")
}

// TestMatcherValidate_RejectsOutOfBandPart locks in a fix for a second real,
// live false positive: upstream's linkerd-ssrf-detect.yaml matches
// `part: interactsh_protocol` (an out-of-band callback value this project
// has no interactsh/OAST infrastructure to supply) against the word "http".
// Part() used to silently fall through to the response body for any
// unrecognized part, so this matched the literal substring "http" appearing
// anywhere in an ordinary HTML page — true for nearly any real website, not
// evidence of SSRF. Now rejected at load time instead.
func TestMatcherValidate_RejectsOutOfBandPart(t *testing.T) {
	err := matcher.Validate(matcher.Matcher{Type: "word", Part: "interactsh_protocol", Words: []string{"http"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out-of-band")
}

// TestMatchingNames locks in the fix for a real usefulness gap: a
// matchers-condition: or template with several named sub-checks (like
// upstream's http-missing-security-headers.yaml) used to only be able to
// say "something matched" — this reports which named check(s) actually
// fired, so a Finding can be specific instead of generic.
func TestMatchingNames(t *testing.T) {
	resp := matcher.Response{Headers: http.Header{"Content-Type": []string{"text/html"}}}
	matchers := []matcher.Matcher{
		{Type: "dsl", Name: "csp", DSL: []string{`!regex('(?i)content-security-policy', header)`}},
		{Type: "dsl", Name: "content-type", DSL: []string{`!regex('(?i)content-type', header)`}},
		{Type: "status", Name: "", Status: []int{200}}, // unnamed, must be omitted even if it matches
	}
	names := matcher.MatchingNames(matchers, resp)
	assert.Equal(t, []string{"csp"}, names, "only the named, actually-matching check should be reported")
}

func TestMatcherValidate(t *testing.T) {
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "status"}))
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "regex", Regex: []string{`ng-version="[0-9.]+"`}}))
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "dsl", DSL: []string{`status_code == 200`}}))

	require.Error(t, matcher.Validate(matcher.Matcher{Type: "regex", Regex: []string{`(unclosed`}}), "malformed regex is rejected")
	require.Error(t, matcher.Validate(matcher.Matcher{Type: "dsl", DSL: []string{`status_code === 200`}}), "malformed dsl is rejected")
	require.Error(t, matcher.Validate(matcher.Matcher{Type: "binary"}), "unsupported type is rejected")
}
