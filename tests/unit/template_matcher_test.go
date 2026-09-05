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

// TestMatcherValidate_AcceptsInteractshPart locks in the fix for a real,
// live false positive that predates this project's OOB infrastructure:
// upstream's linkerd-ssrf-detect.yaml matches `part: interactsh_protocol`
// against the word "http". Part() used to silently fall through to the
// response body for any unrecognized part, so this matched the literal
// substring "http" appearing anywhere in an ordinary HTML page — true for
// nearly any real website, not evidence of SSRF. As of the interactsh_ OOB
// work (docs/follow-up.md), interactsh_protocol/interactsh_request/
// interactsh_response are real, supported parts (see ValidPart's doc
// comment) — Validate now accepts this matcher rather than rejecting it,
// and the original false-positive class is prevented at runtime instead:
// nuclei.Executor.awaitOOB unconditionally populates all three in
// r.ExtraVars for every request (real callback or not), so Part()'s
// r.ExtraVars lookup for them never falls through to the body.
func TestMatcherValidate_AcceptsInteractshPart(t *testing.T) {
	for _, part := range []string{"interactsh_protocol", "interactsh_request", "interactsh_response"} {
		err := matcher.Validate(matcher.Matcher{Type: "word", Part: part, Words: []string{"http"}})
		require.NoError(t, err, "part %q should be a recognized, supported part now", part)
	}
}

// TestMatcherPart_InteractshFallsBackToEmpty_NotBody is the direct
// regression guard for the false-positive class TestMatcherValidate_
// AcceptsInteractshPart's doc comment describes: a request that never got
// an interactsh_ ExtraVars entry at all (e.g. a hand-built Response, or a
// bug that skipped awaitOOB) must never have Part("interactsh_protocol",
// ...) silently return the response body instead.
func TestMatcherPart_InteractshFallsBackToEmpty_NotBody(t *testing.T) {
	resp := matcher.Response{Body: []byte("<html>...http...</html>")}
	assert.Equal(t, "", matcher.Part("interactsh_protocol", resp), "an unset interactsh_ part must resolve to empty, never fall through to the body")
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

// TestMatcherEvaluate_PartContentType locks in `part: content_type`
// (matcher & extractor both share Part()), added for real upstream
// templates like gitlab-saml.yaml's SAML-panel check.
func TestMatcherEvaluate_PartContentType(t *testing.T) {
	resp := matcher.Response{
		Headers: http.Header{"Content-Type": []string{"application/xml"}},
		Body:    []byte("application/xml appears in the body too, must not match on that"),
	}
	m := matcher.Matcher{Type: "word", Part: "content_type", Words: []string{"application/xml"}}
	assert.True(t, m.Evaluate(resp))

	miss := matcher.Matcher{Type: "word", Part: "content_type", Words: []string{"text/html"}}
	assert.False(t, miss.Evaluate(resp))
}

// TestMatcherEvaluate_PartResponse locks in `part: response`, aliased to
// the existing "all" (header+body) behavior — every real `part: response`
// template sampled in the synced corpus only word/regex-matches header or
// body content, never the literal HTTP status line, so this is a safe,
// verified equivalence rather than an assumption (see matcher.Part's doc
// comment).
func TestMatcherEvaluate_PartResponse(t *testing.T) {
	resp := matcher.Response{
		Headers: http.Header{"X-App": []string{"Homarr"}},
		Body:    []byte("<title>Homarr</title>"),
	}
	fromHeader := matcher.Matcher{Type: "word", Part: "response", Words: []string{"Homarr"}}
	assert.True(t, fromHeader.Evaluate(resp), "response part must see header content")

	fromBody := matcher.Matcher{Type: "word", Part: "response", Words: []string{"<title>Homarr</title>"}}
	assert.True(t, fromBody.Evaluate(resp), "response part must see body content")
}

func TestMatcherValidate_AcceptsNewParts(t *testing.T) {
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "word", Part: "content_type", Words: []string{"x"}}))
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "word", Part: "response", Words: []string{"x"}}))
}

// TestMatcherEvaluate_PartLocationServerSetCookie is LT-22's (docs/follow-up.md)
// regression guard: these 3 named header-part shortcuts were entirely
// unimplemented before this (36/320 real-corpus rejections, ~11%) — ValidPart
// rejected them at load time and Part() had no case for them at all.
func TestMatcherEvaluate_PartLocationServerSetCookie(t *testing.T) {
	resp := matcher.Response{
		Headers: http.Header{
			"Location":   []string{"https://example.com/new"},
			"Server":     []string{"nginx/1.18.0"},
			"Set-Cookie": []string{"a=1; Path=/", "b=2; HttpOnly"},
		},
	}

	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "word", Part: "location", Words: []string{"x"}}))
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "word", Part: "server", Words: []string{"x"}}))
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "word", Part: "set_cookie", Words: []string{"x"}}))

	assert.True(t, matcher.Matcher{Type: "word", Part: "location", Words: []string{"/new"}}.Evaluate(resp))
	assert.True(t, matcher.Matcher{Type: "word", Part: "server", Words: []string{"nginx"}}.Evaluate(resp))
	assert.True(t, matcher.Matcher{Type: "word", Part: "set_cookie", Words: []string{"HttpOnly"}}.Evaluate(resp))
	// Both Set-Cookie lines must be visible, not just the first.
	assert.True(t, matcher.Matcher{Type: "word", Part: "set_cookie", Words: []string{"a=1"}}.Evaluate(resp))
}

func TestMatcherValidate(t *testing.T) {
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "status"}))
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "regex", Regex: []string{`ng-version="[0-9.]+"`}}))
	require.NoError(t, matcher.Validate(matcher.Matcher{Type: "dsl", DSL: []string{`status_code == 200`}}))

	require.Error(t, matcher.Validate(matcher.Matcher{Type: "regex", Regex: []string{`(unclosed`}}), "malformed regex is rejected")
	require.Error(t, matcher.Validate(matcher.Matcher{Type: "dsl", DSL: []string{`status_code === 200`}}), "malformed dsl is rejected")
	require.Error(t, matcher.Validate(matcher.Matcher{Type: "binary"}), "unsupported type is rejected")
}
