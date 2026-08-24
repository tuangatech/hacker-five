package unit

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

func TestExtract_RegexGroup(t *testing.T) {
	resp := matcher.Response{Body: []byte(`<span class="version">4.8.1</span>`)}
	extractors := []extractor.Extractor{
		{Type: "regex", Name: "version", Group: 1, Regex: []string{`<span class="version">([0-9.]+)`}},
	}
	out := extractor.Extract(extractors, resp)
	assert.Equal(t, "4.8.1", out["version"])
}

func TestExtract_RegexWholeMatch(t *testing.T) {
	resp := matcher.Response{Body: []byte("build-id: abc123")}
	extractors := []extractor.Extractor{
		{Type: "regex", Name: "buildID", Regex: []string{`abc\d+`}},
	}
	out := extractor.Extract(extractors, resp)
	assert.Equal(t, "abc123", out["buildID"])
}

func TestExtract_JSON(t *testing.T) {
	resp := matcher.Response{Body: []byte(`{"token":"tok-1","data":{"user":{"id":"42"}}}`)}
	extractors := []extractor.Extractor{
		{Type: "json", Name: "token", JSON: []string{"token"}},
		{Type: "json", Name: "userID", JSON: []string{"data.user.id"}},
	}
	out := extractor.Extract(extractors, resp)
	assert.Equal(t, "tok-1", out["token"])
	assert.Equal(t, "42", out["userID"])
}

func TestExtract_Kval(t *testing.T) {
	resp := matcher.Response{Headers: http.Header{"X-Request-Id": []string{"req-99"}}}
	extractors := []extractor.Extractor{
		{Type: "kval", Name: "reqID", Kval: []string{"X-Request-Id"}},
	}
	out := extractor.Extract(extractors, resp)
	assert.Equal(t, "req-99", out["reqID"])
}

func TestExtract_DSL(t *testing.T) {
	resp := matcher.Response{Body: []byte("hello world")}
	extractors := []extractor.Extractor{
		{Type: "dsl", Name: "bodyLen", DSL: []string{"len(body)"}},
	}
	out := extractor.Extract(extractors, resp)
	assert.Equal(t, "11", out["bodyLen"])
}

func TestExtract_UnnamedSkipped(t *testing.T) {
	resp := matcher.Response{Body: []byte("hello")}
	extractors := []extractor.Extractor{
		{Type: "regex", Regex: []string{"hello"}}, // no Name
	}
	out := extractor.Extract(extractors, resp)
	assert.Empty(t, out)
}

func TestExtract_NoMatchOmitted(t *testing.T) {
	resp := matcher.Response{Body: []byte("no version here")}
	extractors := []extractor.Extractor{
		{Type: "regex", Name: "version", Regex: []string{`[0-9]+\.[0-9]+`}},
	}
	out := extractor.Extract(extractors, resp)
	_, ok := out["version"]
	assert.False(t, ok)
}

func TestExtractorValidate(t *testing.T) {
	require.NoError(t, extractor.Validate(extractor.Extractor{Type: "json"}))
	require.NoError(t, extractor.Validate(extractor.Extractor{Type: "kval"}))
	require.NoError(t, extractor.Validate(extractor.Extractor{Type: "regex", Regex: []string{"abc"}}))
	require.NoError(t, extractor.Validate(extractor.Extractor{Type: "dsl", DSL: []string{"len(body)"}}))

	require.Error(t, extractor.Validate(extractor.Extractor{Type: "regex", Regex: []string{"(unclosed"}}))
	require.Error(t, extractor.Validate(extractor.Extractor{Type: "unsupported"}))
}
