package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
	"github.com/tuangatech/hacker-five/pkg/template/native"
)

func TestNativeExecutorRun_SingleRequestMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(server.Close)

	tmpl := &native.Template{
		ID:   "single-match",
		Info: native.Info{Name: "Single match", Severity: "info"},
		Requests: []native.Request{{
			Path:     "{{BaseURL}}/",
			Matchers: []matcher.Matcher{{Type: "word", Words: []string{"hello"}}},
		}},
	}

	findings, err := native.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl, "", "")
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "custom", findings[0].Type, "no tags: falls back to \"custom\"")
}

// TestNativeExecutorRun_WithHeaders_AppliedToRequest is
// nuclei.Executor's TestExecutorRun_WithHeaders_AppliedToRequest
// counterpart for the native generic (non-idor-tagged) template path.
func TestNativeExecutorRun_WithHeaders_AppliedToRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "session=abc123" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte("authenticated content"))
	}))
	t.Cleanup(server.Close)

	tmpl := &native.Template{
		ID:   "cookie-gated",
		Info: native.Info{Name: "Cookie gated", Severity: "info"},
		Requests: []native.Request{{
			Path:     "{{BaseURL}}/",
			Matchers: []matcher.Matcher{{Type: "word", Words: []string{"authenticated content"}}},
		}},
	}

	exec := native.New(newExecutorClient()).WithHeaders(map[string]string{"Cookie": "session=abc123"})
	findings, err := exec.Run(context.Background(), server.URL, tmpl, "", "")
	require.NoError(t, err)
	require.Len(t, findings, 1, "WithHeaders' Cookie must have reached the request for the gated content to be visible at all")
}

func TestNativeExecutorRun_NoMatchersNeverAFindingButStillExtracts(t *testing.T) {
	var profileHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			// No matchers on this request — pure chaining step, per
			// docs/10-implementation-plan-ph1b.md Step 3: extraction must
			// still run even though there's nothing to match against.
			_, _ = w.Write([]byte(`{"token":"tok-abc"}`))
		case "/profile":
			profileHit = true
			if r.Header.Get("Authorization") == "Bearer tok-abc" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("secret profile data"))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	}))
	t.Cleanup(server.Close)

	tmpl := &native.Template{
		ID:   "chained",
		Info: native.Info{Name: "Chained", Severity: "info"},
		Requests: []native.Request{
			{
				Path: "{{BaseURL}}/login",
				Extractors: []extractor.Extractor{
					{Type: "json", Name: "auth_token", JSON: []string{"token"}},
				},
				// no matchers: — must never produce a finding on its own
			},
			{
				Path:      "{{BaseURL}}/profile",
				Headers:   map[string]string{"Authorization": "Bearer {{auth_token}}"},
				Condition: `auth_token != ""`,
				Matchers:  []matcher.Matcher{{Type: "word", Words: []string{"secret profile data"}}},
			},
		},
	}

	findings, err := native.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl, "", "")
	require.NoError(t, err)
	require.Len(t, findings, 1, "only request 2 (the actual probe) should produce a finding")
	assert.True(t, profileHit, "request 2 must have fired, meaning auth_token was extracted from request 1 despite it having no matchers")
}

func TestNativeExecutorRun_FalseConditionSkipsRequest(t *testing.T) {
	var probeHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe" {
			probeHit = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	tmpl := &native.Template{
		ID:   "conditional",
		Info: native.Info{Name: "Conditional", Severity: "info"},
		Requests: []native.Request{{
			Path:      "{{BaseURL}}/probe",
			Condition: `undefined_token != ""`, // undefined -> dsl.Eval errors -> treated as false
			Matchers:  []matcher.Matcher{{Type: "status", Status: []int{200}}},
		}},
	}

	findings, err := native.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl, "", "")
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.False(t, probeHit, "a false/unresolvable condition must skip the request entirely")
}

func TestNativeExecutorRun_MatchersConditionDefaultsToAnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("only-one-keyword-present"))
	}))
	t.Cleanup(server.Close)

	tmpl := &native.Template{
		ID:   "and-default",
		Info: native.Info{Name: "AND default", Severity: "info"},
		Requests: []native.Request{{
			Path: "{{BaseURL}}/",
			// no matchers-condition: -> defaults to "and" for native (unlike
			// Nuclei's "or" default) — one matcher fails, so overall: no match.
			Matchers: []matcher.Matcher{
				{Type: "word", Words: []string{"only-one-keyword-present"}},
				{Type: "word", Words: []string{"this-keyword-is-absent"}},
			},
		}},
	}

	findings, err := native.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl, "", "")
	require.NoError(t, err)
	assert.Empty(t, findings, "AND default means both matchers must pass; one doesn't")
}
