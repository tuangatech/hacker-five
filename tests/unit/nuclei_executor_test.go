package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

func newExecutorClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

func TestExecutorRun_SinglePathMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`ng-version="17.0.1"`))
		}
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "angular-detect-style",
		Info: nuclei.Info{Name: "Angular detect", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method: http.MethodGet,
			Path:   []string{"{{BaseURL}}"},
			Matchers: []matcher.Matcher{
				{Type: "word", Words: []string{"ng-version="}},
			},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "misconfig", findings[0].Type)
	assert.Equal(t, "info", findings[0].Severity)
}

func TestExecutorRun_MultiPathStopsAtFirstMatch(t *testing.T) {
	var hits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/adminer.php" {
			_, _ = w.Write([]byte("Adminer</title>"))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "adminer-panel-style",
		Info: nuclei.Info{Name: "Adminer panel", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method:           http.MethodGet,
			Path:             []string{"{{BaseURL}}/adminer.php", "{{BaseURL}}/_adminer.php", "{{BaseURL}}/adminer/"},
			StopAtFirstMatch: true,
			Matchers: []matcher.Matcher{
				{Type: "word", Words: []string{"Adminer</title>"}},
			},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, []string{"/adminer.php"}, hits, "stop-at-first-match must not try the remaining paths once one matches")
}

func TestExecutorRun_NoMatchNoFinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "no-hit",
		Info: nuclei.Info{Name: "No hit", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method: http.MethodGet,
			Path:   []string{"{{BaseURL}}/nope"},
			Matchers: []matcher.Matcher{
				{Type: "status", Status: []int{200}},
			},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestExecutorRun_ChainedRequestsUseExtractedVariable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			_, _ = w.Write([]byte(`{"token":"tok-abc"}`))
		case "/profile":
			if r.Header.Get("Authorization") == "Bearer tok-abc" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("secret profile data"))
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
		}
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "chained-template",
		Info: nuclei.Info{Name: "Chained", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{
			{
				Method: http.MethodGet,
				Path:   []string{"{{BaseURL}}/login"},
				Extractors: []extractor.Extractor{
					{Type: "json", Name: "auth_token", JSON: []string{"token"}},
				},
				Matchers: []matcher.Matcher{
					{Type: "status", Status: []int{200}},
				},
			},
			{
				Method:  http.MethodGet,
				Path:    []string{"{{BaseURL}}/profile"},
				Headers: map[string]string{"Authorization": "Bearer {{auth_token}}"},
				Matchers: []matcher.Matcher{
					{Type: "word", Words: []string{"secret profile data"}},
				},
			},
		},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 2, "both the login and profile requests should match")
}
