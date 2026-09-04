package unit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/oob"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// apacheServerStatusFlowTemplate mirrors real upstream's
// apache-server-status-localhost.yaml (simplified to one spoofed header
// instead of the real template's eleven): a 403/404/401 "is it blocked"
// gate (internal: true) followed by a bypass attempt using a spoofed
// X-Forwarded-For header — connected via flow: http(1) && http(2). See
// TestExecutorRun_FlowApacheServerStatus_FalsePositiveFixed and
// TestExecutorRun_FlowApacheServerStatus_RealBypassDetected below, and
// docs/10-implementation-plan-ph1b.md's flow: note for the real, live false
// positive this reproduces and fixes.
const apacheServerStatusFlowTemplate = `
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
          - 401
        condition: or
        internal: true
  - method: GET
    path:
      - "{{BaseURL}}/server-status"
    headers:
      X-Forwarded-For: 127.0.0.1
    matchers:
      - type: word
        words:
          - "Apache Server Status"
`

// TestExecutorRun_FlowApacheServerStatus_FalsePositiveFixed is the concrete
// proof flow: support fixes Step 2's real, live false positive: against a
// correctly-configured server (doesn't trust X-Forwarded-For, always
// blocks /server-status), request 1's internal gate matcher passes (403 =
// correctly blocked) but request 2's spoofed-header bypass genuinely fails
// — so no finding should be produced. Before flow: support, this project
// ran both requests unconditionally/independently and reported request 1's
// own 403 match as a false "Server Status Disclosure" finding.
func TestExecutorRun_FlowApacheServerStatus_FalsePositiveFixed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "apache-status.yaml", apacheServerStatusFlowTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings, "a correctly-configured server must not be reported as vulnerable")
}

// TestExecutorRun_FlowApacheServerStatus_RealBypassDetected is the positive
// counterpart: a server that actually trusts the spoofed X-Forwarded-For
// header. Request 1's gate still passes (403 without the header), and
// request 2's bypass now genuinely succeeds — exactly one finding, from
// request 2 only (request 1's matcher is internal: true and never produces
// one).
func TestExecutorRun_FlowApacheServerStatus_RealBypassDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			_, _ = w.Write([]byte("Apache Server Status for localhost"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "apache-status.yaml", apacheServerStatusFlowTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Evidence["response"], "Apache Server Status")
}

// TestExecutorRun_FlowUmamiPanel_MatcherlessExtractorChains is modeled on
// real upstream's umami-panel.yaml: request 1 has a real matcher (the
// finding), request 2 has no matchers at all — only an extractor. Before
// this project's chainable fix (see tryPath's doc comment), a matcher-less
// request never ran its extractors (matcher.EvaluateAll(nil, ...) is
// false), so request 2 would never even fire under flow:'s && short
// circuit — chainVars.Extract needs to run regardless of there being
// nothing to match. Verified here by tracking which paths the test server
// actually saw, since Run doesn't expose chainVars directly.
func TestExecutorRun_FlowUmamiPanel_MatcherlessExtractorChains(t *testing.T) {
	var hits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		switch r.URL.Path {
		case "/login":
			_, _ = w.Write([]byte("umami</h1>"))
		case "/~404":
			_, _ = w.Write([]byte("v1.2.3"))
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "umami.yaml", `
id: umami-panel-style
info:
  name: Umami Panel
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    matchers:
      - type: word
        words:
          - "umami</h1>"
  - method: GET
    path:
      - "{{BaseURL}}/~404"
    extractors:
      - type: regex
        name: version
        part: body
        regex:
          - 'v(\d+\.\d+\.\d+)'
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "request 1's word matcher should produce exactly one finding")
	assert.ElementsMatch(t, []string{"/login", "/~404"}, hits, "request 2 (matcher-less, extractor-only) must still fire once request 1's flow-gate matched")
}

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

// TestExecutorRun_WithHeaders_AppliedToRequest proves WithHeaders actually
// reaches the outgoing request — the real gap docs/11-implementation-plan-ph2.md
// Step 5 found: DVWA's real XSS/SQLi pages are gated behind a session
// cookie, and neither template format had any way to carry one in. The
// server here only serves the vulnerable-looking content when it sees the
// session cookie, so a finding can only come from WithHeaders' value
// actually landing on the request.
func TestExecutorRun_WithHeaders_AppliedToRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "PHPSESSID=abc123; security=low" {
			w.WriteHeader(http.StatusFound) // simulates DVWA's login redirect
			return
		}
		_, _ = w.Write([]byte(`Hello "><injectable>`))
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "dvwa-xss-style",
		Info: nuclei.Info{Name: "DVWA XSS", Severity: "low"},
		HTTP: []nuclei.HTTPRequest{{
			Method: http.MethodGet,
			Path:   []string{"{{BaseURL}}/vulnerabilities/xss_r/?name=test"},
			Matchers: []matcher.Matcher{
				{Type: "word", Words: []string{`"><injectable>`}},
			},
		}},
	}

	exec := nuclei.New(newExecutorClient()).WithHeaders(map[string]string{"Cookie": "PHPSESSID=abc123; security=low"})
	findings, err := exec.Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 1, "WithHeaders' Cookie must have reached the request for the session-gated content to be visible at all")
}

// TestExecutorRun_WithHeaders_TemplateHeaderWins proves a template's own
// Headers: entry overrides WithHeaders' baseline on a literal name
// conflict, per WithHeaders' documented "baseline, not an override"
// contract.
func TestExecutorRun_WithHeaders_TemplateHeaderWins(t *testing.T) {
	var gotCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "header-override-style",
		Info: nuclei.Info{Name: "Header override", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method:  http.MethodGet,
			Path:    []string{"{{BaseURL}}"},
			Headers: map[string]string{"Cookie": "template-value"},
		}},
	}

	exec := nuclei.New(newExecutorClient()).WithHeaders(map[string]string{"Cookie": "cli-baseline-value"})
	_, err := exec.Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	assert.Equal(t, "template-value", gotCookie)
}

// TestExecutorRun_WithHeaders_AppliedToRawRequest is the raw:-based
// counterpart to TestExecutorRun_WithHeaders_AppliedToRequest — WithHeaders
// was only wired into tryPath's request builder, not tryRaw's, so any
// raw:-based template (needed for e.g. boolean-based blind SQLi's
// two-request differential, which path:'s try-each-until-match shape can't
// express) silently couldn't carry a session cookie via --header at all.
// The server here only serves the vulnerable-looking content when it sees
// the cookie, so a finding can only come from WithHeaders' value actually
// reaching the raw: request.
func TestExecutorRun_WithHeaders_AppliedToRawRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "PHPSESSID=abc123; security=low" {
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("User ID exists in the database."))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "raw-header.yaml", `
id: raw-header-style
info:
  name: Raw header style
  severity: medium
http:
  - raw:
      - |
        GET /vulnerabilities/sqli_blind/?id=1 HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words:
          - "exists in the database"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	exec := nuclei.New(newExecutorClient()).WithHeaders(map[string]string{"Cookie": "PHPSESSID=abc123; security=low"})
	findings, err := exec.Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "WithHeaders' Cookie must have reached the raw: request for the session-gated content to be visible at all")
}

// TestExecutorRun_WithHeaders_RawTemplateHeaderWins proves the raw: path
// follows the same "baseline, not an override" contract as tryPath: a
// header line the raw: text itself sets wins over WithHeaders' baseline on
// a literal name conflict.
func TestExecutorRun_WithHeaders_RawTemplateHeaderWins(t *testing.T) {
	var gotCookie string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "raw-header-override.yaml", `
id: raw-header-override-style
info:
  name: Raw header override style
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        Cookie: template-value
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	exec := nuclei.New(newExecutorClient()).WithHeaders(map[string]string{"Cookie": "cli-baseline-value"})
	_, err := exec.Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	assert.Equal(t, "template-value", gotCookie)
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

// TestExecutorRun_TrailingSlashTarget_NoDoubleSlash guards the 2026-09-04
// fix (docs/follow-up.md P0-3): templates conventionally write
// "{{BaseURL}}/path", so a target passed with its own trailing slash
// rendered "http://host//path" in both the fired request and the reported
// Finding.Target. Executor.Run now trims a trailing slash from the target
// once, up front.
func TestExecutorRun_TrailingSlashTarget_NoDoubleSlash(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path == "/panel" {
			_, _ = w.Write([]byte("admin panel"))
		}
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "panel-detect",
		Info: nuclei.Info{Name: "Panel detect", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method:   http.MethodGet,
			Path:     []string{"{{BaseURL}}/panel"},
			Matchers: []matcher.Matcher{{Type: "word", Words: []string{"admin panel"}}},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL+"/", tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "/panel", gotPath, "the fired request path must not be doubled")
	assert.Equal(t, server.URL+"/panel", findings[0].Target)
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

// TestExecutorRun_PathWithPayloads mirrors real upstream's
// phpmyadmin-panel.yaml shape (the more common payloads: pattern in the
// synced corpus — see docs/10-implementation-plan-ph1b.md's raw:/payloads:
// note): a plain path:-based request with a single inline-list payload
// substituted into that path, stop-at-first-match true.
func TestExecutorRun_PathWithPayloads(t *testing.T) {
	var hits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/phpmyadmin/" {
			_, _ = w.Write([]byte(`alt="phpMyAdmin`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "path-payload.yaml", `
id: path-payload-style
info:
  name: Path Payload Style
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}{{paths}}"
    payloads:
      paths:
        - ""
        - "/phpmyadmin/"
        - "/admin/phpmyadmin/"
    stop-at-first-match: true
    matchers:
      - type: word
        words:
          - 'alt="phpMyAdmin'
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, []string{"/", "/phpmyadmin/"}, hits, "stop-at-first-match must stop the payload loop once one value matches")
}

// TestExecutorRun_RawSinglePayload mirrors real upstream's
// apache-mod-negotiation-listing.yaml shape: a raw: request with a single
// inline-list payload, firing once per value.
func TestExecutorRun_RawSinglePayload(t *testing.T) {
	var hits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Available variants: href=\"admin.php\""))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "raw-payload.yaml", `
id: raw-payload-style
info:
  name: Raw Payload Style
  severity: low
http:
  - raw:
      - |
        GET {{path}} HTTP/1.1
        Host: {{Hostname}}
    payloads:
      path:
        - /index
        - /admin
        - /login
    matchers:
      - type: word
        words:
          - "Available variants"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "only the /admin iteration should match")
	assert.Equal(t, []string{"/index", "/admin", "/login"}, hits, "no stop-at-first-match set, so every payload value fires")
}

// TestExecutorRun_RawMultiEntryCorrelation mirrors real upstream's
// open-proxy-internal.yaml shape (scaled down): multiple raw: entries in
// one block, all fired every time, with a matcher correlating results
// across them via indexed identifiers (body_N/status_code_N) — the
// scope the user explicitly asked for over the simpler
// try-each-independently alternative.
func TestExecutorRun_RawMultiEntryCorrelation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte("It works"))
		case "/internal-probe":
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "multi-raw.yaml", `
id: multi-raw-correlation-style
info:
  name: Multi Raw Correlation Style
  severity: high
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /internal-probe HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && contains(body_1, \"It works\") && status_code_2 == 404"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "the correlating matcher should fire once both probes' results are bound")
}

// TestExecutorRun_PathDuration_SlowResponseMatches is modeled on real
// upstream's CVE-2023-2130.yaml: a plain path:-based (non-raw:) blind-SQLi
// sleep check using the bare "duration" DSL identifier. Proves tryPath now
// times its single request and binds it — before this, path:-based
// templates had no timing signal at all (only tryRaw did).
func TestExecutorRun_PathDuration_SlowResponseMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1100 * time.Millisecond)
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "bare-duration-style",
		Info: nuclei.Info{Name: "Bare Duration Style", Severity: "medium"},
		HTTP: []nuclei.HTTPRequest{{
			Method: http.MethodGet,
			Path:   []string{"{{BaseURL}}/"},
			Matchers: []matcher.Matcher{
				{Type: "dsl", DSL: []string{"duration>=1"}},
			},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 1, "a genuinely slow response must satisfy duration>=1")
}

// TestExecutorRun_PathDuration_FastResponseNoMatch is
// TestExecutorRun_PathDuration_SlowResponseMatches' negative counterpart —
// an immediate response must not satisfy the same duration>=1 threshold,
// confirming this isn't a matcher that trivially always fires.
func TestExecutorRun_PathDuration_FastResponseNoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "bare-duration-style",
		Info: nuclei.Info{Name: "Bare Duration Style", Severity: "medium"},
		HTTP: []nuclei.HTTPRequest{{
			Method: http.MethodGet,
			Path:   []string{"{{BaseURL}}/"},
			Matchers: []matcher.Matcher{
				{Type: "dsl", DSL: []string{"duration>=1"}},
			},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Empty(t, findings, "an immediate response must not satisfy duration>=1")
}

// TestExecutorRun_RawDurationN_CorrelatesPerEntry is modeled on real
// upstream's CVE-2015-2196.yaml-style raw:-multi-request blind SQLi: a fast
// baseline probe followed by a deliberately slow one, correlated via
// duration_1/duration_2 in one shared DSL matcher — proves tryRawIteration
// times each raw: entry independently, not just the last one.
func TestExecutorRun_RawDurationN_CorrelatesPerEntry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(1100 * time.Millisecond)
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "raw-duration.yaml", `
id: raw-duration-correlation-style
info:
  name: Raw Duration Correlation Style
  severity: high
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /slow HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: dsl
        dsl:
          - "duration_1 < 1 && duration_2 >= 1"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "duration_1/duration_2 must reflect each entry's own elapsed time, not a shared or last-entry-only value")
}

// TestExecutorRun_RawContentTypeN_Correlates is modeled on real upstream's
// CVE-2015-2755.yaml-style raw:-multi-request check correlating each probe's
// own Content-Type — proves tryRawIteration binds content_type_N per entry,
// the same way it already binds body_N/header_N/status_code_N.
func TestExecutorRun_RawContentTypeN_Correlates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "application/json")
		case "/other":
			w.Header().Set("Content-Type", "text/plain")
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "raw-content-type.yaml", `
id: raw-content-type-correlation-style
info:
  name: Raw Content-Type Correlation Style
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /other HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: dsl
        dsl:
          - "contains(content_type_1, \"json\") && contains(content_type_2, \"text/plain\")"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "content_type_1/content_type_2 must reflect each entry's own response header")
}

// TestExecutorRun_Pitchfork_ZipsKeysLockstep is modeled on real upstream's
// zabbix-default-login.yaml-style credential check: two payload keys,
// attack: pitchfork. The server only reports success for the
// index-correlated pair (username[0]/password[0]) — pitchfork must reach
// it, and must fire exactly 2 requests total (one per lockstep pass), never
// the 4 a cartesian product would try.
func TestExecutorRun_Pitchfork_ZipsKeysLockstep(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-User") == "admin" && r.Header.Get("X-Pass") == "pass1" {
			_, _ = w.Write([]byte("SUCCESS"))
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "pitchfork.yaml", `
id: pitchfork-style
info:
  name: Pitchfork Style
  severity: high
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-User: {{username}}
        X-Pass: {{password}}
    attack: pitchfork
    payloads:
      username:
        - admin
        - root
      password:
        - pass1
        - pass2
    matchers:
      - type: word
        words:
          - "SUCCESS"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "the index-correlated pair (admin/pass1) must be reached")
	assert.Equal(t, 2, requests, "pitchfork must fire exactly one request per lockstep pass (2), not a cartesian product (4)")
}

// TestExecutorRun_Clusterbomb_TriesEveryCombination is
// TestExecutorRun_Pitchfork_ZipsKeysLockstep's counterpart, proving the
// opposite: the server's success condition is a cross combination
// (username[0]/password[1]) that pitchfork's lockstep pairing would never
// reach — only clusterbomb's full Cartesian product does. Also asserts all
// 4 combinations (2x2) actually fire.
func TestExecutorRun_Clusterbomb_TriesEveryCombination(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-User") == "admin" && r.Header.Get("X-Pass") == "pass2" {
			_, _ = w.Write([]byte("SUCCESS"))
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "clusterbomb.yaml", `
id: clusterbomb-style
info:
  name: Clusterbomb Style
  severity: high
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-User: {{username}}
        X-Pass: {{password}}
    attack: clusterbomb
    payloads:
      username:
        - admin
        - root
      password:
        - pass1
        - pass2
    matchers:
      - type: word
        words:
          - "SUCCESS"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "the cross combination (admin/pass2), unreachable by pitchfork, must be reached by clusterbomb")
	assert.Equal(t, 4, requests, "clusterbomb must try every combination (2x2 = 4)")
}

// TestExecutorRun_BatteringRam_BroadcastsSingleListToAllKeys proves
// battering ram's distinguishing behavior: one shared value list broadcast
// into every key simultaneously, so two different keys always carry the
// SAME value on a given pass — never an independently-chosen pair the way
// pitchfork/clusterbomb allow.
func TestExecutorRun_BatteringRam_BroadcastsSingleListToAllKeys(t *testing.T) {
	var mismatched bool
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("X-A") != r.Header.Get("X-B") {
			mismatched = true
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "batteringram.yaml", `
id: batteringram-style
info:
  name: Battering Ram Style
  severity: info
http:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        X-A: {{a}}
        X-B: {{b}}
    attack: batteringram
    payloads:
      a:
        - "1"
        - "2"
      b:
        - "1"
        - "2"
    matchers:
      - type: status
        status:
          - 200
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	_, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	assert.Equal(t, 2, requests, "battering ram must fire once per value in the shared list (2), not a cartesian product")
	assert.False(t, mismatched, "every key must carry the same broadcast value on a given pass")
}

// TestExecutorRun_FileBasedPayload_WordPressVersionPattern is modeled
// end-to-end on real upstream's http/technologies/wordpress/plugins/
// wp-crontrol.yaml: a single-value file-based payload (last_version) +
// same-request extractor→matcher binding + concat()/compare_versions() —
// proves the full real pattern actually works, not just that the file
// reads.
func TestExecutorRun_FileBasedPayload_WordPressVersionPattern(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-content/plugins/wp-crontrol/readme.txt" {
			_, _ = w.Write([]byte("Stable tag: 1.0.0\n"))
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writePayloadFile(t, dir, "helpers/wordpress/plugins/wp-crontrol.txt", "1.16.2\n")
	writeTemplate(t, dir, "wp-crontrol.yaml", `
id: wordpress-wp-crontrol-style
info:
  name: WP Crontrol Detection Style
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-content/plugins/wp-crontrol/readme.txt"
    payloads:
      last_version: helpers/wordpress/plugins/wp-crontrol.txt
    extractors:
      - type: regex
        part: body
        internal: true
        name: internal_detected_version
        group: 1
        regex:
          - '(?i)Stable.tag:\s?([\w.]+)'
    matchers:
      - type: dsl
        name: outdated_version
        dsl:
          - compare_versions(internal_detected_version, concat("< ", last_version))
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "the live 1.0.0 is older than the file-loaded last_version (1.16.2), compare_versions/concat/file-based payload must all connect correctly")
}

// TestExecutorRun_NullPayloadEntry_RendersAsEmptyString is modeled on real
// upstream's softether-vpn-default-login.yaml: a `password: [null]` entry
// must render as a genuinely empty string in the fired request — not the
// literal text "null" or "<nil>" — proving schema.go's decodeStringSequence
// fix works end-to-end, not just that the template loads.
func TestExecutorRun_NullPayloadEntry_RendersAsEmptyString(t *testing.T) {
	var gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "null-payload.yaml", `
id: null-payload-style
info:
  name: Null Payload Style
  severity: info
http:
  - raw:
      - |
        POST / HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user=admin&pass={{password}}
    payloads:
      password:
        - null
    matchers:
      - type: status
        status:
          - 200
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	_, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	assert.Equal(t, "user=admin&pass=\n", gotBody, "a null payload entry must render as an empty string, not the literal text \"null\"")
}

// TestExecutorRun_SameRequestExtractorBinding is modeled on real upstream's
// apache-httpd-eol.yaml: a single request whose matcher references its own
// extractor's Name (compare_versions(version, ...)) — end-to-end proof
// that extraction now runs before matcher evaluation and its result is
// visible as a DSL identifier, not just that the template loads (see
// TestNucleiLoadDir_SameRequestExtractorBindingLoads).
func TestExecutorRun_SameRequestExtractorBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.2.34 (Unix)")
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "eol.yaml", `
id: apache-httpd-eol-style
info:
  name: Apache HTTP Server EOL
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - compare_versions(version, '<=2.2.34')
    extractors:
      - type: regex
        part: header
        name: version
        group: 1
        regex:
          - 'Server: Apache/([0-9.]+)'
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "Apache/2.2.34 is <= 2.2.34, so the EOL matcher should fire")

	// A newer, non-EOL version must NOT match.
	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.58 (Unix)")
	}))
	t.Cleanup(server2.Close)
	findings, err = nuclei.New(newExecutorClient()).Run(context.Background(), server2.URL, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings, "Apache/2.4.58 is not <= 2.2.34")
}

// TestExecutorRun_CrossRequestExtractorBinding is modeled on real
// upstream's google-iap-detect.yaml: request 1 extracts "email", request 2
// (reached via flow: http(1) && http(2)) references it in a dsl:
// extractor — end-to-end proof that chainVars now flow into DSL
// evaluation, not just {{}} substitution.
func TestExecutorRun_CrossRequestExtractorBinding(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Goog-Iap-Generated-Response", "true")
		_, _ = w.Write([]byte("owner: security@example.com;"))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "iap.yaml", `
id: google-iap-detect-style
info:
  name: Google IAP Detect
  severity: info
flow: http(1) && http(2)
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    extractors:
      - type: regex
        part: body
        name: email
        group: 1
        regex:
          - "owner:\\s*([^;]+)"
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        part: header
        words:
          - "X-Goog-Iap-Generated-Response"
    extractors:
      - type: dsl
        name: contact_email
        dsl:
          - "email"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "request 2's word matcher should fire; the DSL extractor referencing request 1's \"email\" must not error the template out")
}

// cve2012_3153Template is modeled directly on real upstream's
// CVE-2012-3153.yaml: a plain path:-based request (no raw: at all) with 2
// Path entries whose matchers-condition: and matchers correlate body_1
// (first path's response) with body_2 (second path's response) — the
// genuine "path:-multi-request correlation" gap. See
// TestExecutorRun_PathCorrelation_BothProbesFireAndCorrelate and its
// negative counterpart below.
const cve2012_3153Template = `
id: path-correlation-style
info:
  name: Path Correlation Style
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/showenv"
      - "{{BaseURL}}/rwservlet?file:///"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_1, "Reports Servlet")'
      - type: dsl
        dsl:
          - '!contains(body_2, "<html")'
`

// TestExecutorRun_PathCorrelation_BothProbesFireAndCorrelate is the positive
// case: both Path entries must actually fire (tracked via hits — proving
// this project no longer treats Path as an independent try-until-match
// list once a request is flagged pathCorrelated), and the finding's
// Target/evidence must reflect the LAST entry's response, same convention
// tryRaw already uses for req.Raw.
func TestExecutorRun_PathCorrelation_BothProbesFireAndCorrelate(t *testing.T) {
	var hits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/showenv" {
			_, _ = w.Write([]byte("Oracle Reports Servlet Info"))
			return
		}
		_, _ = w.Write([]byte("plain text, no html here"))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "path-correlation.yaml", cve2012_3153Template)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "both correlated probes are true, so the and-combined matcher must fire")
	assert.ElementsMatch(t, []string{"/showenv", "/rwservlet"}, hits, "correlation mode must fire every Path entry, not stop after the first one succeeds")
	assert.Contains(t, findings[0].Target, "/rwservlet", "Target should reflect the last-fired entry, same convention tryRaw uses")
}

// TestExecutorRun_PathCorrelation_NoMatchWhenOneProbeFails is the negative
// counterpart: the second probe's response DOES contain "<html", so the
// and-combined matcher must not fire — proving this isn't a matcher that
// trivially always passes once both probes are fired.
func TestExecutorRun_PathCorrelation_NoMatchWhenOneProbeFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/showenv" {
			_, _ = w.Write([]byte("Oracle Reports Servlet Info"))
			return
		}
		_, _ = w.Write([]byte("<html>a real login page</html>"))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "path-correlation.yaml", cve2012_3153Template)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings, "the second probe's <html> body must fail !contains(body_2, \"<html\")")
}

// TestExecutorRun_IndexedWordMatcherPart_RawEntries is modeled on real
// upstream's CVE-2014-4592.yaml: a raw:-request block with 2 Raw entries
// whose WORD matchers use `part: body_2`/`part: header_2` — proves
// matcher.Part actually resolves an indexed part: name out of
// r.ExtraVars, not just a dsl: identifier referencing the same value (see
// TestExecutorRun_RawMultiEntryCorrelation for the dsl: form, already
// working before this change). This is the largest real bucket behind this
// change: 239 of 246 real "unsupported part" rejections were exactly this
// shape.
func TestExecutorRun_IndexedWordMatcherPart_RawEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/readme.txt":
			_, _ = w.Write([]byte("WP Planet Plugin Readme"))
		case "/xss.php":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<script>alert(document.domain)</script>"))
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "indexed-part.yaml", `
id: indexed-part-style
info:
  name: Indexed Part Style
  severity: medium
http:
  - raw:
      - |
        GET /readme.txt HTTP/1.1
        Host: {{Hostname}}
      - |
        GET /xss.php HTTP/1.1
        Host: {{Hostname}}
    matchers-condition: and
    matchers:
      - type: word
        part: body_1
        words:
          - "Plugin Readme"
      - type: word
        part: body_2
        words:
          - "<script>alert(document.domain)</script>"
      - type: word
        part: header_2
        words:
          - "text/html"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "part: body_1/body_2/header_2 must each resolve to their own probe's own result")
}

// TestExecutorRun_SinglePathIndexOneAlias_Matches is modeled on real
// upstream's CVE-2023-1362.yaml: a genuinely single-path request whose
// matcher references the "_1"-suffixed status_code_1/body_1 form. Proves
// tryPath's alias binding actually resolves at runtime, not just that the
// template loads (see TestNucleiLoadDir_SinglePathIndexOneAliasLoads).
func TestExecutorRun_SinglePathIndexOneAlias_Matches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("BUM</b>Sys</a>"))
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "single-path-alias.yaml", `
id: single-path-index-one-style
info:
  name: Single Path Index One Style
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && contains(body_1, 'BUM</b>Sys</a>')"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "status_code_1/body_1 must alias the bare status_code/body values on a genuinely single-path request")
}

// TestExecutorRun_IndependentMultiPath_EachPathReportsSeparately is a
// regression guard for the new pathCorrelated branch in runPathRequest:
// a plain multi-path template with NO indexed identifiers anywhere (the
// overwhelming majority of the ~9,000+ real multi-path templates) must keep
// today's independent try-each-path behavior — every matching path reports
// its OWN finding — not silently switch to firing all paths and reporting
// once. Deliberately omits stop-at-first-match (already covered by
// TestExecutorRun_MultiPathStopsAtFirstMatch) so both paths get a chance to
// each produce their own finding.
func TestExecutorRun_IndependentMultiPath_EachPathReportsSeparately(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin panel"))
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "independent-multi-path-style",
		Info: nuclei.Info{Name: "Independent Multi Path Style", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method: http.MethodGet,
			Path:   []string{"{{BaseURL}}/panel", "{{BaseURL}}/admin"},
			Matchers: []matcher.Matcher{
				{Type: "word", Words: []string{"admin panel"}},
			},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 2, "each of the two independently-matching paths must produce its own finding, not one correlated finding")
}

// --- LT-13 (docs/follow-up.md): malformed request URLs from path:-based
// requests, and the coverage loss a hard error caused ---

// TestExecutorRun_PathHostnamePlaceholder_Renders is the regression guard
// for LT-13 bug 1: tryPath built its vars.Context with no Hostname field at
// all, so any path:-based template referencing {{Host}}/{{Hostname}} (real
// example: CVE-2018-8024.yaml's "{{Hostname}}:4040/jobs/...") rendered the
// placeholder as an empty string rather than erroring — producing a
// malformed URL (e.g. ":4040/jobs/...") that failed downstream with
// "missing protocol scheme", exactly the live failure the user's
// aceautowreckers.com scan reported. tryRaw already resolved this
// correctly; tryPath/tryPathCorrelatedIteration did not.
func TestExecutorRun_PathHostnamePlaceholder_Renders(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "path-hostname-placeholder-style",
		Info: nuclei.Info{Name: "Path Hostname Placeholder Style", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method:   http.MethodGet,
			Path:     []string{"{{BaseURL}}/?h={{Hostname}}"},
			Matchers: []matcher.Matcher{{Type: "word", Words: []string{"OK"}}},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	u, parseErr := url.Parse(server.URL)
	require.NoError(t, parseErr)
	assert.Equal(t, "h="+u.Host, gotQuery, "{{Hostname}} must render as the actual target host in a path:-based request, not empty")
}

// TestExecutorRun_PathCorrelatedHostnamePlaceholder_Renders is
// TestExecutorRun_PathHostnamePlaceholder_Renders' counterpart for
// tryPathCorrelatedIteration (the pathCorrelated branch, used once a
// matcher/extractor references an indexed body_N/status_code_N/... — see
// loader.go's usesPathCorrelation) — the same missing-Hostname bug existed
// in this second, structurally-separate call site.
func TestExecutorRun_PathCorrelatedHostnamePlaceholder_Renders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/probe1":
			if r.URL.Query().Get("h") != "" {
				_, _ = w.Write([]byte("host-ok"))
			}
		case "/probe2":
			_, _ = w.Write([]byte("second"))
		}
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "path-correlation-hostname.yaml", `
id: path-correlation-hostname-style
info:
  name: Path Correlation Hostname Style
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe1?h={{Hostname}}"
      - "{{BaseURL}}/probe2"
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'contains(body_1, "host-ok")'
      - type: dsl
        dsl:
          - 'contains(body_2, "second")'
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "body_1 must contain \"host-ok\", which only happens if {{Hostname}} rendered non-empty in the first correlated probe")
}

// TestExecutorRun_PathLeadingWhitespaceTrimmed is the regression guard for
// LT-13 bug 2: a template's baked-in leading space before {{BaseURL}} (real
// example: aem-querybuilder-json-servlet.yaml) used to reach
// http.NewRequestWithContext unsanitized, producing "first path segment in
// URL cannot contain colon" once the scheme was pushed past the leading
// space. tryPath now trims the rendered URL before building the request.
func TestExecutorRun_PathLeadingWhitespaceTrimmed(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "leading-whitespace-style",
		Info: nuclei.Info{Name: "Leading Whitespace Style", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method:   http.MethodGet,
			Path:     []string{" {{BaseURL}}/panel"},
			Matchers: []matcher.Matcher{{Type: "word", Words: []string{"OK"}}},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err)
	require.Len(t, findings, 1, "a leading space baked into the template's path: entry must not stop the request from firing")
	assert.Equal(t, "/panel", gotPath)
}

// TestExecutorRun_PathMalformedURL_SiblingPathStillTried is the regression
// guard for LT-13 bug 3: a malformed rendered URL (real example:
// laravel-debug-error.yaml's stray unescaped "%^&") used to return a hard
// error from tryPath, which aborted runPathRequest's entire remaining
// payloadLoop — silently dropping every other still-untried Path entry in
// the same request block, not just the bad one. The first Path entry here
// has an invalid percent-escape; the second is well-formed and must still
// fire and be allowed to match.
func TestExecutorRun_PathMalformedURL_SiblingPathStillTried(t *testing.T) {
	var hits []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.URL.Path)
		if r.URL.Path == "/good" {
			_, _ = w.Write([]byte("found"))
		}
	}))
	t.Cleanup(server.Close)

	tmpl := &nuclei.Template{
		ID:   "malformed-url-style",
		Info: nuclei.Info{Name: "Malformed URL Style", Severity: "info"},
		HTTP: []nuclei.HTTPRequest{{
			Method:   http.MethodGet,
			Path:     []string{"{{BaseURL}}/bad%zz", "{{BaseURL}}/good"},
			Matchers: []matcher.Matcher{{Type: "word", Words: []string{"found"}}},
		}},
	}

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, tmpl)
	require.NoError(t, err, "a malformed rendered URL must be skipped, not returned as a hard scan error")
	require.Len(t, findings, 1, "the second, well-formed Path entry must still fire and match")
	assert.Contains(t, hits, "/good", "the malformed first entry must not abort the remaining Path entries in this request block")
}

// TestExecutorRun_BareHeaderIdentifier_MatchesRealHeader is the runtime
// counterpart to TestNucleiLoadDir_BareHeaderIdentifierLoads (LT-15,
// docs/follow-up.md): a dsl: matcher referencing a bare header name
// (`server`) must actually resolve against the real fired response's
// Server header, not just parse/validate at load time.
func TestExecutorRun_BareHeaderIdentifier_MatchesRealHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Webp-Server-Go/1.0")
	}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "webp-server-lfi-style.yaml", `
id: webp-server-lfi-style
info:
  name: WebP Server LFI Style
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - 'contains(server, "Webp-Server-Go")'
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "the bare `server` identifier must resolve to the real Server header value")
}

// TestExecutorRun_BareHeaderIdentifier_AbsentHeaderNoMatch is the negative
// counterpart: a target that never sends a Server header at all must not
// satisfy the same check.
func TestExecutorRun_BareHeaderIdentifier_AbsentHeaderNoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "webp-server-lfi-style.yaml", `
id: webp-server-lfi-style
info:
  name: WebP Server LFI Style
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: dsl
        dsl:
          - 'contains(server, "Webp-Server-Go")'
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings, "no Server header at all must not satisfy contains(server, ...)")
}

// TestExecutorRun_PartRequestExtractor_CapturesRawRequest is the runtime
// counterpart to TestNucleiLoadDir_PartRequestExtractorLoads (LT-15,
// docs/follow-up.md): an extractor using `part: request` must actually
// capture the real outgoing request text — proven here by feeding the
// extracted value straight into a same-request dsl: matcher (the same
// extractor->matcher binding TestExecutorRun_SameRequestExtractorBinding
// already exercises for `part: header`).
func TestExecutorRun_PartRequestExtractor_CapturesRawRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "part-request-style.yaml", `
id: part-request-style
info:
  name: Part Request Style
  severity: info
http:
  - method: POST
    path:
      - "{{BaseURL}}/upload"
    body: "filename=shell.php"
    matchers:
      - type: dsl
        dsl:
          - contains(sent_filename, "shell.php")
    extractors:
      - type: regex
        part: request
        internal: true
        name: sent_filename
        regex:
          - 'filename=\S+'
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), server.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "part: request must have captured the real outgoing request text (including the body's filename=shell.php), not an empty/fallback value")
}

// --- interactsh_ / OOB correlation ---
//
// Every test below uses newFakeOOBServer (detector_ssrf_test.go, same
// package) — a real RSA-OAEP+AES-256-CTR Interactsh-protocol server
// stand-in served locally via httptest.NewServer (127.0.0.1, an
// OS-assigned loopback port). None of these tests ever construct a
// nuclei.Executor with a real oast.pro/oast.live (or any other) public
// server URL — WithOOBServers is only ever pointed at oobSrv.URL below.

// interactshRawTemplate mirrors real CVE-2019-6799.yaml's shape (see
// TestNucleiLoadDir_InteractshRawTemplateLoads): one raw: request embedding
// {{interactsh-url}}, matched with a `part: interactsh_protocol` word
// matcher AND a plain body word matcher — both must hold for a Finding.
const interactshRawTemplate = `
id: interactsh-raw-style
info:
  name: Interactsh Raw Style
  severity: medium
http:
  - raw:
      - |
        GET /probe?cb={{interactsh-url}} HTTP/1.1
        Host: {{Hostname}}
    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - http
      - type: word
        words:
          - OK
`

// TestExecutorRun_InteractshCorrelation_RealEncryptedRoundTrip_Matches
// proves the full path end to end: nuclei.Executor renders
// {{interactsh-url}} into a real probe URL, fires it against a real target
// server, then correlates a real RSA-OAEP+AES-256-CTR-encrypted interaction
// (from the fake OOB server) back to that exact probe via its nonce — the
// same crypto/correlation ssrf's own
// TestSSRFOOBCallback_RealEncryptedRoundTrip_Hit already proves, now
// through nuclei.Executor's prepareOOB/awaitOOB instead.
func TestExecutorRun_InteractshCorrelation_RealEncryptedRoundTrip_Matches(t *testing.T) {
	oobSrv, fake := newFakeOOBServer(t)
	defer oobSrv.Close()

	probedURLCh := make(chan string, 4)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probedURLCh <- r.URL.String()
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(target.Close)

	// The probe's own query string is "?cb=<correlationID><nonce>.<bareHost>"
	// (oob.Client.NewPayloadHost's shape) — extracting the nonce this way,
	// rather than predicting it, mirrors detector_ssrf_test.go's own
	// TestSSRFOOBCallback_RealEncryptedRoundTrip_Hit technique exactly.
	go func() {
		for u := range probedURLCh {
			const marker = "cb="
			idx := strings.Index(u, marker)
			if idx < 0 {
				continue
			}
			after := u[idx+len(marker):]
			dot := strings.Index(after, ".")
			if dot < 0 || dot <= oob.CorrelationIDLen {
				continue
			}
			nonce := after[oob.CorrelationIDLen:dot]
			<-fake.mu
			fake.nonce = nonce
			fake.mu <- struct{}{}
			return
		}
	}()

	dir := t.TempDir()
	writeTemplate(t, dir, "interactsh-raw-style.yaml", interactshRawTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	exec := nuclei.New(newExecutorClient()).WithOOBServers([]string{oobSrv.URL})
	t.Cleanup(exec.Close)
	findings, err := exec.Run(context.Background(), target.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "a real correlated interactsh callback plus the OK body match should both hold")
}

// TestExecutorRun_InteractshCorrelation_NoCallback_NoMatch is the negative
// counterpart: OOB is configured (registration against oobSrv succeeds,
// same fake server) but the probe's nonce is never told to the fake
// server, so its /poll responses never correlate to anything — matching a
// genuinely non-vulnerable real target that never makes the outbound
// callback. interactsh_protocol must resolve to "" (never fall through to
// the response body — see matcher.ValidPart's doc comment), so the
// matchers-condition: and template must not match at all.
func TestExecutorRun_InteractshCorrelation_NoCallback_NoMatch(t *testing.T) {
	oobSrv, _ := newFakeOOBServer(t)
	defer oobSrv.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(target.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "interactsh-raw-style.yaml", interactshRawTemplate)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	exec := nuclei.New(newExecutorClient()).WithOOBServers([]string{oobSrv.URL})
	t.Cleanup(exec.Close)
	findings, err := exec.Run(context.Background(), target.URL, templates[0])
	require.NoError(t, err)
	assert.Empty(t, findings, "no correlated callback means interactsh_protocol stays empty, so the AND'd matcher must not fire")
}

// TestExecutorRun_InteractshURL_RendersAndFiresWithoutOOBConfigured proves
// a request embedding {{interactsh-url}} still renders and fires when no
// OOB server is configured at all (WithOOBServers never called — this
// project's default Executor) — the placeholder resolves to
// oobDisabledHost rather than making Render fail with "undefined
// variable", so any of the template's OTHER, non-OOB matchers still get a
// fair chance to run. Uses a body-only matcher (no interactsh_ part) so a
// match here can only be explained by the request actually having fired.
func TestExecutorRun_InteractshURL_RendersAndFiresWithoutOOBConfigured(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK " + r.URL.RawQuery))
	}))
	t.Cleanup(target.Close)

	dir := t.TempDir()
	writeTemplate(t, dir, "interactsh-no-oob.yaml", `
id: interactsh-no-oob
info:
  name: Interactsh No OOB
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/?cb={{interactsh-url}}"
    matchers:
      - type: word
        words:
          - "OK"
`)
	templates, errs := nuclei.LoadDir(dir)
	require.Empty(t, errs)
	require.Len(t, templates, 1)

	findings, err := nuclei.New(newExecutorClient()).Run(context.Background(), target.URL, templates[0])
	require.NoError(t, err)
	require.Len(t, findings, 1, "the request must still render (via oobDisabledHost) and fire even with no OOB server configured")
}
