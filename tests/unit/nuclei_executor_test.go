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
