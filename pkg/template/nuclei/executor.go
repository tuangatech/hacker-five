package nuclei

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/vars"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Executor runs one parsed Template against one target.
type Executor struct {
	client       *httpclient.Client
	extraHeaders map[string]string
}

// New constructs an Executor.
func New(client *httpclient.Client) *Executor {
	return &Executor{client: client}
}

// WithHeaders sets static HTTP headers applied to every request this
// Executor fires via a template's path: entries (tryPath) — raw: requests
// are unaffected, since their headers are already literal text an author
// can embed directly in the raw request text, no CLI mechanism needed
// there. The motivating use case is a session cookie a target's login flow
// issued outside this scan (e.g. DVWA — see
// docs/11-implementation-plan-ph2.md Step 5): neither template format's
// {{}} variable substitution has a CLI-supplied placeholder for one, unlike
// native's idor-tagged templates, which get AuthToken/OtherAuthToken.
// Applied before a template's own Headers: map, so a literal name conflict
// still lets the template win — these are a baseline, not an override. A
// nil/empty headers map is a no-op, leaving any prior WithHeaders call's
// value in place. Returns the Executor so it can be chained at the
// construction call site (mirrors idor.Detector's functional-options
// pattern in spirit, but as a post-construction setter since there's only
// one thing to configure here).
func (e *Executor) WithHeaders(headers map[string]string) *Executor {
	if len(headers) > 0 {
		e.extraHeaders = headers
	}
	return e
}

// Run fires every request in tmpl.HTTP, in order, against target — or, for a
// flow: template (tmpl.flowAST != nil), fires them under the parsed flow
// script's boolean control instead (see runFlow). Each request's Path
// entries are tried in turn (stopping early if StopAtFirstMatch is set); a
// match against a path emits one Finding and runs that request's
// Extractors, binding their results as chain-scoped variables available to
// every later request in the template — matching doc 02's variable-scope
// rules. Path/Headers/Body are all rendered via vars.Render, so
// "{{BaseURL}}" and any bound chain variable resolve the same way the
// native format (Step 3) will use them.
func (e *Executor) Run(ctx context.Context, target string, tmpl *Template) ([]detectors.Finding, error) {
	// Normalize the target's trailing slash once, up front. Templates
	// conventionally write "{{BaseURL}}/path" — upstream Nuclei's own
	// convention, where {{BaseURL}} carries no trailing slash — so a target
	// submitted with one (e.g. a Web UI form value "https://example.com/")
	// otherwise renders as "https://example.com//path" in both the fired
	// request and the resulting Finding.Target. Covers the path: renderer
	// (BaseURL in renderCtx) and the raw: builder (buildRawRequest's
	// target+path concat) alike, and runFlow below inherits the fix since
	// it's only ever reached from here. Mirrors the same trailing-slash fix
	// made for the authbypass detector (doc15 Step 2 addendum, 2026-09-04).
	target = strings.TrimRight(target, "/")

	if tmpl.flowAST != nil {
		return e.runFlow(ctx, target, tmpl)
	}

	var findings []detectors.Finding
	chainVars := map[string]string{}

	for reqIdx, req := range tmpl.HTTP {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		fs, _, err := e.runRequest(ctx, target, tmpl, reqIdx, req, chainVars)
		if err != nil {
			return findings, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

// runRequest fires one tmpl.HTTP[reqIdx] entry — via tryRaw for a raw:-based
// request, or runPathRequest for a path:-based one (which may also carry
// payloads:, see runPathRequest) — and reports whether it ended up
// "chainable": genuinely matched, or matcher-less (nothing to match, so
// trivially true — see runPathRequest/tryRawIteration's chainable doc
// comments). Shared by Run's plain independent loop and runFlow's http(N)
// calls so both go through identical request-firing logic.
func (e *Executor) runRequest(ctx context.Context, target string, tmpl *Template, reqIdx int, req HTTPRequest, chainVars map[string]string) ([]detectors.Finding, bool, error) {
	if len(req.Raw) > 0 {
		return e.tryRaw(ctx, target, tmpl, reqIdx, req, chainVars)
	}
	return e.runPathRequest(ctx, target, tmpl, reqIdx, req, chainVars)
}

// runFlow executes tmpl.flowAST, whose http(N) calls invoke runRequest for
// tmpl.HTTP[N-1] — short-circuiting exactly like the parsed &&/|| tree
// (flow.go), so a request gated behind an earlier false && or true || never
// fires, same as real Nuclei. The template's reportable output is the union
// of every reached request's own Findings (matching real Nuclei: each
// http() call's matchers report independently, there's no single
// template-level pass/fail) — the flow expression's own top-level bool is
// discarded once evaluation completes, only used internally to drive
// short-circuiting.
func (e *Executor) runFlow(ctx context.Context, target string, tmpl *Template) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	chainVars := map[string]string{}

	call := func(n int) (bool, error) {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		reqIdx := n - 1
		fs, chainable, err := e.runRequest(ctx, target, tmpl, reqIdx, tmpl.HTTP[reqIdx], chainVars)
		if err != nil {
			return false, err
		}
		findings = append(findings, fs...)
		return chainable, nil
	}

	if _, err := tmpl.flowAST.eval(call); err != nil {
		return findings, err
	}
	return findings, nil
}

// runPathRequest tries every payload iteration (or a single unbound pass —
// see HTTPRequest.resolvePayloads) around every req.Path candidate, same
// combined payloads:+path: loop Run always ran directly before flow:
// support existed — see docs/10-implementation-plan-ph1b.md's raw:/
// payloads: note for why payloads: legitimately shows up on a plain path:
// request (real example: upstream's phpmyadmin-panel.yaml). Returns every
// Finding produced plus whether ANY iteration was chainable (see tryPath's
// doc comment) — needed by runFlow's http(N) truthiness; StopAtFirstMatch
// still only stops early on a genuine match, unchanged from before this
// refactor.
func (e *Executor) runPathRequest(ctx context.Context, target string, tmpl *Template, reqIdx int, req HTTPRequest, chainVars map[string]string) ([]detectors.Finding, bool, error) {
	// resolvePayloads already validated this at load time; err is nil here
	// in practice, checked defensively only.
	iterations, err := req.resolvePayloads(tmpl.sourceDir)
	if err != nil {
		return nil, false, nil
	}
	multi := len(iterations) > 0
	if !multi {
		iterations = []map[string]string{nil}
	}

	// pathCorrelated (see schema.go's doc comment) opts out of the
	// independent-per-path loop below entirely — a request flagged this way
	// needs every Path entry fired unconditionally and its matchers
	// evaluated once against the combined body_N/header_N/... result, same
	// as tryRaw already does for Raw. Computed once at load time
	// (loader.go's usesPathCorrelation), so this is a cheap field check, not
	// a re-scan of the matchers on every scan.
	if req.pathCorrelated {
		return e.runPathRequestCorrelated(ctx, target, tmpl, reqIdx, req, chainVars, iterations, multi)
	}

	var findings []detectors.Finding
	chainable := false

payloadLoop:
	for pIdx, extraVars := range iterations {
		for _, path := range req.Path {
			if ctx.Err() != nil {
				return findings, chainable, ctx.Err()
			}

			finding, matched, ch, err := e.tryPath(ctx, target, tmpl, reqIdx, req, path, chainVars, extraVars, pIdx, multi)
			if err != nil {
				return findings, chainable, err
			}
			if ch {
				chainable = true
			}
			if matched {
				findings = append(findings, finding)
				if req.StopAtFirstMatch {
					break payloadLoop
				}
			}
		}
	}
	return findings, chainable, nil
}

// runPathRequestCorrelated is runPathRequest's payload-iteration loop for a
// pathCorrelated request — structurally identical to tryRaw's own loop (see
// its doc comment), just delegating to tryPathCorrelatedIteration instead of
// tryRawIteration per pass. StopAtFirstMatch stops the payload-value loop
// early, same meaning it already has for both the independent-path loop
// above and tryRaw — it does NOT mean "stop after the first Path entry
// matches" here, since every Path entry always fires within one iteration
// (that's the entire point of correlation mode).
func (e *Executor) runPathRequestCorrelated(ctx context.Context, target string, tmpl *Template, reqIdx int, req HTTPRequest, chainVars map[string]string, iterations []map[string]string, multi bool) ([]detectors.Finding, bool, error) {
	var findings []detectors.Finding
	chainable := false
	for pIdx, extraVars := range iterations {
		if ctx.Err() != nil {
			return findings, chainable, ctx.Err()
		}

		finding, matched, ch, err := e.tryPathCorrelatedIteration(ctx, target, tmpl, reqIdx, req, chainVars, extraVars, pIdx, multi)
		if err != nil {
			return findings, chainable, err
		}
		if ch {
			chainable = true
		}
		if matched {
			findings = append(findings, finding)
			if req.StopAtFirstMatch {
				break
			}
		}
	}
	return findings, chainable, nil
}

// tryPathCorrelatedIteration fires every entry in req.Path once (rendering
// each through the same method/path/headers/body pipeline tryPath uses for
// a single entry), binds every entry's result as
// body_N/header_N/status_code_N/content_type_N/duration_N (plus a bare
// "duration" aliased to the last entry — mirrors tryRawIteration exactly,
// just building each request from Method/Path/Headers/Body instead of
// parsing a Raw text block), and evaluates req.Matchers/req.Extractors
// against the LAST entry's response. Only ever called for a request with
// pathCorrelated set (len(req.Raw) == 0 && len(req.Path) > 1 — see
// schema.go's doc comment), so req.Path is never empty here in practice.
// Same non-fatal treatment of render/network errors as tryPath/
// tryRawIteration: any failure on any entry aborts just this one iteration.
func (e *Executor) tryPathCorrelatedIteration(ctx context.Context, target string, tmpl *Template, reqIdx int, req HTTPRequest, chainVars, extraVars map[string]string, pIdx int, idSuffix bool) (finding detectors.Finding, matched bool, chainable bool, err error) {
	renderVars := chainVars
	if len(extraVars) > 0 {
		renderVars = make(map[string]string, len(chainVars)+len(extraVars))
		for k, v := range chainVars {
			renderVars[k] = v
		}
		for k, v := range extraVars {
			renderVars[k] = v
		}
	}
	renderCtx := vars.Context{BaseURL: target, Vars: renderVars}

	extraStrVars := make(map[string]string, len(req.Path)*3)
	extraInts := make(map[string]int, len(req.Path)*2+1)
	var lastReq *http.Request
	var lastReqBody string
	var lastFullURL string
	var lastStatus int
	var lastHeaders http.Header
	var lastBody []byte

	for i, path := range req.Path {
		if ctx.Err() != nil {
			return detectors.Finding{}, false, false, ctx.Err()
		}
		n := i + 1

		fullURL, err := vars.Render(path, renderCtx)
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}
		body, err := vars.Render(req.Body, renderCtx)
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}

		httpReq, err := http.NewRequestWithContext(ctx, methodOrDefault(req.Method), fullURL, bodyReader(body))
		if err != nil {
			return detectors.Finding{}, false, false, fmt.Errorf("nuclei: building request for template %s: %w", tmpl.ID, err)
		}
		for k, v := range e.extraHeaders {
			httpReq.Header.Set(k, v)
		}
		for k, v := range req.Headers {
			if rv, err := vars.Render(v, renderCtx); err == nil {
				httpReq.Header.Set(k, rv)
			}
		}

		start := time.Now()
		resp, err := e.client.Do(httpReq)
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}
		respBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}
		// See tryPath's durationInts comment: measured around e.client.Do
		// only, same narrow, accepted over-counting risk on a transient
		// failure that triggers this client's own retry/backoff.
		entryDuration := int(time.Since(start).Seconds())

		extraStrVars[fmt.Sprintf("body_%d", n)] = string(respBody)
		extraStrVars[fmt.Sprintf("header_%d", n)] = matcher.Part("header", matcher.Response{Headers: resp.Header})
		extraStrVars[fmt.Sprintf("content_type_%d", n)] = resp.Header.Get("Content-Type")
		extraInts[fmt.Sprintf("status_code_%d", n)] = resp.StatusCode
		extraInts[fmt.Sprintf("duration_%d", n)] = entryDuration
		extraInts["duration"] = entryDuration

		lastReq, lastReqBody, lastFullURL = httpReq, body, fullURL
		lastStatus, lastHeaders, lastBody = resp.StatusCode, resp.Header, respBody
	}

	if lastReq == nil {
		return detectors.Finding{}, false, false, nil // req.Path empty — pathCorrelated requires len > 1, defensive only
	}

	// chainVars/extraVars merged in alongside the body_N/header_N entries —
	// same mechanism tryRawIteration uses, see its doc comment.
	for k, v := range chainVars {
		extraStrVars[k] = v
	}
	for k, v := range extraVars {
		extraStrVars[k] = v
	}

	baseResp := matcher.Response{StatusCode: lastStatus, Headers: lastHeaders, Body: lastBody, ExtraVars: extraStrVars, ExtraInts: extraInts}
	extracted := extractor.Extract(req.Extractors, baseResp)

	mResp := matcher.Response{StatusCode: lastStatus, Headers: lastHeaders, Body: lastBody, ExtraVars: mergeVars(extraStrVars, extracted), ExtraInts: extraInts}
	evaluated := len(req.Matchers) > 0 && matcher.EvaluateAll(req.Matchers, req.MatchersCondition, mResp)
	chainable = evaluated || len(req.Matchers) == 0
	matched = evaluated && hasReportableMatcher(req.Matchers)
	if !chainable {
		return detectors.Finding{}, false, false, nil
	}

	for k, v := range extracted {
		chainVars[k] = v
	}
	if !matched {
		return detectors.Finding{}, false, true, nil
	}

	matchedChecks := matcher.MatchingNames(req.Matchers, mResp)
	description := tmpl.Info.Name
	if len(matchedChecks) > 0 {
		description = fmt.Sprintf("%s (%s)", tmpl.Info.Name, strings.Join(matchedChecks, ", "))
	}

	id := fmt.Sprintf("nuclei-%s-%d", tmpl.ID, reqIdx)
	if idSuffix {
		id = fmt.Sprintf("nuclei-%s-%d-%d", tmpl.ID, reqIdx, pIdx)
	}

	return detectors.Finding{
		ID:          id,
		Type:        "misconfig",
		Severity:    severityOrDefault(tmpl.Info.Severity),
		Confidence:  "high",
		Target:      lastFullURL,
		Description: description,
		Evidence: map[string]string{
			"template_id":    tmpl.ID,
			"status":         fmt.Sprintf("%d", lastStatus),
			"matched_checks": strings.Join(matchedChecks, ","),
			"request":        detectors.FormatRequest(lastReq.Method, lastFullURL, lastReq.Header, []byte(lastReqBody)),
			"response":       detectors.FormatResponse(lastStatus, lastHeaders, lastBody),
		},
	}, true, true, nil
}

// tryPath renders and fires one request for one Path entry, evaluates its
// matchers, and — when chainable — runs its extractors into chainVars. A
// rendering failure (an unresolved {{chainVar}}, e.g. because an earlier
// request's extractor never fired) or a network error is not scan-fatal:
// it's reported as "no match" for this path, same as a legitimately
// non-matching response.
//
// Returns (finding, matched, chainable, err). matched is a genuine,
// reportable match (len(req.Matchers) > 0, they evaluated true, and at
// least one of them isn't internal: true — see hasReportableMatcher) — the
// only case that produces a real Finding and the only thing
// StopAtFirstMatch reacts to, unchanged from before flow: support (an
// all-internal block, e.g. a flow-control gate, can evaluate true without
// ever producing a Finding). chainable is broader — true whenever
// evaluation succeeded (even an all-internal block) or there were no
// matchers at all: a matcher-less request block is trivially "chainable" (real
// Nuclei semantics — nothing to detect, but extraction/flow-gating still
// proceeds), which is what lets a chaining-only request like upstream's
// umami-panel.yaml's second request (extractor-only, no matchers) actually
// run its extractor — previously impossible, since EvaluateAll(nil, ...)
// is false and nothing ran extractors on a non-match. flow: is what made
// this gap visible (see docs/10-implementation-plan-ph1b.md's flow: note),
// but the fix applies uniformly, not just to flow templates.
//
// extraVars carries one payload iteration's bound value (nil when req has
// no payload key — the pre-existing, unchanged behavior); it's merged into
// the render context only, never written back into chainVars — extractor
// results still always go into the real chainVars, so a payload
// substitution never leaks into later requests' variable scope. pIdx/
// idSuffix give the resulting Finding a unique ID across payload
// iterations (see the Finding.ID line below).
func (e *Executor) tryPath(ctx context.Context, target string, tmpl *Template, reqIdx int, req HTTPRequest, path string, chainVars, extraVars map[string]string, pIdx int, idSuffix bool) (finding detectors.Finding, matched bool, chainable bool, err error) {
	renderVars := chainVars
	if len(extraVars) > 0 {
		renderVars = make(map[string]string, len(chainVars)+len(extraVars))
		for k, v := range chainVars {
			renderVars[k] = v
		}
		for k, v := range extraVars {
			renderVars[k] = v
		}
	}
	renderCtx := vars.Context{BaseURL: target, Vars: renderVars}

	fullURL, err := vars.Render(path, renderCtx)
	if err != nil {
		return detectors.Finding{}, false, false, nil
	}
	body, err := vars.Render(req.Body, renderCtx)
	if err != nil {
		return detectors.Finding{}, false, false, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, methodOrDefault(req.Method), fullURL, bodyReader(body))
	if err != nil {
		return detectors.Finding{}, false, false, fmt.Errorf("nuclei: building request for template %s: %w", tmpl.ID, err)
	}
	for k, v := range e.extraHeaders {
		httpReq.Header.Set(k, v)
	}
	for k, v := range req.Headers {
		if rv, err := vars.Render(v, renderCtx); err == nil {
			httpReq.Header.Set(k, rv)
		}
	}

	start := time.Now()
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return detectors.Finding{}, false, false, nil
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return detectors.Finding{}, false, false, nil
	}
	// Elapsed time for this single request, bound as the bare "duration" DSL
	// identifier (blind time-based SQLi templates, e.g. upstream's
	// CVE-2023-2130.yaml: dsl: 'duration>=6') — see loader.go's
	// indexedDSLContext doc comment for why this needs an explicit IntVars
	// entry rather than a dsl.Context field like status_code/body/header/
	// content_type. Measured around e.client.Do only, so it includes this
	// client's own retry/backoff time on a transient failure before the
	// eventual success (see pkg/scanner/httpclient's WithRetry) — a narrow,
	// accepted source of over-counting on a flaky connection, not something
	// this project's retry policy special-cases for duration templates.
	//
	// duration_1/status_code_1 alias the bare duration/status_code values:
	// real Nuclei's DSL always accepts a "_1" suffix as a synonym for "the
	// (only, or first) response", even on a genuinely single-path request
	// with no multi-probe correlation involved at all (real examples:
	// CVE-2023-1362.yaml's `status_code_1 == 200`,
	// yonyou-nc-baseapp-deserialization.yaml's
	// `contains_all(body_1, "java.io", ...)` — both single-path templates).
	// body_1/header_1/content_type_1 get the matching string-side alias via
	// aliasVars below, merged into dslVars.
	elapsed := int(time.Since(start).Seconds())
	durationInts := map[string]int{"duration": elapsed, "duration_1": elapsed, "status_code_1": resp.StatusCode}

	// Extraction runs unconditionally, before matchers evaluate — not just
	// when chainable — so a matcher in THIS SAME request can reference an
	// extractor's Name from THIS SAME request as a DSL identifier (real
	// example: upstream's apache-httpd-eol.yaml, compare_versions(version,
	// '<=2.2.34') where "version" is extracted by this same request). It's
	// a pure function over the already-fetched response, so computing it
	// unconditionally has no side effect until its results are used below.
	// extraVars (this iteration's bound payloads: values, e.g. WP-crontrol-
	// style last_version) must reach the DSL context here too, not just the
	// request-rendering pass above — a real template can reference its own
	// payload variable directly in a dsl: matcher (upstream's
	// http/technologies/wordpress/plugins/*.yaml pattern:
	// compare_versions(extracted, concat("< ", last_version))), same as it
	// can reference an extractor's Name.
	aliasVars := map[string]string{
		"body_1":         string(respBody),
		"header_1":       matcher.Part("header", matcher.Response{Headers: resp.Header}),
		"content_type_1": resp.Header.Get("Content-Type"),
	}
	dslVars := mergeVars(chainVars, extraVars, aliasVars)
	baseResp := matcher.Response{StatusCode: resp.StatusCode, Headers: resp.Header, Body: respBody, ExtraVars: dslVars, ExtraInts: durationInts}
	extracted := extractor.Extract(req.Extractors, baseResp)

	mResp := matcher.Response{StatusCode: resp.StatusCode, Headers: resp.Header, Body: respBody, ExtraVars: mergeVars(dslVars, extracted), ExtraInts: durationInts}
	evaluated := len(req.Matchers) > 0 && matcher.EvaluateAll(req.Matchers, req.MatchersCondition, mResp)
	chainable = evaluated || len(req.Matchers) == 0
	matched = evaluated && hasReportableMatcher(req.Matchers)
	if !chainable {
		return detectors.Finding{}, false, false, nil
	}

	for k, v := range extracted {
		chainVars[k] = v
	}
	if !matched {
		return detectors.Finding{}, false, true, nil
	}

	// matchedChecks names which specific sub-matcher(s) fired — important
	// for a matchers-condition: or template (e.g. upstream's
	// http-missing-security-headers.yaml ORs together 11 named checks): one
	// match is enough to produce a Finding, but "something matched" isn't
	// actionable on its own — the description/evidence should say which
	// header/check it actually was.
	matchedChecks := matcher.MatchingNames(req.Matchers, mResp)
	description := tmpl.Info.Name
	if len(matchedChecks) > 0 {
		description = fmt.Sprintf("%s (%s)", tmpl.Info.Name, strings.Join(matchedChecks, ", "))
	}

	id := fmt.Sprintf("nuclei-%s-%d", tmpl.ID, reqIdx)
	if idSuffix {
		id = fmt.Sprintf("nuclei-%s-%d-%d", tmpl.ID, reqIdx, pIdx)
	}

	return detectors.Finding{
		ID:          id,
		Type:        "misconfig",
		Severity:    severityOrDefault(tmpl.Info.Severity),
		Confidence:  "high",
		Target:      fullURL,
		Description: description,
		Evidence: map[string]string{
			"template_id":    tmpl.ID,
			"status":         fmt.Sprintf("%d", resp.StatusCode),
			"matched_checks": strings.Join(matchedChecks, ","),
			"request":        detectors.FormatRequest(httpReq.Method, fullURL, httpReq.Header, []byte(body)),
			"response":       detectors.FormatResponse(resp.StatusCode, resp.Header, respBody),
		},
	}, true, true, nil
}

// tryRaw runs one req.Raw-based request block: once per payload iteration
// (or a single unbound pass if req has no payloads — see
// HTTPRequest.resolvePayloads), firing every entry in req.Raw and evaluating
// req.Matchers against the last entry's response, enriched with every
// entry's body_N/header_N/status_code_N so a correlating matcher (real
// example: upstream's open-proxy-internal.yaml, 24 probes + one shared DSL
// matcher) actually works — see docs/10-implementation-plan-ph1b.md's
// raw:/payloads: note for why this project fires every entry unconditionally
// rather than treating Raw like a Path-style "try each until one matches"
// list. StopAtFirstMatch, when set, stops the payload-value loop early
// instead (matching what it already means for path:-based requests).
// Returns every Finding produced plus whether ANY payload iteration ended
// up chainable (see tryPath's doc comment for what that means) — needed by
// runFlow's http(N) truthiness.
func (e *Executor) tryRaw(ctx context.Context, target string, tmpl *Template, reqIdx int, req HTTPRequest, chainVars map[string]string) ([]detectors.Finding, bool, error) {
	iterations, err := req.resolvePayloads(tmpl.sourceDir)
	if err != nil {
		return nil, false, nil // already rejected at load time; defensive only
	}
	multi := len(iterations) > 0
	if !multi {
		iterations = []map[string]string{nil}
	}

	host, err := hostnameOf(target)
	if err != nil {
		return nil, false, nil
	}

	var findings []detectors.Finding
	chainable := false
	for pIdx, payloadVars := range iterations {
		if ctx.Err() != nil {
			return findings, chainable, ctx.Err()
		}

		iterVars := chainVars
		if multi {
			iterVars = make(map[string]string, len(chainVars)+len(payloadVars))
			for k, v := range chainVars {
				iterVars[k] = v
			}
			for k, v := range payloadVars {
				iterVars[k] = v
			}
		}
		renderCtx := vars.Context{BaseURL: target, Hostname: host, Vars: iterVars}

		finding, matched, ch, err := e.tryRawIteration(ctx, tmpl, reqIdx, req, renderCtx, chainVars, payloadVars, pIdx, multi)
		if err != nil {
			return findings, chainable, err
		}
		if ch {
			chainable = true
		}
		if matched {
			findings = append(findings, finding)
			if req.StopAtFirstMatch {
				break
			}
		}
	}
	return findings, chainable, nil
}

// tryRawIteration fires every entry in req.Raw once (rendering each through
// renderCtx), binds every entry's result as body_N/header_N/status_code_N/
// content_type_N/duration_N (plus a bare "duration" aliased to the last
// entry, same as the existing bare status_code/body/header/content_type
// aliasing), and evaluates req.Matchers/req.Extractors against the last entry's
// response — same non-fatal treatment of render/parse/network errors as
// tryPath: any failure on any entry aborts just this one iteration, not the
// whole scan. Returns (finding, matched, chainable, err) — see tryPath's
// doc comment for the matched/chainable distinction, which applies here
// identically (a matcher-less raw: block is trivially chainable too).
func (e *Executor) tryRawIteration(ctx context.Context, tmpl *Template, reqIdx int, req HTTPRequest, renderCtx vars.Context, chainVars, payloadVars map[string]string, pIdx int, idSuffix bool) (finding detectors.Finding, matched bool, chainable bool, err error) {
	extraVars := make(map[string]string, len(req.Raw)*3)
	extraInts := make(map[string]int, len(req.Raw)*2+1)
	var lastReq *http.Request
	var lastReqBody string
	var lastStatus int
	var lastHeaders http.Header
	var lastBody []byte

	for i, entry := range req.Raw {
		if ctx.Err() != nil {
			return detectors.Finding{}, false, false, ctx.Err()
		}
		n := i + 1

		rendered, err := vars.Render(entry, renderCtx)
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}
		httpReq, reqBody, err := buildRawRequest(ctx, renderCtx.BaseURL, rendered)
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}
		// Same baseline-not-override semantics as tryPath: a raw: entry's own
		// header line (already parsed into httpReq.Header by buildRawRequest)
		// wins over --header on a literal name conflict.
		for k, v := range e.extraHeaders {
			if httpReq.Header.Get(k) == "" {
				httpReq.Header.Set(k, v)
			}
		}
		start := time.Now()
		resp, err := e.client.Do(httpReq)
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}
		respBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return detectors.Finding{}, false, false, nil
		}
		// See tryPath's durationInts comment: measured around e.client.Do
		// only, so it includes this entry's own retry/backoff time on a
		// transient failure — same narrow, accepted over-counting risk.
		entryDuration := int(time.Since(start).Seconds())

		extraVars[fmt.Sprintf("body_%d", n)] = string(respBody)
		extraVars[fmt.Sprintf("header_%d", n)] = matcher.Part("header", matcher.Response{Headers: resp.Header})
		extraVars[fmt.Sprintf("content_type_%d", n)] = resp.Header.Get("Content-Type")
		extraInts[fmt.Sprintf("status_code_%d", n)] = resp.StatusCode
		extraInts[fmt.Sprintf("duration_%d", n)] = entryDuration
		// Bare "duration" aliases to the last entry, same as the bare
		// status_code/body/header/content_type identifiers already do via
		// lastStatus/lastBody/lastHeaders below.
		extraInts["duration"] = entryDuration

		lastReq, lastReqBody = httpReq, reqBody
		lastStatus, lastHeaders, lastBody = resp.StatusCode, resp.Header, respBody
	}

	if lastReq == nil {
		return detectors.Finding{}, false, false, nil // req.Raw was empty — rejected at load time, defensive only
	}

	// chainVars/payloadVars merged in alongside the body_N/header_N entries
	// so a matcher/extractor here can also reference an earlier request's
	// named extractor result, or this iteration's own bound payloads: value
	// (real example: upstream's wp-crontrol.yaml-style
	// compare_versions(extracted, concat("< ", last_version))) — same
	// mechanism tryPath uses, see its doc comment.
	for k, v := range chainVars {
		extraVars[k] = v
	}
	for k, v := range payloadVars {
		extraVars[k] = v
	}

	// Extraction runs unconditionally, before matchers evaluate — see
	// tryPath's doc comment for why (same-request extractor->matcher
	// binding).
	baseResp := matcher.Response{StatusCode: lastStatus, Headers: lastHeaders, Body: lastBody, ExtraVars: extraVars, ExtraInts: extraInts}
	extracted := extractor.Extract(req.Extractors, baseResp)

	mResp := matcher.Response{StatusCode: lastStatus, Headers: lastHeaders, Body: lastBody, ExtraVars: mergeVars(extraVars, extracted), ExtraInts: extraInts}
	evaluated := len(req.Matchers) > 0 && matcher.EvaluateAll(req.Matchers, req.MatchersCondition, mResp)
	chainable = evaluated || len(req.Matchers) == 0
	matched = evaluated && hasReportableMatcher(req.Matchers)
	if !chainable {
		return detectors.Finding{}, false, false, nil
	}

	for k, v := range extracted {
		chainVars[k] = v
	}
	if !matched {
		return detectors.Finding{}, false, true, nil
	}

	matchedChecks := matcher.MatchingNames(req.Matchers, mResp)
	description := tmpl.Info.Name
	if len(matchedChecks) > 0 {
		description = fmt.Sprintf("%s (%s)", tmpl.Info.Name, strings.Join(matchedChecks, ", "))
	}

	id := fmt.Sprintf("nuclei-%s-%d", tmpl.ID, reqIdx)
	if idSuffix {
		id = fmt.Sprintf("nuclei-%s-%d-%d", tmpl.ID, reqIdx, pIdx)
	}

	return detectors.Finding{
		ID:          id,
		Type:        "misconfig",
		Severity:    severityOrDefault(tmpl.Info.Severity),
		Confidence:  "high",
		Target:      lastReq.URL.String(),
		Description: description,
		Evidence: map[string]string{
			"template_id":    tmpl.ID,
			"status":         fmt.Sprintf("%d", lastStatus),
			"matched_checks": strings.Join(matchedChecks, ","),
			"request":        detectors.FormatRequest(lastReq.Method, lastReq.URL.String(), lastReq.Header, []byte(lastReqBody)),
			"response":       detectors.FormatResponse(lastStatus, lastHeaders, lastBody),
		},
	}, true, true, nil
}

// buildRawRequest turns one already-rendered raw HTTP/1.1 request text into
// a real outbound *http.Request pointed at target's host, returning the
// request body text alongside it (for evidence formatting). Splits headers
// from body itself, rather than relying on http.ReadRequest's own body
// extraction, because that requires a Content-Length/Transfer-Encoding
// header real templates often omit — verified live (see
// docs/10-implementation-plan-ph1b.md's raw:/payloads: note): without one,
// http.ReadRequest silently reports an empty body, which would silently
// drop a real POST body from every such template. An absolute-URI request
// line (parsed.URL.IsAbs()) is already rejected at load time (see
// schema.go's hasAbsoluteRequestLine) — this project has no path that can
// honor one without risking a connection to a template-controlled,
// out-of-scope host, so it should never reach here; treated as a build
// error if it somehow does, not silently dialed.
func buildRawRequest(ctx context.Context, target, rendered string) (httpReq *http.Request, body string, err error) {
	headerBlock, body := splitRawHeaderBody(rendered)
	headerBlock = normalizeEmptyRequestTarget(headerBlock)
	parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(headerBlock)))
	if err != nil {
		return nil, "", fmt.Errorf("parsing raw request: %w", err)
	}
	if parsed.URL.IsAbs() {
		return nil, "", fmt.Errorf("raw request has an absolute-URI request line, unsupported")
	}

	fullURL := target + parsed.URL.Path
	if parsed.URL.RawQuery != "" {
		fullURL += "?" + parsed.URL.RawQuery
	}

	httpReq, err = http.NewRequestWithContext(ctx, parsed.Method, fullURL, strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	for k, vs := range parsed.Header {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	// Preserve the literal Host: header a template authored, rather than
	// deriving one from fullURL — real templates deliberately send a
	// different Host than the target's real one (virtual-host confusion
	// checks), and http.Request.Write uses Host over the URL's host when set.
	httpReq.Host = parsed.Host

	return httpReq, body, nil
}

// normalizeEmptyRequestTarget defaults a request line with no target (e.g.
// real upstream's cors-misconfig.yaml uses "GET  HTTP/1.1", an intentional
// double space — real Nuclei treats a missing target as root) to "/".
// http.ReadRequest hard-errors on an empty target ("parse \"\": empty url")
// rather than defaulting it — found live against that real template, not
// hypothetical.
func normalizeEmptyRequestTarget(headerBlock string) string {
	nl := strings.IndexAny(headerBlock, "\r\n")
	if nl == -1 {
		return headerBlock
	}
	firstLine, rest := headerBlock[:nl], headerBlock[nl:]
	fields := strings.Fields(firstLine)
	if len(fields) == 2 { // METHOD HTTP/x.x, target was blank and got collapsed by Fields
		firstLine = fields[0] + " / " + fields[1]
	}
	return firstLine + rest
}

func splitRawHeaderBody(raw string) (headerBlock, body string) {
	if idx := strings.Index(raw, "\r\n\r\n"); idx != -1 {
		return raw[:idx] + "\r\n\r\n", raw[idx+4:]
	}
	if idx := strings.Index(raw, "\n\n"); idx != -1 {
		return raw[:idx] + "\n\n", raw[idx+2:]
	}
	return raw + "\n\n", ""
}

// mergeVars combines maps into one new map, later maps' keys winning on
// conflict — used to build the matcher-facing ExtraVars from chainVars
// (accumulated from earlier requests) plus a request's own freshly
// extracted values (see tryPath/tryRawIteration), without mutating any of
// the inputs.
func mergeVars(maps ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// hasReportableMatcher reports whether matchers contains at least one
// non-internal (Internal == false) entry — i.e. whether a genuine match
// against this block could ever produce a Finding. A block whose matchers
// are all internal: true (real templates' flow-control gates, e.g.
// apache-server-status-localhost.yaml's 403/404/401 check) still
// contributes to that block's own matched/chainable state via
// matcher.EvaluateAll, but must never itself be reported — see
// matcher.Matcher.Internal's doc comment.
func hasReportableMatcher(matchers []matcher.Matcher) bool {
	for _, m := range matchers {
		if !m.Internal {
			return true
		}
	}
	return false
}

func hostnameOf(target string) (string, error) {
	u, err := neturl.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing target URL: %w", err)
	}
	return u.Host, nil
}

func methodOrDefault(m string) string {
	if m == "" {
		return http.MethodGet
	}
	return m
}

func bodyReader(body string) io.Reader {
	if body == "" {
		return nil
	}
	return strings.NewReader(body)
}

// severityOrDefault maps an empty info.severity to "info" — Nuclei allows
// omitting it for informational-only detections like tech fingerprinting.
func severityOrDefault(s string) string {
	if s == "" {
		return "info"
	}
	return s
}
