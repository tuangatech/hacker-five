package nuclei

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/vars"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Executor runs one parsed Template against one target.
type Executor struct {
	client *httpclient.Client
}

// New constructs an Executor.
func New(client *httpclient.Client) *Executor {
	return &Executor{client: client}
}

// Run fires every request in tmpl.HTTP, in order, against target. Each
// request's Path entries are tried in turn (stopping early if
// StopAtFirstMatch is set); a match against a path emits one Finding and
// runs that request's Extractors, binding their results as chain-scoped
// variables available to every later request in the template — matching
// doc 02's variable-scope rules. Path/Headers/Body are all rendered via
// vars.Render, so "{{BaseURL}}" and any bound chain variable resolve the
// same way the native format (Step 3) will use them.
func (e *Executor) Run(ctx context.Context, target string, tmpl *Template) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	chainVars := map[string]string{}

	for reqIdx, req := range tmpl.HTTP {
		for _, path := range req.Path {
			if ctx.Err() != nil {
				return findings, ctx.Err()
			}

			finding, matched, err := e.tryPath(ctx, target, tmpl, reqIdx, req, path, chainVars)
			if err != nil {
				return findings, err
			}
			if matched {
				findings = append(findings, finding)
				if req.StopAtFirstMatch {
					break
				}
			}
		}
	}
	return findings, nil
}

// tryPath renders and fires one request for one Path entry, evaluates its
// matchers, and — on a match — runs its extractors into chainVars. A
// rendering failure (an unresolved {{chainVar}}, e.g. because an earlier
// request's extractor never fired) or a network error is not scan-fatal:
// it's reported as "no match" for this path, same as a legitimately
// non-matching response.
func (e *Executor) tryPath(ctx context.Context, target string, tmpl *Template, reqIdx int, req HTTPRequest, path string, chainVars map[string]string) (detectors.Finding, bool, error) {
	renderCtx := vars.Context{BaseURL: target, Vars: chainVars}

	fullURL, err := vars.Render(path, renderCtx)
	if err != nil {
		return detectors.Finding{}, false, nil
	}
	body, err := vars.Render(req.Body, renderCtx)
	if err != nil {
		return detectors.Finding{}, false, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, methodOrDefault(req.Method), fullURL, bodyReader(body))
	if err != nil {
		return detectors.Finding{}, false, fmt.Errorf("nuclei: building request for template %s: %w", tmpl.ID, err)
	}
	for k, v := range req.Headers {
		if rv, err := vars.Render(v, renderCtx); err == nil {
			httpReq.Header.Set(k, rv)
		}
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return detectors.Finding{}, false, nil
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return detectors.Finding{}, false, nil
	}

	mResp := matcher.Response{StatusCode: resp.StatusCode, Headers: resp.Header, Body: respBody}
	if !matcher.EvaluateAll(req.Matchers, req.MatchersCondition, mResp) {
		return detectors.Finding{}, false, nil
	}

	for k, v := range extractor.Extract(req.Extractors, mResp) {
		chainVars[k] = v
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

	return detectors.Finding{
		ID:          fmt.Sprintf("nuclei-%s-%d", tmpl.ID, reqIdx),
		Type:        "misconfig",
		Severity:    severityOrDefault(tmpl.Info.Severity),
		Confidence:  "high",
		Target:      fullURL,
		Description: description,
		Evidence: map[string]string{
			"template_id":    tmpl.ID,
			"status":         fmt.Sprintf("%d", resp.StatusCode),
			"matched_checks": strings.Join(matchedChecks, ","),
		},
	}, true, nil
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
