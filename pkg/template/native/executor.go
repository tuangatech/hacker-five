package native

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/vars"
	"github.com/tuangatech/hacker-five/pkg/template/dsl"
	"github.com/tuangatech/hacker-five/pkg/template/extractor"
	"github.com/tuangatech/hacker-five/pkg/template/matcher"
)

// Executor runs one parsed native Template against one target.
type Executor struct {
	client *httpclient.Client
}

// New constructs an Executor.
func New(client *httpclient.Client) *Executor {
	return &Executor{client: client}
}

// Run executes tmpl against target. idor-tagged templates route through the
// existing idor.Detector; every other template runs through the generic
// matcher/extractor chaining path.
func (e *Executor) Run(ctx context.Context, target string, tmpl *Template, ownerToken, otherToken string) ([]detectors.Finding, error) {
	if isIDORTagged(tmpl) {
		return e.runIDOR(ctx, target, tmpl, ownerToken, otherToken)
	}
	return e.runGeneric(ctx, target, tmpl)
}

// runIDOR delegates to the existing idor.Detector — see
// docs/10-implementation-plan-ph1b.md Step 3's Context #2/#6. Skips cleanly
// (no findings, no error) when both tokens are empty rather than let
// idor.Detector's single-token heuristic fallback fire fully unauthenticated;
// that fallback is intentional for the flag-driven --detector idor path
// (which Config.Validate() already requires at least one token for), but
// nothing enforces token presence for a template reached only via
// --templates while --detector is something else.
func (e *Executor) runIDOR(ctx context.Context, target string, tmpl *Template, ownerToken, otherToken string) ([]detectors.Finding, error) {
	if ownerToken == "" && otherToken == "" {
		return nil, nil
	}
	req := tmpl.Requests[0]
	minID, maxID, endpointTemplate, err := parseIDORRequest(target, tmpl, req)
	if err != nil {
		return nil, fmt.Errorf("native: template %s: %w", tmpl.ID, err)
	}
	strategy := idor.SequentialIntStrategy{Start: minID, End: maxID}
	detector := idor.New(e.client, strategy)
	return detector.Run(ctx, endpointTemplate, ownerToken, otherToken)
}

// runGeneric fires every request in tmpl.Requests, in order, evaluating each
// one's Condition (against already-bound variables) before firing, then its
// Matchers/Extractors — mirrors nuclei.Executor.Run/tryPath
// (pkg/template/nuclei/executor.go), with one deliberate difference: see
// tryRequest's doc comment on why extraction isn't gated on a match here.
func (e *Executor) runGeneric(ctx context.Context, target string, tmpl *Template) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	chainVars := map[string]string{}
	for k, v := range tmpl.Variables {
		chainVars[k] = v
	}

	for reqIdx, req := range tmpl.Requests {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}

		if req.Condition != "" && !conditionHolds(req.Condition, chainVars) {
			continue // false/unresolvable condition: skip this request, not scan-fatal
		}

		finding, matched, err := e.tryRequest(ctx, target, tmpl, reqIdx, req, chainVars)
		if err != nil {
			return findings, err
		}
		if matched {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func conditionHolds(condition string, boundVars map[string]string) bool {
	val, err := dsl.Eval(condition, dsl.Context{Vars: boundVars})
	if err != nil {
		return false
	}
	b, ok := val.(bool)
	return ok && b
}

// tryRequest renders and fires one request, then always runs its Extractors
// — regardless of whether it "matched" — before deciding whether it's
// finding-worthy. This is deliberately different from nuclei.Executor
// (Step 2), which only extracts on match: that's correct for a Nuclei
// template, where an extractor-only request has no matchers because it's
// never meant to be a standalone finding, and matcher.EvaluateAll's own
// design already reflects that (empty matchers = false, per Step 2's live
// false-positive fix). But the native format's canonical chaining pattern
// (doc02's login-then-probe example) is exactly that shape deliberately —
// request 1 (login) has no matchers at all, existing purely to bind
// {{auth_token}} for request 2 — so gating extraction on a match here would
// silently break the one worked example this format is built around. A
// request with no Matchers therefore never produces a Finding (same
// end result as nuclei's empty-matchers behavior) but its Extractors still
// run.
func (e *Executor) tryRequest(ctx context.Context, target string, tmpl *Template, reqIdx int, req Request, chainVars map[string]string) (detectors.Finding, bool, error) {
	renderCtx := vars.Context{BaseURL: target, Vars: chainVars}

	fullURL, err := vars.Render(req.Path, renderCtx)
	if err != nil {
		return detectors.Finding{}, false, nil
	}
	body, err := vars.Render(req.Body, renderCtx)
	if err != nil {
		return detectors.Finding{}, false, nil
	}

	httpReq, err := http.NewRequestWithContext(ctx, methodOrDefault(req.Method), fullURL, bodyReader(body))
	if err != nil {
		return detectors.Finding{}, false, fmt.Errorf("native: building request for template %s: %w", tmpl.ID, err)
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

	for k, v := range extractor.Extract(req.Extractors, mResp) {
		chainVars[k] = v
	}

	if len(req.Matchers) == 0 {
		return detectors.Finding{}, false, nil
	}
	cond := req.MatchersCondition
	if cond == "" {
		cond = matcher.And // native default differs from Nuclei's "or" default — see schema.go
	}
	if !matcher.EvaluateAll(req.Matchers, cond, mResp) {
		return detectors.Finding{}, false, nil
	}

	matchedChecks := matcher.MatchingNames(req.Matchers, mResp)
	description := tmpl.Info.Name
	if len(matchedChecks) > 0 {
		description = fmt.Sprintf("%s (%s)", tmpl.Info.Name, strings.Join(matchedChecks, ", "))
	}

	return detectors.Finding{
		ID:          fmt.Sprintf("native-%s-%d", tmpl.ID, reqIdx),
		Type:        findingType(tmpl),
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

// findingType uses the template's first tag as the Finding's vulnerability
// category (e.g. "ssrf", "auth-bypass"), falling back to "custom" for an
// untagged template.
func findingType(tmpl *Template) string {
	if len(tmpl.Tags) > 0 {
		return tmpl.Tags[0]
	}
	return "custom"
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

func severityOrDefault(s string) string {
	if s == "" {
		return "info"
	}
	return s
}
