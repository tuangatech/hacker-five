package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// scriptCandidateSentinel-prefixed JSON lines let a script.explore script
// propose a Finding without this package ever trusting its self-report
// (docs/follow-up.md LT-160 item 1, closing the self-reported-confidence
// flaw docs/92-research-llm-orchestrator.md §2 names): a candidate names a
// fully-formed request AND a falsifiable confirmation condition (an expected
// status code and/or a response substring). reconfirmScriptCandidates only
// ships a Finding when independently re-issuing that exact request outside
// the sandbox — via this package's own httpclient, never the sandbox's own
// report of what it saw — actually satisfies the condition. A candidate with
// no confirmation condition, or one whose re-issued response doesn't match,
// is dropped and logged, never silently promoted.
const scriptCandidateSentinel = "HACKERFIVE_FINDING_CANDIDATE:"

// scriptFindingCandidate is the JSON shape a script.explore script prints
// (see buildCatalog's script.explore Description, the only place this
// contract is documented to the model) one line per candidate, prefixed by
// scriptCandidateSentinel.
type scriptFindingCandidate struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	Type            string            `json:"type"`
	Severity        string            `json:"severity"`
	Description     string            `json:"description"`
	ConfirmStatus   int               `json:"confirm_status"`
	ConfirmContains string            `json:"confirm_contains"`
}

// reconfirmMaxRedirects mirrors pkg/scanner/engine.go's own maxRedirects —
// kept as a separate local constant rather than exporting scanner's since
// this is the only other place outside pkg/scanner that issues a real scan
// request.
const reconfirmMaxRedirects = 5

// maxReconfirmBodyBytes bounds how much of a re-issued response body this
// package reads — a confirmation check only ever needs to find a substring
// or note the response for evidence, never the whole body of an arbitrarily
// large response.
const maxReconfirmBodyBytes = 64 * 1024

// safeReconfirmMethods are re-issued without requiring --allow-writes; any
// other method (POST/PUT/DELETE/PATCH/...) is a mutating request and follows
// the same --allow-writes gate as pkg/detectors/businesslogic's own mutating
// checks (CLAUDE.md's "any new mutating capability needs its own
// equally-scoped flag" rule — this reuses the existing one rather than
// adding a new one, since it's the same scan's own AllowWrites already in
// effect).
var safeReconfirmMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

var validReconfirmSeverities = map[string]bool{
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
}

// reconfirmScriptCandidates scans a completed script.explore run's stdout
// for scriptCandidateSentinel lines, independently re-issues each one that
// passes scope/method checks, and returns the Findings that were actually
// confirmed plus a short human-readable note per candidate seen (confirmed,
// dropped, or not confirmed) — fed into the turn's ResultSummary so the
// model sees exactly what happened to what it proposed.
func reconfirmScriptCandidates(ctx context.Context, cfg Config, stdout string) ([]detectors.Finding, []string) {
	var findings []detectors.Finding
	var notes []string
	for _, line := range strings.Split(stdout, "\n") {
		idx := strings.Index(line, scriptCandidateSentinel)
		if idx == -1 {
			continue
		}
		payload := strings.TrimSpace(line[idx+len(scriptCandidateSentinel):])
		var c scriptFindingCandidate
		if err := json.Unmarshal([]byte(payload), &c); err != nil {
			notes = append(notes, fmt.Sprintf("candidate dropped: invalid JSON (%v)", err))
			continue
		}
		f, note := reconfirmCandidate(ctx, cfg, c)
		if f != nil {
			findings = append(findings, *f)
		}
		notes = append(notes, note)
	}
	return findings, notes
}

// reconfirmCandidate is the single gate between a script's proposed request
// and a shipped Finding — see reconfirmScriptCandidates' doc comment for
// why. Every rejection path returns a nil Finding and a reason string;
// nothing here ever fabricates a Finding from the candidate's own claims
// alone.
func reconfirmCandidate(ctx context.Context, cfg Config, c scriptFindingCandidate) (*detectors.Finding, string) {
	if c.URL == "" {
		return nil, "candidate dropped: empty url"
	}
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !safeReconfirmMethods[method] && !cfg.BaseScanConfig.AllowWrites {
		return nil, fmt.Sprintf("candidate dropped (%s %s): mutating method requires --allow-writes", method, c.URL)
	}
	if !inScope(cfg, c.URL) {
		return nil, fmt.Sprintf("candidate dropped (%s %s): target not in scope", method, c.URL)
	}
	if c.ConfirmStatus == 0 && c.ConfirmContains == "" {
		return nil, fmt.Sprintf("candidate dropped (%s %s): no confirm_status/confirm_contains given — refusing to trust the script's own report without a falsifiable check", method, c.URL)
	}

	var body io.Reader
	if c.Body != "" {
		body = strings.NewReader(c.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL, body)
	if err != nil {
		return nil, fmt.Sprintf("candidate dropped (%s %s): building request: %v", method, c.URL, err)
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	client := httpclient.New(httpclient.Config{
		Timeout:            cfg.BaseScanConfig.Timeout,
		MaxRedirects:       reconfirmMaxRedirects,
		InsecureSkipVerify: cfg.BaseScanConfig.Insecure,
		ProxyURL:           cfg.BaseScanConfig.ProxyURL,
	})
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Sprintf("candidate not confirmed (%s %s): re-issued request failed: %v", method, c.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxReconfirmBodyBytes))

	if c.ConfirmStatus != 0 && resp.StatusCode != c.ConfirmStatus {
		return nil, fmt.Sprintf("candidate not confirmed (%s %s): expected status %d, got %d", method, c.URL, c.ConfirmStatus, resp.StatusCode)
	}
	if c.ConfirmContains != "" && !strings.Contains(string(respBody), c.ConfirmContains) {
		return nil, fmt.Sprintf("candidate not confirmed (%s %s): re-issued response did not contain the expected substring", method, c.URL)
	}

	severity := c.Severity
	if !validReconfirmSeverities[severity] {
		severity = "medium"
	}
	findingType := strings.TrimSpace(c.Type)
	if findingType == "" {
		findingType = "script-explore"
	}
	desc := strings.TrimSpace(c.Description)
	if desc == "" {
		desc = "script.explore proposed this request; independently re-issuing it outside the sandbox confirmed the stated condition"
	}

	f := &detectors.Finding{
		ID:          fmt.Sprintf("script-explore-%s-%s", sanitizeCandidateID(findingType), sanitizeCandidateID(c.URL)),
		Type:        findingType,
		Severity:    severity,
		Confidence:  "high",
		Target:      c.URL,
		Description: desc,
		Evidence: map[string]string{
			"method":              method,
			"url":                 c.URL,
			"confirmed_status":    fmt.Sprintf("%d", resp.StatusCode),
			"confirmation_method": "independently re-issued outside the sandbox via pkg/scanner/httpclient (not the script's own self-reported output)",
			"response_snippet":    truncateForHistory(string(respBody)),
		},
	}
	return f, fmt.Sprintf("candidate confirmed (%s %s): finding created", method, c.URL)
}

// inScope reports whether rawURL's host is within the scan's authorized
// scope. cfg.BaseScanConfig.Scope is the same *scope.Scope B4's scope-creep
// gate already checks scan.leaf dispatches against; when a run carries none
// (Scope is optional — see Config.BaseScanConfig's doc comment), fall back
// to requiring an exact host match against the run's own seed target, so a
// script can never point a "confirmed" candidate at a host the run was
// never asked to look at.
func inScope(cfg Config, rawURL string) bool {
	if cfg.BaseScanConfig.Scope != nil {
		return cfg.BaseScanConfig.Scope.Allowed(rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	target, err := url.Parse(cfg.Target)
	if err != nil || target.Hostname() == "" {
		return strings.EqualFold(u.Hostname(), cfg.Target)
	}
	return strings.EqualFold(u.Hostname(), target.Hostname())
}

// sanitizeCandidateID turns an arbitrary type/URL string into a Finding-ID-
// safe fragment — same convention as pkg/detectors/authbypass's own
// sanitizeID (each detector package keeps its own small copy rather than
// sharing one; this is the orchestrator package's).
func sanitizeCandidateID(s string) string {
	s = strings.Trim(s, "/")
	s = strings.NewReplacer("/", "-", "?", "-", "&", "-", "=", "-", ":", "-").Replace(s)
	if s == "" {
		return "root"
	}
	return s
}
