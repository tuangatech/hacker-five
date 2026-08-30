// Package misconfig implements the misconfiguration detector: fixed
// built-in rule tables (exposed paths, directory listing, comment leaks,
// missing security headers, disallowed HTTP methods, CORS misconfiguration,
// verbose error messages, default credentials) checked against a single
// target.
package misconfig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// corsProbeOrigin is a non-existent origin used to test whether a target
// reflects arbitrary Origin headers back in Access-Control-Allow-Origin.
const corsProbeOrigin = "https://hackerfive-cors-probe.invalid"

// baselineCanaryPath is guaranteed not to be a real resource on any target —
// used by probeBaseline to see what a target returns for "definitely
// nothing here," so looksLikeBaselinePage can recognize when a WAF/
// bot-protection layer returns that same generic page for every request,
// including genuinely sensitive-looking paths. Found necessary live against
// a real Akamai-fronted target: every ExposedPaths probe (including root)
// came back as an identical "Access Denied" template that happened to echo
// the requested path and a "https://errors.edgesuite.net/..." reference
// link back in the body — which trivially satisfied keyword rules like
// {Path: "/debug", Keywords: ["debug", ...]} and {Path: "/graphql",
// Keywords: ["errors", ...]}, producing a 100% false-positive run (see
// docs/13-implementation-plan-ph4.md's Step 4 live-verification notes).
// Deliberately alphanumeric only, no hyphens/dots/other punctuation: a
// real WAF/CDN block page that echoes the requested path back HTML-entity-
// encodes punctuation in it (e.g. Akamai renders "-" as "&#45;") but
// leaves alphanumeric runs literal — a hyphenated canary path would
// therefore never appear as a literal substring in the echoed body,
// silently defeating bodyLengthExcluding's normalization (found live: the
// original hyphenated canary under-suppressed several real false
// positives that a purely alphanumeric one correctly catches).
const baselineCanaryPath = "/hackerfivebaselinecanary9f3c7a21"

// suspiciousBaselineStatuses are the status codes a guaranteed-nonexistent
// canary path returning them actually suggests interception (a WAF/
// bot-protection/auth layer), not the application's own routing. A 200
// canary is deliberately excluded: many real targets (SPA catch-all
// routing, an API with no path-based 404s) legitimately return 200 for
// everything, and that's a normal, already-tolerated pattern this project's
// keyword/marker matching handles on its own (see
// TestMisconfigExposedPath_CustomNotFoundPage_NoFinding) — treating a plain
// 200 as "suspicious" would suppress real comment-leak/missing-header
// findings on any such target, which live testing against a real SPA-style
// mock confirmed. A 404 canary is excluded for the same reason as always:
// it's the expected, harmless outcome for most speculative probes.
var suspiciousBaselineStatuses = map[int]bool{
	http.StatusUnauthorized:       true,
	http.StatusForbidden:          true,
	http.StatusTooManyRequests:    true,
	http.StatusServiceUnavailable: true,
}

// malformedQuery is appended to exposed-path checks to try to trigger a
// verbose error response (stack trace, DB error) without being a real
// injection attempt — a single fixed probe, not fuzzing.
const malformedQuery = "?id=%27"

var verboseErrorRegexes = compilePatterns(VerboseErrorPatterns)
var commentLeakRegexes = compilePatternsCaseInsensitive(CommentLeakPatterns)

func compilePatterns(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

// compilePatternsCaseInsensitive is compilePatterns' case-insensitive
// counterpart, used for CommentLeakPatterns — see that var's doc comment for
// why real markup can't be relied on for consistent casing.
func compilePatternsCaseInsensitive(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile("(?i)" + p)
	}
	return out
}

// Detector runs the built-in misconfiguration rule tables against a target.
type Detector struct {
	client *httpclient.Client

	// hostErrors stops a run early once the target host crosses its
	// consecutive-error threshold, same as idor.Detector.
	hostErrors *hosterrors.Cache

	// baseline* capture a single canary probe fetched once per Run call —
	// see baselineCanaryPath/looksLikeBaselinePage. Safe as instance state:
	// scanner.Engine.runDetector constructs a fresh Detector per target, so
	// this never carries over between targets or races across concurrent
	// Run calls on the same instance.
	baselineFetched          bool
	baselineStatus           int
	baselineBody             []byte
	baselineRequestEvidence  string
	baselineResponseEvidence string
}

// New constructs a Detector.
func New(client *httpclient.Client) *Detector {
	return &Detector{
		client:     client,
		hostErrors: hosterrors.New(hosterrors.DefaultThreshold),
	}
}

// Run checks target against every built-in rule category and returns every
// finding. authToken is optional — set as a Bearer header when non-empty,
// for targets where interesting paths sit behind auth.
func (d *Detector) Run(ctx context.Context, target, authToken string) ([]detectors.Finding, error) {
	host, err := hostOf(target)
	if err != nil {
		return nil, fmt.Errorf("misconfig: %w", err)
	}

	var findings []detectors.Finding

	d.probeBaseline(ctx, target, host, authToken)
	if d.baselineFetched && suspiciousBaselineStatuses[d.baselineStatus] {
		// A guaranteed-nonexistent path came back as anything other than a
		// normal 404 — most speculative probes below legitimately 404 on a
		// real target, and that's an expected, harmless scanning outcome,
		// not a signal on its own. A non-404 (403/401/429/a soft-200, ...)
		// instead suggests something above the real application — a WAF,
		// bot-protection layer, auth wall — is intercepting requests
		// uniformly, which is what actually makes body/header content
		// matching meaningless. Surfaced once here; individual
		// exposed-path/dir-listing/comment-leak/missing-header/
		// verbose-error findings below are additionally suppressed
		// wherever their own specific response also matches this shape
		// (see looksLikeBaselinePage) — CORS/disallowed-method/
		// default-credential checks aren't fooled by response body content
		// the same way, so they still run and report normally regardless.
		findings = append(findings, detectors.Finding{
			ID:          "misconfig-waf-blocked",
			Type:        "misconfig",
			Severity:    "low",
			Confidence:  "low",
			Target:      target,
			Description: fmt.Sprintf("a guaranteed-nonexistent path (%s) returned status %d — likely a WAF/bot-protection/auth layer intercepting requests rather than the application's own routing (a real 404 would be expected here)", baselineCanaryPath, d.baselineStatus),
			Evidence: map[string]string{
				"baseline_path":   baselineCanaryPath,
				"baseline_status": fmt.Sprintf("%d", d.baselineStatus),
				"request":         d.baselineRequestEvidence,
				"response":        d.baselineResponseEvidence,
			},
		})
	}

	checks := []func(context.Context, string, string, string) ([]detectors.Finding, error){
		d.checkExposedPaths,
		d.checkDirListing,
		d.checkCommentLeaks,
		d.checkMissingHeaders,
		d.checkDisallowedMethods,
		d.checkCORS,
		d.checkVerboseErrors,
		d.checkDefaultCreds,
	}
	for _, check := range checks {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		if d.hostErrors.ShouldSkip(host) {
			break
		}
		fs, err := check(ctx, target, host, authToken)
		if err != nil {
			return findings, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

func (d *Detector) checkExposedPaths(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, rule := range ExposedPaths {
		req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, rule.Path, authToken, nil, nil)
		if err != nil {
			continue // already recorded against hostErrors; keep checking other paths
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if !containsAny(body, rule.Keywords) {
			continue
		}
		if d.looksLikeBaselinePage(resp.StatusCode, body, rule.Path) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-exposed-path-%s", sanitizeID(rule.Path)),
			Type:        "misconfig",
			Severity:    rule.Severity,
			Confidence:  "high",
			Target:      target + rule.Path,
			Description: fmt.Sprintf("%s returned status %d with sensitive content matching a keyword for an exposed-path rule", rule.Path, resp.StatusCode),
			Evidence: map[string]string{
				"path":     rule.Path,
				"status":   fmt.Sprintf("%d", resp.StatusCode),
				"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
				"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			},
		})
	}
	return findings, nil
}

// checkDirListing probes DirListingPaths (root plus common subpaths) for
// directory-listing banners — see DirListingPaths' doc comment for why this
// exists as a built-in check rather than relying solely on
// templates/nuclei-samples/dvwa-php/dir-listing.yaml, which only checks
// root.
func (d *Detector) checkDirListing(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, path := range DirListingPaths {
		req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, path, authToken, nil, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		if !containsAnyFold(body, DirListingMarkers) {
			continue
		}
		if d.looksLikeBaselinePage(resp.StatusCode, body, path) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-dir-listing-%s", sanitizeID(path)),
			Type:        "misconfig",
			Severity:    "low",
			Confidence:  "high",
			Target:      target + path,
			Description: fmt.Sprintf("%s returned status %d with a directory-listing banner in the body", pathOrRoot(path), resp.StatusCode),
			Evidence: map[string]string{
				"path":     path,
				"status":   fmt.Sprintf("%d", resp.StatusCode),
				"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
				"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			},
		})
	}
	return findings, nil
}

// checkCommentLeaks fetches target root and checks the body for
// CommentLeakPatterns — debug/development leftovers in HTML comments
// (Phase 2 Step 4, docs/11-implementation-plan-ph2.md). Root only, not a
// path list: unlike ExposedPaths' known sensitive-file locations, there's no
// principled list of "where a leftover comment might be," so this stays a
// single bounded request rather than guessing at additional paths.
func (d *Detector) checkCommentLeaks(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, "", authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	if d.looksLikeBaselinePage(resp.StatusCode, body, "") {
		return nil, nil
	}
	pattern, matched := matchAny(body, commentLeakRegexes)
	if !matched {
		return nil, nil
	}
	return []detectors.Finding{{
		ID:          "misconfig-comment-leak",
		Type:        "misconfig",
		Severity:    "low",
		Confidence:  "high",
		Target:      target,
		Description: "response body contains an HTML comment matching a common debug/development leftover pattern",
		Evidence: map[string]string{
			"pattern":  pattern,
			"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		},
	}}, nil
}

func (d *Detector) checkMissingHeaders(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, "", authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	if d.looksLikeBaselinePage(resp.StatusCode, body, "") {
		return nil, nil
	}
	var findings []detectors.Finding
	for _, rule := range MissingHeaders {
		if resp.Header.Get(rule.Name) != "" {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-missing-header-%s", sanitizeID(rule.Name)),
			Type:        "misconfig",
			Severity:    rule.Severity,
			Confidence:  "high",
			Target:      target,
			Description: fmt.Sprintf("response is missing the %s security header", rule.Name),
			Evidence: map[string]string{
				"header":   rule.Name,
				"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
				"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			},
		})
	}
	return findings, nil
}

func (d *Detector) checkDisallowedMethods(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, rule := range DisallowedMethods {
		req, resp, body, err := d.doRequest(ctx, rule.Method, target, host, rule.Path, authToken, nil, nil)
		if err != nil {
			continue
		}
		if rejected(resp.StatusCode) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-method-%s-%s", strings.ToLower(rule.Method), sanitizeID(rule.Path)),
			Type:        "misconfig",
			Severity:    "medium",
			Confidence:  "high",
			Target:      target + rule.Path,
			Description: fmt.Sprintf("%s appears to be accepted (status %d) instead of rejected", rule.Method, resp.StatusCode),
			Evidence: map[string]string{
				"method":   rule.Method,
				"status":   fmt.Sprintf("%d", resp.StatusCode),
				"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
				"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			},
		})
	}
	return findings, nil
}

// rejected reports whether status is one of the expected "method not
// allowed" signals — anything else means the method appears to be accepted.
func rejected(status int) bool {
	return status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented || status == http.StatusForbidden
}

func (d *Detector) checkCORS(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	headers := map[string]string{"Origin": corsProbeOrigin}
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, "", authToken, headers, nil)
	if err != nil {
		return nil, nil
	}

	allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	allowCreds := strings.EqualFold(resp.Header.Get("Access-Control-Allow-Credentials"), "true")
	reflected := allowOrigin == corsProbeOrigin || allowOrigin == "*"
	if !reflected || !allowCreds {
		return nil, nil
	}

	return []detectors.Finding{{
		ID:          "misconfig-cors",
		Type:        "misconfig",
		Severity:    "high",
		Confidence:  "high",
		Target:      target,
		Description: "target reflects an arbitrary Origin (or uses a wildcard) while also allowing credentials, letting any site make authenticated cross-origin requests",
		Evidence: map[string]string{
			"access_control_allow_origin":      allowOrigin,
			"access_control_allow_credentials": resp.Header.Get("Access-Control-Allow-Credentials"),
			"request":                          detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response":                         detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		},
	}}, nil
}

func (d *Detector) checkVerboseErrors(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, rule := range ExposedPaths {
		path := rule.Path + malformedQuery
		req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, path, authToken, nil, nil)
		if err != nil {
			continue
		}
		pattern, matched := matchAny(body, verboseErrorRegexes)
		if !matched {
			continue
		}
		if d.looksLikeBaselinePage(resp.StatusCode, body, rule.Path) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-verbose-error-%s", sanitizeID(rule.Path)),
			Type:        "misconfig",
			Severity:    "medium",
			Confidence:  "high",
			Target:      target + path,
			Description: "response to a malformed request contains a verbose error message (stack trace, internal path, or internal IP)",
			Evidence: map[string]string{
				"path":     path,
				"pattern":  pattern,
				"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
				"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			},
		})
	}
	return findings, nil
}

func (d *Detector) checkDefaultCreds(ctx context.Context, target, host, _ string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, rule := range DefaultCreds {
		form := url.Values{"username": {rule.Username}, "password": {rule.Password}}.Encode()
		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		req, resp, body, err := d.doRequest(ctx, http.MethodPost, target, host, rule.LoginPath, "", headers, strings.NewReader(form))
		if err != nil {
			continue
		}
		if !loginSucceeded(resp, rule.LoginPath) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-default-creds-%s", sanitizeID(rule.LoginPath)),
			Type:        "misconfig",
			Severity:    "critical",
			Confidence:  "high",
			Target:      target + rule.LoginPath,
			Description: fmt.Sprintf("login succeeded at %s using a well-known default credential pair (%s)", rule.LoginPath, rule.Username),
			Evidence: map[string]string{
				"login_path": rule.LoginPath,
				"username":   rule.Username,
				"request":    detectors.FormatRequest(req.Method, req.URL.String(), req.Header, []byte(form)),
				"response":   detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			},
		})
	}
	return findings, nil
}

// loginSucceeded reports whether a default-credential POST looks like it
// authenticated: the client's followed redirect chain landed away from the
// login path it started at, or the response set a session cookie.
func loginSucceeded(resp *http.Response, loginPath string) bool {
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Path != loginPath {
		return true
	}
	return len(resp.Header.Values("Set-Cookie")) > 0
}

// probeBaseline fetches baselineCanaryPath once, to give
// looksLikeBaselinePage something to compare real probes against. A
// request error just leaves baselineFetched false — every check then runs
// unsuppressed, same as before this existed.
func (d *Detector) probeBaseline(ctx context.Context, target, host, authToken string) {
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, baselineCanaryPath, authToken, nil, nil)
	if err != nil {
		return
	}
	d.baselineFetched = true
	d.baselineStatus = resp.StatusCode
	d.baselineBody = body
	d.baselineRequestEvidence = detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil)
	d.baselineResponseEvidence = detectors.FormatResponse(resp.StatusCode, resp.Header, body)
}

// looksLikeBaselinePage reports whether status/body look like the same
// generic response baselineCanaryPath got: same status code and body
// length (after excluding each side's own echoed path — see
// bodyLengthExcluding) within a small tolerance. Real distinct content (an
// actual exposed .env file, a real Swagger UI, a real directory listing)
// differs from a generic error/WAF-block page by far more than the
// boilerplate a target might echo back (the requested path, a request ID)
// — this is deliberately a coarse, cheap heuristic, not exact-body dedup.
// path is the specific path this probe requested (rule.Path,
// baselineCanaryPath, ""'s root, ...) — live testing against a real
// Akamai-fronted target found that comparing raw body length alone
// under-suppressed: the block page echoes the requested path into its own
// text, so a long canary path produces a longer baseline body than a real
// target's short paths (e.g. "/debug"), pushing genuinely-identical block
// pages outside a length-only tolerance (see
// docs/13-implementation-plan-ph4.md's Step 4 live-verification notes).
// Only meaningful when the canary itself came back non-404 — see Run's
// comment on why a 404 baseline never suppresses anything.
func (d *Detector) looksLikeBaselinePage(status int, body []byte, path string) bool {
	if !d.baselineFetched || !suspiciousBaselineStatuses[d.baselineStatus] || status != d.baselineStatus {
		return false
	}
	probeAdjusted := bodyLengthExcluding(body, strings.Trim(path, "/"))
	baselineAdjusted := bodyLengthExcluding(d.baselineBody, strings.Trim(baselineCanaryPath, "/"))
	diff := probeAdjusted - baselineAdjusted
	if diff < 0 {
		diff = -diff
	}
	tolerance := baselineAdjusted / 10
	if tolerance < 32 {
		tolerance = 32
	}
	return diff <= tolerance
}

// bodyLengthExcluding returns body's length minus every occurrence of
// needle — a cheap way to discount a reflected request path before
// comparing two otherwise-identical block-page bodies of different
// requested-path lengths. needle == "" (root) is a no-op.
func bodyLengthExcluding(body []byte, needle string) int {
	if needle == "" {
		return len(body)
	}
	return len(body) - strings.Count(string(body), needle)*len(needle)
}

// doRequest fires one request and records the outcome against hostErrors.
// The returned response's body has already been drained and closed; body is
// returned as a byte slice for matcher convenience. The built *http.Request
// is also returned so callers can render Finding.Evidence's raw-request
// entry without reconstructing it.
func (d *Detector) doRequest(ctx context.Context, method, target, host, path, authToken string, headers map[string]string, reqBody io.Reader) (*http.Request, *http.Response, []byte, error) {
	fullURL := strings.TrimRight(target, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("building request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		d.hostErrors.RecordError(host)
		return nil, nil, nil, fmt.Errorf("fetching %s: %w", fullURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		d.hostErrors.RecordError(host)
		return nil, nil, nil, fmt.Errorf("reading response body: %w", err)
	}
	d.hostErrors.RecordSuccess(host)
	return req, resp, body, nil
}

func hostOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing target URL: %w", err)
	}
	return u.Host, nil
}

func containsAny(body []byte, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(string(body), kw) {
			return true
		}
	}
	return false
}

// containsAnyFold is containsAny's case-insensitive counterpart — needed for
// DirListingMarkers, which (unlike ExposedPaths' secret/hash-format
// keywords) vary in case across real servers (Apache/nginx "Index of /" vs.
// some configs' "index of /").
func containsAnyFold(body []byte, keywords []string) bool {
	s := string(body)
	for _, kw := range keywords {
		if strings.Contains(strings.ToLower(s), strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// pathOrRoot renders "" as "/" for Finding.Description readability — every
// other caller of sanitizeID/target-joining already treats "" as root
// correctly, this is purely a display concern.
func pathOrRoot(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func matchAny(body []byte, patterns []*regexp.Regexp) (string, bool) {
	for _, re := range patterns {
		if re.Match(body) {
			return re.String(), true
		}
	}
	return "", false
}

// sanitizeID turns a path into a Finding-ID-safe fragment.
func sanitizeID(path string) string {
	s := strings.Trim(path, "/")
	s = strings.ReplaceAll(s, "/", "-")
	if s == "" {
		return "root"
	}
	return s
}
