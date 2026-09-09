// Package misconfig implements the misconfiguration detector: fixed
// built-in rule tables (exposed paths, directory listing, comment leaks,
// missing security headers, disallowed HTTP methods, CORS misconfiguration,
// verbose error messages, default credentials) checked against a single
// target.
package misconfig

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/uniformwall"
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

// baselineCanaryPath2 is a second guaranteed-nonexistent path, unrelated to
// baselineCanaryPath, used by detectCatchAll. One canary can't tell a
// per-path-varying catch-all (DokuWiki renders the requested page name into
// a "create this topic" page, so every path yields a slightly different
// body) apart from a real resource — its body legitimately differs from a
// canary's by the reflected path alone. Two canaries compared to each other
// can: if both nonexistent paths get the same template, a third path that
// also gets it is the catch-all, not a find. Same alphanumeric-only
// discipline as baselineCanaryPath (see its comment).
const baselineCanaryPath2 = "/hackerfivecanarytwo5b1d84e0"

// suspiciousBaselineStatuses are the status codes a guaranteed-nonexistent
// canary path returning them actually suggests interception (a WAF/
// bot-protection/auth layer), not the application's own routing. Used for
// the top-level "misconfig-waf-blocked" note and by
// looksLikeInterceptedPage (root-only checks) — NOT by looksLikeBaselinePage
// itself, which applies regardless of status (see its own doc comment for
// why: a 200 canary is a legitimate suppression signal for path-comparative
// checks, just not proof of interception). A 404 canary never triggers
// either path: it's the expected, harmless outcome for most speculative
// probes, not a signal on its own.
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

// notServedStatus reports whether a response status means "this is not
// evidence the path is actually served": a 404 (not found), a 429 throttle,
// or any 5xx (the origin or a gateway failed to answer). A keyword or
// banner match inside such a body is noise — the response is a generic
// error/throttle page, not the resource the rule is looking for. Closes the
// recurring exposed-path false-positive family: 404 (partners.shopify.com,
// LT-2), and 429 after sustained scanning tripped a CDN rate limiter whose
// body still matched exposed-path keywords (shop.app, LT-73). 5xx is
// excluded here for exposed-path / dir-listing checks specifically; the
// verbose-error check keeps 5xx (a 500 stack trace is exactly what it
// wants) and only drops 429.
func notServedStatus(status int) bool {
	return status == http.StatusNotFound ||
		status == http.StatusTooManyRequests ||
		status >= 500
}

// bodyLenWithinTolerance reports whether two body lengths are close enough
// to be the same generic page — the 10%-or-32-bytes tolerance
// looksLikeBaselinePage already uses, factored out for the LT-69
// disallowed-method baseline-diff.
func bodyLenWithinTolerance(a, b int) bool {
	tol := a / 10
	if tol < 32 {
		tol = 32
	}
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= tol
}

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

	// baselineCatchAll is set once by detectCatchAll when a second
	// guaranteed-nonexistent path also returns 2xx with the same template
	// shape as the first — i.e. the host serves a real page for any path
	// (DokuWiki / SPA / soft-404 catch-all). checkExposedPaths /
	// checkDirListing / checkVerboseErrors then require a probe body to
	// differ from that template by more than the two canaries differ from
	// each other before reporting (LT-104).
	baselineCatchAll        bool
	baselineCatchAllChecked bool
	baselineBody2           []byte
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
		// matching meaningless. Surfaced once here; comment-leak/
		// missing-header findings below are additionally suppressed
		// wherever root's own response also matches this shape (see
		// looksLikeInterceptedPage). Exposed-path/dir-listing/
		// verbose-error findings use the broader looksLikeBaselinePage
		// instead, which suppresses regardless of whether this top-level
		// note fired at all — CORS/disallowed-method/default-credential
		// checks aren't fooled by response body content the same way, so
		// they still run and report normally regardless.
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

	d.detectCatchAll(ctx, target, host, authToken)
	if d.baselineCatchAll {
		findings = append(findings, detectors.Finding{
			ID:         "misconfig-soft-404-catchall",
			Type:       "misconfig",
			Severity:   "info",
			Confidence: "medium",
			Target:     target,
			Description: fmt.Sprintf(
				"two unrelated guaranteed-nonexistent paths (%s, %s) both returned status %d with a full page body — this host serves a catch-all/soft-404 for any path, so exposed-path, directory-listing and verbose-error checks below require a probe response to differ structurally from that template before reporting (LT-104)",
				baselineCanaryPath, baselineCanaryPath2, d.baselineStatus),
			Evidence: map[string]string{
				"baseline_path":   baselineCanaryPath,
				"baseline_path_2": baselineCanaryPath2,
				"baseline_status": fmt.Sprintf("%d", d.baselineStatus),
			},
		})
	}

	type check func(context.Context, string, string, string) ([]detectors.Finding, error)

	// Product-fingerprint checks are each one to a few requests and each
	// identifies a specific outdated product plus its known CVEs — the
	// highest-value output this detector produces. They run first, and are
	// deliberately NOT gated by the host-error breaker below. Ordered last (as
	// they were before LT-113), a burst of connection errors from the heavier
	// probe checks — checkDisallowedMethods fires PUT/DELETE/PATCH plus a
	// comparison GET; checkDefaultCreds POSTs ~10 login attempts — would push
	// the host past hosterrors.DefaultThreshold, ShouldSkip would trip, the
	// loop would `break`, and a cleanly-fingerprinted Dolibarr / Nextcloud /
	// phpMyAdmin / Webmin host would silently produce nothing (observed live
	// on erp/ixn.nettix.com.pe, docs/follow-up.md LT-113). A per-target
	// context deadline still stops them.
	priorityChecks := []check{
		d.checkWPUserEnum,
		d.checkDolibarrOutdated,
		d.checkNextcloudStatus,
		d.checkPhpMyAdmin,
		d.checkWebmin,
	}
	// Standard checks are the broader probes (many requests each). They keep
	// the host-error breaker: once a host has failed DefaultThreshold requests
	// in a row, continuing to probe it is both pointless and impolite.
	standardChecks := []check{
		d.checkExposedPaths,
		d.checkDirListing,
		d.checkCommentLeaks,
		d.checkMissingHeaders,
		d.checkDisallowedMethods,
		d.checkCORS,
		d.checkVerboseErrors,
		d.checkDefaultCreds,
	}

	// run one check, folding its result into findings. A non-nil error is
	// non-fatal: no built-in check returns one today, and if one ever starts
	// to, that is a fault in that single check — skip its results and keep
	// going, rather than forfeiting every remaining check for this target as
	// the pre-LT-113 loop did (`return findings, err`). Genuine context
	// cancellation is caught by the ctx.Err() guards at the call sites.
	run := func(c check) {
		fs, err := c(ctx, target, host, authToken)
		if err != nil {
			return
		}
		findings = append(findings, fs...)
	}

	for _, c := range priorityChecks {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		run(c)
	}
	for _, c := range standardChecks {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		if d.hostErrors.ShouldSkip(host) {
			break
		}
		run(c)
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
		if notServedStatus(resp.StatusCode) {
			continue // 404 / 429 / 5xx — a generic error page, not an exposed resource (LT-73)
		}
		if !containsAny(body, rule.Keywords) {
			continue
		}
		if d.looksLikeBaselinePage(resp.StatusCode, body, rule.Path) ||
			d.looksLikeCatchAllServed(resp.StatusCode, body, rule.Path) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-exposed-path-%s", sanitizeID(rule.Path)),
			Type:        "misconfig",
			Severity:    rule.Severity,
			Confidence:  "high",
			Target:      req.URL.String(),
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
		if notServedStatus(resp.StatusCode) {
			continue // 404 / 429 / 5xx — not a served directory listing (LT-73)
		}
		if !containsAnyFold(body, DirListingMarkers) {
			continue
		}
		if d.looksLikeBaselinePage(resp.StatusCode, body, path) ||
			d.looksLikeCatchAllServed(resp.StatusCode, body, path) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-dir-listing-%s", sanitizeID(path)),
			Type:        "misconfig",
			Severity:    "low",
			Confidence:  "high",
			Target:      req.URL.String(),
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
	// Refresh the baseline immediately before evaluating root's response,
	// not just the one captured at Run's start — live testing found a
	// real target whose WAF engaged mid-scan (the start-of-run canary got
	// through with 200; the WAF started blocking with 403 partway through
	// the same run), leaving this check comparing root against a baseline
	// that no longer reflected the target's live behavior. See
	// looksLikeInterceptedPage's doc comment for why this only matters for
	// root-only checks, not exposed-path/dir-listing/verbose-error.
	d.probeBaseline(ctx, target, host, authToken)

	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, "", authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	if d.looksLikeInterceptedPage(resp.StatusCode, body) {
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
	// See checkCommentLeaks' identical refresh for why: a stale
	// start-of-run baseline can miss a WAF that only engages partway
	// through a scan.
	d.probeBaseline(ctx, target, host, authToken)

	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, "", authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	if d.looksLikeInterceptedPage(resp.StatusCode, body) {
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

	// LT-47 (docs/follow-up.md): a present-but-weak Strict-Transport-Security
	// is a real misconfiguration the missing-header rule above can't catch (it
	// only checks presence). "hsts" is on the decision engine's
	// nonActionableTech denylist on the premise that the native check owns
	// HSTS entirely — so grade max-age here rather than leaving it to a nuclei
	// template that denylist would otherwise be the sole check for.
	if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
		if maxAge, hasPreload, ok := parseHSTSMaxAge(hsts); ok && maxAge < weakHSTSMinMaxAge {
			desc := fmt.Sprintf("Strict-Transport-Security max-age is %d seconds, below the recommended minimum of %d (1 year)", maxAge, weakHSTSMinMaxAge)
			if hasPreload {
				desc += "; the response also sends the preload directive, which the HSTS preload list rejects below max-age=31536000"
			}
			findings = append(findings, detectors.Finding{
				ID:          "misconfig-weak-hsts-max-age",
				Type:        "misconfig",
				Severity:    "low",
				Confidence:  "high",
				Target:      target,
				Description: desc,
				Evidence: map[string]string{
					"header":   "Strict-Transport-Security",
					"observed": hsts,
					"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
					"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
				},
			})
		}
	}
	return findings, nil
}

// weakHSTSMinMaxAge is the max-age (seconds) below which a present
// Strict-Transport-Security header is graded weak — one year, the value the
// HSTS preload list requires and the common hardening-guide floor.
const weakHSTSMinMaxAge = 31536000

// parseHSTSMaxAge pulls the max-age (seconds) and whether a preload directive
// is present out of a Strict-Transport-Security header value. ok is false
// when the header carries no parseable max-age token at all (a malformed
// header is not graded here). A "max-age=0" (HSTS explicitly disabled)
// parses fine and is caught by the < weakHSTSMinMaxAge comparison.
func parseHSTSMaxAge(v string) (maxAge int, hasPreload bool, ok bool) {
	for _, part := range strings.Split(v, ";") {
		token := strings.ToLower(strings.TrimSpace(part))
		switch {
		case token == "preload":
			hasPreload = true
		case strings.HasPrefix(token, "max-age"):
			eq := strings.IndexByte(token, '=')
			if eq < 0 {
				continue
			}
			n, err := strconv.Atoi(strings.TrimSpace(strings.Trim(strings.TrimSpace(token[eq+1:]), `"`)))
			if err != nil {
				continue
			}
			maxAge, ok = n, true
		}
	}
	return maxAge, hasPreload, ok
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
		if looksLikeKnownWAFBlockPage(body) {
			continue // a WAF block page served for this verb too — not an accept
		}
		if d.methodResponseMatchesGET(ctx, target, host, rule.Path, authToken, resp, body) {
			continue // LT-69: same status + body shape as a plain GET, no mutate signal
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-method-%s-%s", strings.ToLower(rule.Method), sanitizeID(rule.Path)),
			Type:        "misconfig",
			Severity:    "medium",
			Confidence:  "high",
			Target:      req.URL.String(),
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

// methodResponseMatchesGET reports whether a disallowed-method probe's
// response is indistinguishable from a plain GET of the same path — the
// LT-69 false-positive shape: a CDN / static-origin (www.shopify.com, hit
// live) serves the same page for PUT/DELETE/PATCH as for GET, which the
// status-only rejected() check reads as "method accepted". A method that
// really was handled differs from a read: a created/accepted/no-content
// status, an Allow header, or a Location. Absent any of those, if the
// method response's status and body shape match a GET of the same path, the
// server isn't routing the verb at all.
func (d *Detector) methodResponseMatchesGET(ctx context.Context, target, host, path, authToken string, methodResp *http.Response, methodBody []byte) bool {
	// Only a success-shaped response can be "the same static page served for
	// every verb" (the LT-69 shape). A 500 the disallowed method drew is the
	// origin app itself erroring — kept as a real signal, per LT-2's own
	// reasoning — so it's never suppressed here.
	if methodResp.StatusCode < 200 || methodResp.StatusCode >= 400 {
		return false
	}
	switch methodResp.StatusCode {
	case http.StatusCreated, http.StatusAccepted, http.StatusNoContent, http.StatusResetContent:
		return false // a distinct mutate outcome — treat as a real accept
	}
	if methodResp.Header.Get("Location") != "" || methodResp.Header.Get("Allow") != "" {
		return false
	}
	_, getResp, getBody, err := d.doRequest(ctx, http.MethodGet, target, host, path, authToken, nil, nil)
	if err != nil {
		return false // can't compare — fall back to the status-only signal
	}
	if getResp.StatusCode != methodResp.StatusCode {
		return false
	}
	return bodyLenWithinTolerance(len(getBody), len(methodBody))
}

// rejected reports whether status is one of the expected "method not
// allowed" signals — anything else means the method appears to be accepted.
// 404 counts too: many routers (e.g. Rails, which this check has hit live —
// partners.shopify.com) serve the same generic catch-all 404 page for a
// path+method combination that isn't routed at all, indistinguishable from
// the response to a nonexistent path under any method. That's evidence the
// method wasn't handled, not that it was accepted.
//
// 502/503/504 count too (docs/follow-up.md LT-2, live-confirmed against
// nettix.com.pe): a reverse proxy/load balancer returning Bad
// Gateway/Service Unavailable/Gateway Timeout means the request never
// reached — or never got a real answer from — the origin application at
// all, so there's no basis for calling the method "accepted." 500 is
// deliberately NOT included here: unlike the other three, it's the
// origin application itself reporting a failure, which is at least as
// consistent with "the app tried to handle this method and broke" (still
// evidence it wasn't rejected outright, and arguably an interesting signal
// in its own right) as with an infrastructure-level non-response.
//
// 401 and 407 count too, via isAuthWallStatus (docs/follow-up.md LT-120,
// live-confirmed against agent.aalberts.com — HTTP Basic auth returning 401
// to every request, PUT/DELETE/PATCH included): a 401/407 is the auth layer
// refusing the request before the origin ever sees the verb, exactly the
// same "not accepted" signal 403 already stood for here.
func rejected(status int) bool {
	if isAuthWallStatus(status) {
		return true
	}
	return status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented ||
		status == http.StatusNotFound ||
		status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// isAuthWallStatus reports whether status is one an auth/proxy layer
// returns to say "I refused this before the origin app handled it" —
// 401 Unauthorized, 403 Forbidden, 407 Proxy Authentication Required.
// Shared by rejected() (a verb drawing one of these was rejected, not
// accepted — LT-120) and checkCORS's severity down-rank (a CORS finding
// observed only on such a response can't be read cross-origin, so its
// evidence doesn't support a high — LT-121).
func isAuthWallStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden ||
		status == http.StatusProxyAuthRequired
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

	severity, confidence := "high", "high"
	description := "target reflects an arbitrary Origin (or uses a wildcard) while also allowing credentials, letting any site make authenticated cross-origin requests"
	// LT-121: the misconfigured headers were seen only on an auth-wall
	// response (401/403/407 — e.g. agent.aalberts.com, uniformly HTTP Basic
	// auth). A cross-origin caller still can't read that body, so this
	// evidence doesn't support a high; down-rank and flag it for
	// verification against an authenticated 200 rather than suppressing it —
	// the same misconfig may well extend to the real API behind the wall.
	if isAuthWallStatus(resp.StatusCode) {
		severity, confidence = "medium", "medium"
		description += fmt.Sprintf(" — but observed only on an auth-walled response (status %d), which a cross-origin caller cannot read; verify the same headers against an authenticated 200 before treating this as high", resp.StatusCode)
	}

	return []detectors.Finding{{
		ID:          "misconfig-cors",
		Type:        "misconfig",
		Severity:    severity,
		Confidence:  confidence,
		Target:      target,
		Description: description,
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
		if resp.StatusCode == http.StatusTooManyRequests {
			continue // a throttle page's body is not a verbose error (LT-73); 5xx is kept — a 500 stack trace is the point
		}
		pattern, matched := matchAny(body, verboseErrorRegexes)
		if !matched {
			continue
		}
		if d.looksLikeBaselinePage(resp.StatusCode, body, rule.Path) ||
			d.looksLikeCatchAllServed(resp.StatusCode, body, rule.Path) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-verbose-error-%s", sanitizeID(rule.Path)),
			Type:        "misconfig",
			Severity:    "medium",
			Confidence:  "high",
			Target:      req.URL.String(),
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

var wpUserSlugRe = regexp.MustCompile(`"slug"\s*:\s*"([^"]{1,80})"`)

// checkWPUserEnum flags an unauthenticated WordPress REST user listing at
// WPUserEnumPath. A finding requires all of: HTTP 200, a JSON content type,
// a body that is a non-empty JSON array, and every wpUserObjectMarkers key
// present — the combination that distinguishes a real user array from
// WordPress's hardened "rest_user_cannot_view" response (which is also 200
// JSON on some setups but is an object without "slug"). The disclosed slugs
// are valid login names; see WPUserEnumPath's doc comment.
func (d *Detector) checkWPUserEnum(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, WPUserEnumPath, authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil // 401/403 (locked down), 404 (not WordPress), 5xx — no listing
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 3 || trimmed[0] != '[' {
		return nil, nil // not a JSON array ("[]" is len 2 and also excluded)
	}
	if !containsAll(body, wpUserObjectMarkers) {
		return nil, nil
	}
	// No looksLikeBaselinePage / looksLikeCatchAllServed guard here: the
	// checks above are a hard product signature (200 + JSON content type + a
	// JSON array carrying every wpUserObjectMarkers key) that a WAF block
	// page or a soft-404 catch-all cannot satisfy. Adding the guard only
	// created false negatives — a Dolibarr/Nextcloud/WordPress host that
	// serves its real app for every path (its own login/redirect behaviour)
	// had its confirmed-product finding suppressed because the canary probe
	// landed on that same real page (LT-113, live on erp/ixn.nettix.com.pe).

	var slugs []string
	seen := map[string]bool{}
	for _, m := range wpUserSlugRe.FindAllSubmatch(body, -1) {
		s := string(m[1])
		if !seen[s] {
			seen[s] = true
			slugs = append(slugs, s)
		}
	}

	desc := fmt.Sprintf("the WordPress REST API at %s returns the site's user list without authentication, disclosing valid login names usable for credential stuffing or password spraying against wp-login.php", WPUserEnumPath)
	if len(slugs) > 0 {
		desc = fmt.Sprintf("%s (%d account(s): %s)", desc, len(slugs), strings.Join(slugs, ", "))
	}
	return []detectors.Finding{{
		ID:          "misconfig-wordpress-user-enumeration",
		Type:        "misconfig",
		Severity:    "medium",
		Confidence:  "high",
		Target:      req.URL.String(),
		Description: desc,
		Evidence: map[string]string{
			"path":      WPUserEnumPath,
			"status":    fmt.Sprintf("%d", resp.StatusCode),
			"usernames": strings.Join(slugs, ", "),
			"request":   detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response":  detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		},
	}}, nil
}

// dolibarrTitleVersionRe pulls the true Dolibarr version out of the login
// page's <title>, which upstream deliberately suffixes with " @ <version>"
// for exactly this purpose — htdocs/core/tpl/login.tpl.php:
// "We must keep the @, some tools use it to know it is login page and find
// true dolibarr version." $titletruedolibarrversion there is bare
// DOL_VERSION with no MAIN_HIDE_VERSION guard, so this is reliable when the
// root URL lands on the login form.
var dolibarrTitleVersionRe = regexp.MustCompile(`@ (?:Doli[A-Za-z]+ )?(\d+\.\d+\.\d+)`)

// dolibarrAssetVersionRe is the fallback: every themed CSS/JS URL in a
// Dolibarr <head> carries "&version=<DOL_VERSION>" (main.inc.php builds
// $themeparam that way). Served markup HTML-entity-encodes the ampersands,
// hence the optional "amp;".
var dolibarrAssetVersionRe = regexp.MustCompile(`[?&](?:amp;)?version=(\d+\.\d+\.\d+)`)

// checkDolibarrOutdated flags a Dolibarr install whose self-reported version
// falls in the affected range of one or more published CVEs (the Dolibarr
// rows of KnownVulnerableVersions). It mirrors checkWPUserEnum's shape — one
// fixed request, a hard "is this the product" gate (the author <meta>), a
// version taken from the app's own output, and an AND against a curated
// table — so it stays immune to the
// tag-scoped-corpus time budget that can skip the equivalent nuclei CVE
// templates (docs/follow-up.md, LT-98). No version parsed ⇒ no finding: the
// check never guesses a version it could not read.
func (d *Detector) checkDolibarrOutdated(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, "/", authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(DolibarrAuthorMeta)) {
		return nil, nil // root not served, or not Dolibarr
	}
	// No baseline/catch-all guard: DolibarrAuthorMeta plus a parsed version
	// is a hard product signature no WAF/interstitial page carries. Dolibarr
	// itself redirects every unauthenticated path to the login page, so the
	// canary probe lands on the very page this check reads — guarding on it
	// suppressed the finding on a real, outdated, internet-facing instance
	// (LT-113, live on erp/ixn.nettix.com.pe).

	version := firstSubmatchString(dolibarrTitleVersionRe, body)
	if version == "" {
		version = firstSubmatchString(dolibarrAssetVersionRe, body)
	}
	if version == "" {
		return nil, nil // confirmed Dolibarr, but this response did not disclose a version
	}

	matched, severity := matchKnownCVEs(ProductDolibarr, version)
	if len(matched) == 0 {
		return nil, nil // a current-enough release — nothing to report
	}
	ids, details := formatCVEDetails(matched)

	desc := fmt.Sprintf(
		"Dolibarr %s is running here (version read from the login page); it trails the current stable release %s and falls within the affected range of %d published CVE(s): %s. An authenticated or admin-level foothold turns the higher-severity entries into remote code execution or SQL injection.",
		version, DolibarrLatestStable, len(matched), strings.Join(details, "; "))

	return []detectors.Finding{{
		ID:          "misconfig-dolibarr-outdated",
		Type:        "misconfig",
		Severity:    severity,
		Confidence:  "high",
		Target:      req.URL.String(),
		Description: desc,
		Evidence: map[string]string{
			"product":       "Dolibarr",
			"version":       version,
			"latest_stable": DolibarrLatestStable,
			"cves":          strings.Join(ids, ", "),
			"request":       detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response":      detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		},
	}}, nil
}

// firstSubmatchString returns the first capture group of re against body, or
// "" when there is no match.
func firstSubmatchString(re *regexp.Regexp, body []byte) string {
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}

// versionLessThan reports whether dotted-numeric version a sorts before b,
// comparing segment by segment with a missing trailing segment treated as 0.
// ok is false when either side is not plain dot-separated integers — the
// caller then declines to match rather than risk a bogus comparison. Same
// hand-rolled-comparator precedent as pkg/template/dsl (no semver dependency
// pulled in for four table rows).
func versionLessThan(a, b string) (less bool, ok bool) {
	as, aok := splitVersionInts(a)
	bs, bok := splitVersionInts(b)
	if !aok || !bok {
		return false, false
	}
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			return av < bv, true
		}
	}
	return false, true
}

func splitVersionInts(v string) ([]int, bool) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

// matchKnownCVEs returns every KnownVulnerableVersions row for product whose
// FixedIn release is strictly newer than detectedVersion, plus the finding
// severity that band implies: "medium" for any version-only match, bumped to
// "high" once a matched CVE scores CVSS >= 9.0. It never returns "critical" —
// the finding asserts "this host runs an affected version", not "it is
// exploitable unauthenticated right now". A detectedVersion that isn't plain
// dotted integers matches nothing (versionLessThan's ok=false path), so the
// caller reports no CVE rather than risk a bogus comparison.
func matchKnownCVEs(product, detectedVersion string) (matched []VersionCVERule, severity string) {
	severity = "medium"
	for _, rule := range KnownVulnerableVersions {
		if rule.Product != product {
			continue
		}
		if less, ok := versionLessThan(detectedVersion, rule.FixedIn); ok && less {
			matched = append(matched, rule)
			if rule.CVSS >= 9.0 {
				severity = "high"
			}
		}
	}
	return matched, severity
}

// formatCVEDetails renders matched rows for a Finding: ids is the bare CVE
// list (for the "cves" evidence entry), details is one
// "CVE-x (CVSS n.n, fixed in v[, public exploit]): summary" line each (joined
// with "; " into the description).
func formatCVEDetails(matched []VersionCVERule) (ids, details []string) {
	ids = make([]string, 0, len(matched))
	details = make([]string, 0, len(matched))
	for _, m := range matched {
		ids = append(ids, m.CVE)
		exploit := ""
		if m.ExploitPublic {
			exploit = ", public exploit"
		}
		details = append(details, fmt.Sprintf("%s (CVSS %.1f, fixed in %s%s): %s",
			m.CVE, m.CVSS, m.FixedIn, exploit, m.Summary))
	}
	return ids, details
}

var nextcloudVersionstringRe = regexp.MustCompile(`"versionstring"\s*:\s*"([^"]{1,40})"`)
var nextcloudProductnameRe = regexp.MustCompile(`"productname"\s*:\s*"([^"]{1,60})"`)

// checkNextcloudStatus flags Nextcloud's unauthenticated /status.php: always
// an information-disclosure finding (the exact build, no auth — CWE-200), and
// additionally an "outdated" finding when the disclosed versionstring is
// either an end-of-life major or below the fix line of one of the Nextcloud
// rows of KnownVulnerableVersions. Same shape as
// checkWPUserEnum/checkDolibarrOutdated — fixed path, an AND-of-JSON-keys
// product gate, version taken from the app's own output.
func (d *Detector) checkNextcloudStatus(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, NextcloudStatusPath, authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return nil, nil
	}
	if !containsAll(body, nextcloudStatusMarkers) {
		return nil, nil
	}
	// No baseline/catch-all guard — see checkWPUserEnum: the JSON-key
	// product gate above is not something a generic catch-all page returns,
	// and the guard only produced false negatives on hosts that serve a real
	// app for every path (LT-113).

	product := firstSubmatchString(nextcloudProductnameRe, body)
	if product == "" {
		product = "Nextcloud"
	}
	version := firstSubmatchString(nextcloudVersionstringRe, body)

	evidence := func() map[string]string {
		return map[string]string{
			"path":          NextcloudStatusPath,
			"status":        fmt.Sprintf("%d", resp.StatusCode),
			"productname":   product,
			"versionstring": version,
			"request":       detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response":      detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		}
	}

	verClause := ""
	if version != "" {
		verClause = fmt.Sprintf(" (%s %s)", product, version)
	}
	findings := []detectors.Finding{{
		ID:         "misconfig-nextcloud-status-disclosure",
		Type:       "misconfig",
		Severity:   "low",
		Confidence: "high",
		Target:     req.URL.String(),
		Description: fmt.Sprintf(
			"%s serves /status.php without authentication, disclosing the exact build%s. Nextcloud's hardening guide recommends restricting this endpoint — the version it leaks lets an attacker line this instance up against published advisories.",
			product, verClause),
		Evidence: evidence(),
	}}

	if version == "" {
		return findings, nil // build disclosed but not parseable — can't judge "outdated"
	}

	matched, severity := matchKnownCVEs(ProductNextcloud, version)
	major, majorOK := majorOf(version)
	eol := majorOK && major < nextcloudOldestMaintainedMajor
	if !eol && len(matched) == 0 {
		return findings, nil // a maintained, current-enough release
	}

	reasons := make([]string, 0, 2)
	if eol {
		reasons = append(reasons, fmt.Sprintf("major %d is end-of-life (maintained majors are %d and newer; current stable %s) and receives no security fixes",
			major, nextcloudOldestMaintainedMajor, NextcloudLatestStable))
	}
	ids, details := formatCVEDetails(matched)
	if len(matched) > 0 {
		reasons = append(reasons, fmt.Sprintf("it is below the fix line of %d published CVE(s): %s", len(matched), strings.Join(details, "; ")))
	}

	ev := evidence()
	ev["latest_stable"] = NextcloudLatestStable
	if len(ids) > 0 {
		ev["cves"] = strings.Join(ids, ", ")
	}
	findings = append(findings, detectors.Finding{
		ID:          "misconfig-nextcloud-outdated",
		Type:        "misconfig",
		Severity:    severity,
		Confidence:  "high",
		Target:      req.URL.String(),
		Description: fmt.Sprintf("%s %s is running here (from /status.php): %s.", product, version, strings.Join(reasons, "; and ")),
		Evidence:    ev,
	})
	return findings, nil
}

var phpMyAdminVersionRe = regexp.MustCompile(`[?&]v=(\d+\.\d+\.\d+)`)

// checkPhpMyAdmin flags an internet-reachable phpMyAdmin login page — a
// standing target for credential brute force, session attacks and
// phpMyAdmin's own CVE history, none of which a login page facing the public
// internet should be exposed to. It walks PhpMyAdminProbePaths and stops at
// the first response carrying both phpMyAdminLoginMarkers. When that response
// also discloses a version (the "?v=" cache-buster on a bundled asset URL)
// that falls below a KnownVulnerableVersions fix line, a second
// "misconfig-phpmyadmin-outdated" finding is emitted alongside the exposure
// one — same version-only severity discipline as checkDolibarrOutdated.
func (d *Detector) checkPhpMyAdmin(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	for _, path := range PhpMyAdminProbePaths {
		req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, path, authToken, nil, nil)
		if err != nil {
			continue
		}
		if notServedStatus(resp.StatusCode) {
			continue
		}
		if !containsAll(body, phpMyAdminLoginMarkers) {
			continue
		}
		// No baseline/catch-all guard — see checkWPUserEnum: phpMyAdminLoginMarkers
		// is a hard product gate, and the guard only cost real findings on
		// hosts that serve one real page for every path (LT-113).

		version := firstSubmatchString(phpMyAdminVersionRe, body)
		verClause := ""
		if version != "" {
			verClause = fmt.Sprintf(" (version %s, from an asset URL)", version)
		}
		ev := map[string]string{
			"path":     path,
			"status":   fmt.Sprintf("%d", resp.StatusCode),
			"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		}
		if version != "" {
			ev["version"] = version
		}
		findings := []detectors.Finding{{
			ID:         "misconfig-phpmyadmin-exposed",
			Type:       "misconfig",
			Severity:   "medium",
			Confidence: "high",
			Target:     req.URL.String(),
			Description: fmt.Sprintf(
				"a phpMyAdmin login page is served at %s with no network restriction%s — internet-facing phpMyAdmin is a persistent target for credential brute force, session fixation and phpMyAdmin's own steady stream of CVEs, and should sit behind a VPN or IP allow-list.",
				path, verClause),
			Evidence: ev,
		}}

		if matched, severity := matchKnownCVEs(ProductPhpMyAdmin, version); len(matched) > 0 {
			ids, details := formatCVEDetails(matched)
			outEv := map[string]string{
				"path":          path,
				"version":       version,
				"latest_stable": PhpMyAdminLatestStable,
				"cves":          strings.Join(ids, ", "),
				"request":       detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
				"response":      detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			}
			findings = append(findings, detectors.Finding{
				ID:         "misconfig-phpmyadmin-outdated",
				Type:       "misconfig",
				Severity:   severity,
				Confidence: "high",
				Target:     req.URL.String(),
				Description: fmt.Sprintf(
					"the phpMyAdmin login page at %s discloses version %s (from a bundled-asset URL); it trails the current stable release %s and falls within the affected range of %d published CVE(s): %s.",
					path, version, PhpMyAdminLatestStable, len(matched), strings.Join(details, "; ")),
				Evidence: outEv,
			})
		}
		return findings, nil
	}
	return nil, nil
}

// majorOf returns the leading integer segment of a dotted version, or ok=false
// when v is not dot-separated integers.
func majorOf(v string) (int, bool) {
	seg, ok := splitVersionInts(v)
	if !ok || len(seg) == 0 {
		return 0, false
	}
	return seg[0], true
}

// webminServerVersionRe pulls the version out of a "MiniServ/2.111" Server
// header (two- or three-segment). Case-insensitive so "miniserv/..." matches
// too.
var webminServerVersionRe = regexp.MustCompile(`(?i)MiniServ/(\d+\.\d+(?:\.\d+)?)`)

// checkWebmin flags an internet-reachable Webmin / MiniServ admin login. The
// hard gate is the "Server: MiniServ" header — the bespoke HTTP server behind
// Webmin, Usermin and Virtualmin, and nothing else — confirmed by the login
// form's session_login.cgi post target in the body. A MiniServ admin panel on
// the public internet is itself the finding (misconfig-webmin-login-exposed,
// medium); when the Server header also carries a version below a
// KnownVulnerableVersions fix line, a second misconfig-webmin-outdated finding
// is emitted. Same one-request, product-gated, table-driven shape as the other
// native version checks — no version parsed ⇒ no CVE finding.
func (d *Detector) checkWebmin(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, "/", authToken, nil, nil)
	if err != nil {
		return nil, nil
	}
	server := resp.Header.Get("Server")
	if !strings.Contains(strings.ToLower(server), strings.ToLower(WebminServerToken)) {
		return nil, nil // not MiniServ — not Webmin
	}
	if !bytes.Contains(body, []byte(webminLoginMarker)) {
		return nil, nil // MiniServ, but this response isn't the unauthenticated login page
	}
	// No baseline/catch-all guard — see checkWPUserEnum: the "Server:
	// MiniServ" header plus the login marker is a hard product gate no
	// generic catch-all carries (LT-113).

	version := firstSubmatchString(webminServerVersionRe, []byte(server))
	verClause := ""
	if version != "" {
		verClause = fmt.Sprintf(" (MiniServ/%s)", version)
	}
	ev := map[string]string{
		"server":   server,
		"status":   fmt.Sprintf("%d", resp.StatusCode),
		"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
		"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
	}
	if version != "" {
		ev["version"] = version
	}
	findings := []detectors.Finding{{
		ID:         "misconfig-webmin-login-exposed",
		Type:       "misconfig",
		Severity:   "medium",
		Confidence: "high",
		Target:     req.URL.String(),
		Description: fmt.Sprintf(
			"a Webmin/MiniServ admin login is served here%s with no network restriction — Webmin's HTTP server has a recurring history of unauthenticated and pre-auth CVEs, and a root-privileged system-administration panel should sit behind a VPN or IP allow-list, never on the open internet.",
			verClause),
		Evidence: ev,
	}}

	matched, severity := matchKnownCVEs(ProductWebmin, version)
	if len(matched) == 0 {
		return findings, nil
	}
	ids, details := formatCVEDetails(matched)
	outEv := map[string]string{
		"server":        server,
		"version":       version,
		"latest_stable": WebminLatestStable,
		"cves":          strings.Join(ids, ", "),
		"request":       detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
		"response":      detectors.FormatResponse(resp.StatusCode, resp.Header, body),
	}
	findings = append(findings, detectors.Finding{
		ID:         "misconfig-webmin-outdated",
		Type:       "misconfig",
		Severity:   severity,
		Confidence: "high",
		Target:     req.URL.String(),
		Description: fmt.Sprintf(
			"Webmin %s is running here (from the MiniServ Server header); it trails the current stable release %s and falls within the affected range of %d published CVE(s): %s.",
			version, WebminLatestStable, len(matched), strings.Join(details, "; ")),
		Evidence: outEv,
	})
	return findings, nil
}

// baselineCredUsername/Password are a definitely-wrong credential pair sent
// once per unique LoginPath before any real DefaultCreds pair — see
// loginProbeResult/loginSucceeded's doc comments for why: a bare Set-Cookie
// header used to be treated as proof of a successful login, but a real
// production site (live-tested) sets a tracking/session cookie on every
// response regardless of outcome, which false-positived a "critical"
// successful admin/admin login against what was actually a 404 routing
// error. Alphanumeric only, matching baselineCanaryPath's reasoning — not
// that it matters here (no page is expected to echo login form values back
// HTML-escaped), but keeps the convention consistent.
const (
	baselineCredUsername = "hackerfivebaselinecanary9f3c7a21"
	baselineCredPassword = "hackerfivebaselinepassword1c8e4d"
)

// loginProbeResult captures just enough of a login attempt's outcome to
// compare a real DefaultCreds pair against baselineCredUsername/Password's
// known-wrong attempt at the same path.
type loginProbeResult struct {
	finalPath  string
	statusCode int
}

func (d *Detector) checkDefaultCreds(ctx context.Context, target, host, _ string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	baselines := make(map[string]loginProbeResult, len(DefaultCreds))
	for _, rule := range DefaultCreds {
		baseline, ok := baselines[rule.LoginPath]
		if !ok {
			var err error
			baseline, err = d.probeLogin(ctx, target, host, rule.LoginPath, baselineCredUsername, baselineCredPassword)
			if err != nil {
				// No negative control for this path — skip every real pair
				// against it rather than risk a false positive with
				// nothing to compare against.
				continue
			}
			baselines[rule.LoginPath] = baseline
		}

		req, resp, body, err := d.doRequest(ctx, http.MethodPost, target, host, rule.LoginPath, "", defaultCredsHeaders, strings.NewReader(defaultCredsForm(rule)))
		if err != nil {
			continue
		}
		if !loginSucceeded(resp, baseline) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("misconfig-default-creds-%s", sanitizeID(rule.LoginPath)),
			Type:        "misconfig",
			Severity:    "critical",
			Confidence:  "high",
			Target:      req.URL.String(),
			Description: fmt.Sprintf("login succeeded at %s using a well-known default credential pair (%s)", rule.LoginPath, rule.Username),
			Evidence: map[string]string{
				"login_path":          rule.LoginPath,
				"username":            rule.Username,
				"request":             detectors.FormatRequest(req.Method, req.URL.String(), req.Header, []byte(defaultCredsForm(rule))),
				"response":            detectors.FormatResponse(resp.StatusCode, resp.Header, body),
				"baseline_final_path": baseline.finalPath,
				"baseline_status":     fmt.Sprintf("%d", baseline.statusCode),
			},
		})
	}
	return findings, nil
}

var defaultCredsHeaders = map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

func defaultCredsForm(rule DefaultCredRule) string {
	return url.Values{"username": {rule.Username}, "password": {rule.Password}}.Encode()
}

// probeLogin fires one login POST and records just its outcome shape
// (final path after any redirect chain, status code) — used both for the
// baselineCredUsername/Password negative control and, via loginSucceeded,
// compared against a real DefaultCreds pair's own probeLogin result.
func (d *Detector) probeLogin(ctx context.Context, target, host, loginPath, username, password string) (loginProbeResult, error) {
	form := url.Values{"username": {username}, "password": {password}}.Encode()
	_, resp, _, err := d.doRequest(ctx, http.MethodPost, target, host, loginPath, "", defaultCredsHeaders, strings.NewReader(form))
	if err != nil {
		return loginProbeResult{}, err
	}
	finalPath := loginPath
	if resp.Request != nil && resp.Request.URL != nil {
		finalPath = resp.Request.URL.Path
	}
	return loginProbeResult{finalPath: finalPath, statusCode: resp.StatusCode}, nil
}

// loginSucceeded reports whether a real DefaultCreds POST looks like it
// authenticated, by comparing against baseline — a POST with a known-wrong
// password at the same path (see baselineCredUsername/Password). A bare
// Set-Cookie header used to be treated as success on its own, which
// false-positived against a real production site (live-tested) that sets a
// tracking/session cookie on every response regardless of outcome —
// including a 404 routing error ("Cannot POST /admin/login"). Real success
// needs a difference from what a known-wrong pair gets: either the real
// attempt's final path differs from the known-wrong attempt's (redirected
// somewhere the failure didn't), or the real attempt's status is a
// success-shaped 2xx/3xx while the known-wrong one's isn't.
func loginSucceeded(resp *http.Response, baseline loginProbeResult) bool {
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Path != baseline.finalPath {
		return true
	}
	realIsSuccessStatus := resp.StatusCode >= 200 && resp.StatusCode < 400
	baselineIsSuccessStatus := baseline.statusCode >= 200 && baseline.statusCode < 400
	return realIsSuccessStatus && !baselineIsSuccessStatus
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
//
// Deliberately not gated on suspiciousBaselineStatuses — used only by
// checks whose entire premise is "is THIS specific path distinctively
// different from a definitely-nonexistent one" (exposed-path, dir-listing,
// verbose-error). If a real target's canary probe legitimately comes back
// 200 (a normal SPA/catch-all pattern) and a real path's response is
// shape-identical to it, that still falsifies the check's own premise
// regardless of status — live-found against a real Next.js SPA whose
// shared shell embeds the requested path in a canonical-URL tag,
// incidentally satisfying broad keyword rules like {Path: "/debug",
// Keywords: ["debug"]}/{Path: "/graphql", Keywords: ["errors"]} on every
// path via body-length correlation that matched request-path length
// byte-for-byte. See looksLikeInterceptedPage for the stricter,
// status-gated variant root-only checks need instead.
func (d *Detector) looksLikeBaselinePage(status int, body []byte, path string) bool {
	if looksLikeKnownWAFBlockPage(body) {
		return true
	}
	if !d.baselineFetched || status != d.baselineStatus {
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

// detectCatchAll runs once per Run. probeBaseline has already fetched
// baselineCanaryPath; if that came back 2xx, this fetches a second
// unrelated guaranteed-nonexistent path and sets baselineCatchAll when it
// is also 2xx, same status, and its path-adjusted body length is close to
// the first's. That is the signature of a host serving a real page for any
// path — which looksLikeBaselinePage alone can misjudge, because a template
// that renders the requested path into the page (DokuWiki's "create this
// topic" page) drifts a single canary's body away from a real probe's by
// the reflected path text. Comparing two canaries to each other removes
// that confound (LT-104).
func (d *Detector) detectCatchAll(ctx context.Context, target, host, authToken string) {
	if d.baselineCatchAllChecked {
		return
	}
	d.baselineCatchAllChecked = true
	if !d.baselineFetched || d.baselineStatus < 200 || d.baselineStatus >= 300 {
		return // a 404 (or a 401/403 WAF wall, handled separately) is not a catch-all
	}
	_, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, baselineCanaryPath2, authToken, nil, nil)
	if err != nil || resp.StatusCode != d.baselineStatus {
		return
	}
	adj1 := bodyLengthExcluding(d.baselineBody, strings.Trim(baselineCanaryPath, "/"))
	adj2 := bodyLengthExcluding(body, strings.Trim(baselineCanaryPath2, "/"))
	tol := adj1 / 4
	if tol < 256 {
		tol = 256
	}
	if absInt(adj1-adj2) > tol {
		return // the two nonexistent paths get materially different pages — not a plain catch-all
	}
	d.baselineBody2 = body
	d.baselineCatchAll = true
}

// looksLikeCatchAllServed reports whether a 2xx probe body is just the
// confirmed catch-all template with this path's name rendered into it,
// rather than a distinct resource. Only meaningful once detectCatchAll has
// set baselineCatchAll. The tolerance adapts to how much the two canaries
// themselves differ per path: a genuine resource (a real Swagger UI, a real
// directory index) sits many multiples of that variance away from the
// template; the catch-all's own per-path text substitution does not
// (LT-104).
func (d *Detector) looksLikeCatchAllServed(status int, body []byte, path string) bool {
	if !d.baselineCatchAll || status != d.baselineStatus {
		return false
	}
	adj1 := bodyLengthExcluding(d.baselineBody, strings.Trim(baselineCanaryPath, "/"))
	adj2 := bodyLengthExcluding(d.baselineBody2, strings.Trim(baselineCanaryPath2, "/"))
	adjP := bodyLengthExcluding(body, strings.Trim(path, "/"))
	tol := 3 * absInt(adj1-adj2)
	if floor := adj1 / 8; tol < floor {
		tol = floor
	}
	if tol < 512 {
		tol = 512
	}
	return absInt(adjP-adj1) <= tol && absInt(adjP-adj2) <= tol
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// looksLikeInterceptedPage is looksLikeBaselinePage's stricter counterpart
// for root-only checks (comment-leak, missing-headers). Their finding isn't
// "is this path special" — it's "what does the app's real response look
// like" — so a root response that's shape-identical to canary's is only
// grounds for suppression when the canary itself signals interception (a
// WAF/bot-layer/auth-wall — suspiciousBaselineStatuses), not merely because
// the app happens to serve the same page everywhere. A real, sitewide issue
// (e.g. a debug comment baked into a shared header/footer template) must
// not be suppressed just because it also shows up on a fake path — if
// anything that makes it a *more* meaningful finding, not a false one.
//
// knownWAFBlockPageMarkers bypasses that whole comparison, and is checked
// first, independent of status/canary state: live testing against a real
// Akamai-fronted target found the canary-comparison technique's own
// assumption doesn't hold universally — root ("/") was consistently
// WAF-blocked (403) while a random nonexistent path was consistently
// allowed through (200), confirmed via five repeated request pairs, not
// timing flakiness. A canary genuinely cannot stand in for root against a
// WAF with path-specific rules like this one. Recognizing the block page's
// own content directly sidesteps the whole comparison.
func (d *Detector) looksLikeInterceptedPage(status int, body []byte) bool {
	if looksLikeKnownWAFBlockPage(body) {
		return true
	}
	if !d.baselineFetched || !suspiciousBaselineStatuses[d.baselineStatus] {
		return false
	}
	return d.looksLikeBaselinePage(status, body, "")
}

// looksLikeKnownWAFBlockPage delegates to pkg/uniformwall, the single
// shared copy of the block-page marker list (Phase 7 Step 4 D6). The list
// originated here — narrow by design, only Akamai's live-confirmed
// "edgesuite" marker, expand only with the same live-confirmation
// discipline (CLAUDE.md's "flag doubtful matchers instead of guessing").
func looksLikeKnownWAFBlockPage(body []byte) bool {
	return uniformwall.LooksLikeKnownBlockPage(body)
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

// containsAll is containsAny's AND counterpart — every keyword must appear.
// Used by checkWPUserEnum, whose matcher needs all of "id"/"slug"/"name"
// present to tell a real user array from WordPress's hardened response.
func containsAll(body []byte, keywords []string) bool {
	s := string(body)
	for _, kw := range keywords {
		if !strings.Contains(s, kw) {
			return false
		}
	}
	return true
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
