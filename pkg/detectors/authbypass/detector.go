// Package authbypass implements the API auth-bypass detector: missing
// authentication, JWT alg:none/signature-stripping bypass, an offline JWT
// weak-secret dictionary check, a bounded rate-limit-signal probe, token
// reuse across two accounts, and broken-session (logout-then-reuse)
// detection. See docs/11-implementation-plan-ph2.md Step 1 for the full
// design, including why the roadmap's literal "rate limiting bypass" check
// is not built as a real credential-guessing sequence.
package authbypass

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// rateLimitProbeCount is the fixed, capped request count
// checkRateLimitSignal sends — never a real credential-guessing sequence,
// see rules.go's rateLimitProbeUsername/Password doc comment.
const rateLimitProbeCount = 10

// Detector runs the built-in API auth-bypass checks against a target.
type Detector struct {
	client *httpclient.Client

	// hostErrors stops a run early once the target host crosses its
	// consecutive-error threshold, same as idor.Detector/misconfig.Detector.
	hostErrors *hosterrors.Cache

	authHeaderName   string
	authHeaderFormat string
	loginPaths       []string
	logoutPaths      []string
}

// Option configures a Detector at construction time. Mirrors
// idor.Option's shape exactly — same convention, not a new pattern.
type Option func(*Detector)

// WithAuthHeader overrides the header name/value format checkRateLimitSignal
// and checkBrokenSession use to carry ownerToken — not every real target
// speaks "Authorization: Bearer <token>" (e.g. vAPI's
// "Authorization-Token: base64(username:password)"). Same shape and
// same-argument-left-"" default-preserving behavior as
// idor.Detector.WithAuthHeader.
func WithAuthHeader(name, format string) Option {
	return func(d *Detector) {
		if name != "" {
			d.authHeaderName = name
		}
		if format != "" {
			d.authHeaderFormat = format
		}
	}
}

// WithLoginPaths overrides LoginPaths' fixed default candidate list —
// live-verified (docs/11-implementation-plan-ph2.md Step 5) to match
// neither crAPI's nor vAPI's real login routes, so checkRateLimitSignal is
// otherwise a no-op against both of this project's own lab targets. An
// empty/nil paths leaves LoginPaths' package default in place.
func WithLoginPaths(paths []string) Option {
	return func(d *Detector) {
		if len(paths) > 0 {
			d.loginPaths = paths
		}
	}
}

// WithLogoutPaths is WithLoginPaths' checkBrokenSession counterpart,
// overriding LogoutPaths' fixed default.
func WithLogoutPaths(paths []string) Option {
	return func(d *Detector) {
		if len(paths) > 0 {
			d.logoutPaths = paths
		}
	}
}

// New constructs a Detector.
func New(client *httpclient.Client, opts ...Option) *Detector {
	d := &Detector{
		client:           client,
		hostErrors:       hosterrors.New(hosterrors.DefaultThreshold),
		authHeaderName:   DefaultAuthHeaderName,
		authHeaderFormat: DefaultAuthHeaderFormat,
		loginPaths:       LoginPaths,
		logoutPaths:      LogoutPaths,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Run checks target against every built-in auth-bypass check and returns
// every finding. ownerToken is required for the JWT and rate-limit-signal
// checks; otherToken, if non-empty, additionally enables the token-reuse
// check (mirrors idor.Detector's two-account baseline shape). protectedPaths
// is the candidate endpoint list checkMissingAuth/checkJWTAlgNone/
// checkTokenReuse/checkBrokenSession fire against.
func (d *Detector) Run(ctx context.Context, target, ownerToken, otherToken string, protectedPaths []string) ([]detectors.Finding, error) {
	host, err := hostOf(target)
	if err != nil {
		return nil, fmt.Errorf("authbypass: %w", err)
	}

	var findings []detectors.Finding
	// checkBrokenSession is deliberately last: it logs the owner session out,
	// which would otherwise poison every check after it that also relies on
	// ownerToken still being valid within this same Run call.
	checks := []func(context.Context, string, string, string, string, []string) ([]detectors.Finding, error){
		d.checkMissingAuth,
		d.checkJWTAlgNone,
		d.checkJWTWeakSecret,
		d.checkRateLimitSignal,
		d.checkTokenReuse,
		d.checkBrokenSession,
	}
	for _, check := range checks {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		if d.hostErrors.ShouldSkip(host) {
			break
		}
		fs, err := check(ctx, target, host, ownerToken, otherToken, protectedPaths)
		if err != nil {
			return findings, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

// checkMissingAuth fires each protectedPaths entry with no Authorization
// header at all — a protected endpoint accepting the request (200) instead
// of rejecting it (401/403) is a real missing-authentication bug.
func (d *Detector) checkMissingAuth(ctx context.Context, target, host, _, _ string, protectedPaths []string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, path := range protectedPaths {
		req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, path, "")
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("authbypass-missing-auth-%s", sanitizeID(path)),
			Type:        "authbypass",
			Severity:    "high",
			Confidence:  "high",
			Target:      req.URL.String(),
			Description: fmt.Sprintf("%s returned status 200 with no Authorization header at all — endpoint accepts unauthenticated requests", path),
			Evidence: map[string]string{
				"path":     path,
				"status":   strconv.Itoa(resp.StatusCode),
				"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
				"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
			},
		})
	}
	return findings, nil
}

// checkJWTAlgNone tries the alg:none and bare-signature-stripping bypass
// variants of ownerToken against each protectedPaths entry.
func (d *Detector) checkJWTAlgNone(ctx context.Context, target, host, ownerToken, _ string, protectedPaths []string) ([]detectors.Finding, error) {
	if ownerToken == "" || !looksLikeJWT(ownerToken) {
		return nil, nil
	}
	algNone, sigStripped, err := tamperAlgNone(ownerToken)
	if err != nil {
		return nil, nil // not a well-formed JWT header — nothing to tamper
	}

	var findings []detectors.Finding
	for _, path := range protectedPaths {
		for variant, tampered := range map[string]string{"alg-none": algNone, "signature-stripped": sigStripped} {
			req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, path, tampered)
			if err != nil {
				continue
			}
			if resp.StatusCode != http.StatusOK {
				continue
			}
			findings = append(findings, detectors.Finding{
				ID:          fmt.Sprintf("authbypass-jwt-%s-%s", variant, sanitizeID(path)),
				Type:        "authbypass",
				Severity:    "critical",
				Confidence:  "high",
				Target:      req.URL.String(),
				Description: fmt.Sprintf("%s accepted a JWT tampered with the %q bypass — the server does not verify the token's signature", path, variant),
				Evidence: map[string]string{
					"path":     path,
					"variant":  variant,
					"status":   strconv.Itoa(resp.StatusCode),
					"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
					"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
				},
			})
		}
	}
	return findings, nil
}

// checkJWTWeakSecret verifies ownerToken's signature locally against every
// entry in WeakJWTSecrets. Zero HTTP requests — offline only, see rules.go's
// WeakJWTSecrets doc comment for why this must never become live guessing.
func (d *Detector) checkJWTWeakSecret(_ context.Context, target, _, ownerToken, _ string, _ []string) ([]detectors.Finding, error) {
	if ownerToken == "" || !looksLikeJWT(ownerToken) {
		return nil, nil
	}
	for _, secret := range WeakJWTSecrets {
		if !verifiesWithSecret(ownerToken, secret) {
			continue
		}
		return []detectors.Finding{{
			ID:          "authbypass-jwt-weak-secret",
			Type:        "authbypass",
			Severity:    "critical",
			Confidence:  "high",
			Target:      target,
			Description: "the provided token's HMAC signature verifies against a well-known weak secret — checked entirely offline, never sent to the server",
			Evidence: map[string]string{
				"check": "offline HMAC verification against a fixed, published wordlist — no request sent to the target for this check",
			},
		}}, nil
	}
	return nil, nil
}

// probeBody pairs one encoding of the fixed rate-limit-probe credential pair
// (rules.go's rateLimitProbeUsername/Password) with the Content-Type it
// needs.
type probeBody struct {
	Body        string
	ContentType string
}

// rateLimitProbeBodies returns the same probe credential pair encoded both
// as a form body and as JSON — checkRateLimitSignal tries both shapes per
// candidate login path during discovery. Real login endpoints commonly
// require one or the other; a form-encoded body against a JSON-only API
// (live-verified against crAPI's real /identity/api/auth/login, see
// docs/11-implementation-plan-ph2.md Step 5) returns 415 Unsupported Media
// Type, not a real invalid-credential rejection — without trying the JSON
// shape too, that 415 would be misread as "reached the login endpoint" and
// the resulting finding would describe a request the target's real login
// logic never actually saw.
func rateLimitProbeBodies() []probeBody {
	form := url.Values{"username": {rateLimitProbeUsername}, "password": {rateLimitProbePassword}}.Encode()
	jsonBody := fmt.Sprintf(`{"username":%q,"password":%q}`, rateLimitProbeUsername, rateLimitProbePassword)
	return []probeBody{
		{form, "application/x-www-form-urlencoded"},
		{jsonBody, "application/json"},
	}
}

// checkRateLimitSignal tries each LoginPaths entry until one responds, then
// fires a fixed, capped number of requests (rateLimitProbeCount) using a
// single, deliberately-invalid credential pair — never a real
// credential-guessing sequence, see rules.go's doc comment and
// docs/11-implementation-plan-ph2.md Step 1. Flags when none of those
// requests shows any throttling signal (429, or a Retry-After header).
func (d *Detector) checkRateLimitSignal(ctx context.Context, target, host, _, _ string, _ []string) ([]detectors.Finding, error) {
	var loginPath, probeBody, probeContentType string
	for _, candidate := range d.loginPaths {
		for _, pb := range rateLimitProbeBodies() {
			_, resp, _, err := d.doRequestBody(ctx, http.MethodPost, target, host, candidate, "", pb.Body, pb.ContentType)
			if err != nil {
				continue
			}
			// 404: this path doesn't exist. 415: this path exists but
			// rejects this body shape — try the other shape before giving
			// up on the path entirely (see rateLimitProbeBodies' doc
			// comment for why a form-encoded probe against a JSON-only API
			// would otherwise be misread as "reached the login endpoint").
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnsupportedMediaType {
				continue
			}
			loginPath, probeBody, probeContentType = candidate, pb.Body, pb.ContentType
			break
		}
		if loginPath != "" {
			break
		}
	}
	if loginPath == "" {
		return nil, nil // no reachable login endpoint found — nothing to probe
	}

	throttled := false
	var lastReq *http.Request
	var lastResp *http.Response
	var lastBody []byte
	for i := 0; i < rateLimitProbeCount; i++ {
		req, resp, body, err := d.doRequestBody(ctx, http.MethodPost, target, host, loginPath, "", probeBody, probeContentType)
		if err != nil {
			continue
		}
		lastReq, lastResp, lastBody = req, resp, body
		if resp.StatusCode == http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "" {
			throttled = true
			break
		}
	}
	if throttled || lastResp == nil {
		return nil, nil
	}

	return []detectors.Finding{{
		ID:          fmt.Sprintf("authbypass-no-rate-limit-%s", sanitizeID(loginPath)),
		Type:        "authbypass",
		Severity:    "medium",
		Confidence:  "low",
		Target:      target + loginPath,
		Description: fmt.Sprintf("%d consecutive login attempts with an invalid credential produced no 429/Retry-After signal at %s — no rate limiting observed; needs manual triage since a real attempt might trip a threshold this probe's request count didn't reach", rateLimitProbeCount, loginPath),
		Evidence: map[string]string{
			"login_path":    loginPath,
			"request_count": strconv.Itoa(rateLimitProbeCount),
			"request":       detectors.FormatRequest(lastReq.Method, lastReq.URL.String(), lastReq.Header, nil),
			"response":      detectors.FormatResponse(lastResp.StatusCode, lastResp.Header, lastBody),
		},
	}}, nil
}

// checkTokenReuse compares raw response bytes, not idor.Signature's fuzzy
// (size-tolerance + keyword-set) comparison — deliberately: idor's tolerance
// exists to absorb noise like timestamps within an otherwise-identical
// *denied* response, but here two genuinely different accounts' real content
// can easily land within that same tolerance (similar size, same JSON field
// names) and wrongly look like a match. Token reuse needs the opposite bias
// — high precision, flag only when the bytes are actually identical — since
// a false positive here means telling a user their app has an auth bug it
// doesn't have. For each protectedPaths entry, if ownerToken and otherToken
// (two unrelated accounts) both get an identical 200 response, the endpoint
// isn't differentiating between accounts — flagged low-confidence, since a
// legitimately shared/non-personalized endpoint would look the same and
// isn't itself a bug (needs manual triage).
func (d *Detector) checkTokenReuse(ctx context.Context, target, host, ownerToken, otherToken string, protectedPaths []string) ([]detectors.Finding, error) {
	if ownerToken == "" || otherToken == "" {
		return nil, nil
	}
	var findings []detectors.Finding
	for _, path := range protectedPaths {
		_, ownerResp, ownerBody, err := d.doRequest(ctx, http.MethodGet, target, host, path, ownerToken)
		if err != nil {
			continue
		}
		otherReq, otherResp, otherBody, err := d.doRequest(ctx, http.MethodGet, target, host, path, otherToken)
		if err != nil {
			continue
		}
		if ownerResp.StatusCode != http.StatusOK || otherResp.StatusCode != http.StatusOK {
			continue
		}
		if string(ownerBody) != string(otherBody) {
			continue // expected/safe: each account sees its own distinct content
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("authbypass-token-reuse-%s", sanitizeID(path)),
			Type:        "authbypass",
			Severity:    "medium",
			Confidence:  "low",
			Target:      otherReq.URL.String(),
			Description: fmt.Sprintf("%s returned an identical response for two unrelated accounts' tokens — endpoint may not differentiate by account; needs manual triage, since a legitimately shared/non-personalized endpoint looks the same", path),
			Evidence: map[string]string{
				"path":     path,
				"request":  detectors.FormatRequest(otherReq.Method, otherReq.URL.String(), otherReq.Header, nil),
				"response": detectors.FormatResponse(otherResp.StatusCode, otherResp.Header, otherBody),
			},
		})
	}
	return findings, nil
}

// checkBrokenSession fires a logout request with ownerToken, then re-fires
// the first protectedPaths entry with the same (now supposedly dead) token —
// flags if it's still accepted. Deliberately placed last in Run's checks
// slice: this is the one check in this detector that changes state (ends a
// real session), same bounded-mutation precedent as
// misconfig.DefaultCredRule's single login POST — a single, non-retried
// logout, not a destructive action, but real enough that every other check
// needing a live ownerToken must run before this one.
func (d *Detector) checkBrokenSession(ctx context.Context, target, host, ownerToken, _ string, protectedPaths []string) ([]detectors.Finding, error) {
	if ownerToken == "" || len(protectedPaths) == 0 {
		return nil, nil
	}
	var logoutPath string
	for _, candidate := range d.logoutPaths {
		_, resp, _, err := d.doRequest(ctx, http.MethodPost, target, host, candidate, ownerToken)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			continue
		}
		logoutPath = candidate
		break
	}
	if logoutPath == "" {
		return nil, nil // no reachable logout endpoint found — nothing to test
	}

	path := protectedPaths[0]
	req, resp, body, err := d.doRequest(ctx, http.MethodGet, target, host, path, ownerToken)
	if err != nil {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	return []detectors.Finding{{
		ID:          fmt.Sprintf("authbypass-broken-session-%s", sanitizeID(path)),
		Type:        "authbypass",
		Severity:    "high",
		Confidence:  "high",
		Target:      req.URL.String(),
		Description: fmt.Sprintf("%s still accepted the token after logging out via %s — the session/token was not invalidated", path, logoutPath),
		Evidence: map[string]string{
			"logout_path": logoutPath,
			"path":        path,
			"request":     detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response":    detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		},
	}}, nil
}

// doRequest fires one bodyless request and records the outcome against
// hostErrors. Mirrors misconfig.Detector.doRequest's shape.
func (d *Detector) doRequest(ctx context.Context, method, target, host, path, token string) (*http.Request, *http.Response, []byte, error) {
	return d.doRequestBody(ctx, method, target, host, path, token, "", "")
}

// doRequestBody is doRequest's body-carrying variant, used by the rate-limit
// and broken-session checks. contentType is only set as a header when body
// is non-empty; ignored otherwise. Callers with a fixed body shape (like
// checkBrokenSession's bodyless logout) can pass "", "".
func (d *Detector) doRequestBody(ctx context.Context, method, target, host, path, token, reqBody, contentType string) (*http.Request, *http.Response, []byte, error) {
	// TrimSuffix avoids a double slash when target itself carries a
	// trailing one (e.g. a Web UI-submitted "https://example.com/") — path
	// is always leading-slash-prefixed (see pkg/recon/suggest.go's
	// endpointPath), so target's own trailing slash is the only source of
	// duplication. Found live, 2026-09-04: a real finding's Target rendered
	// "https://www.thriftbooks.com//giftcard/".
	fullURL := strings.TrimSuffix(target, "/") + path
	var bodyReader io.Reader
	if reqBody != "" {
		bodyReader = strings.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authbypass: building request: %w", err)
	}
	if token != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", token, 1))
	}
	if reqBody != "" && contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		d.hostErrors.RecordError(host)
		return nil, nil, nil, fmt.Errorf("authbypass: fetching %s: %w", fullURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		d.hostErrors.RecordError(host)
		return nil, nil, nil, fmt.Errorf("authbypass: reading response body: %w", err)
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

// sanitizeID turns a path into a Finding-ID-safe fragment. Same convention
// as misconfig.Detector's sanitizeID.
func sanitizeID(path string) string {
	s := strings.Trim(path, "/")
	s = strings.NewReplacer("/", "-", "?", "-", "&", "-", "=", "-").Replace(s)
	if s == "" {
		return "root"
	}
	return s
}
