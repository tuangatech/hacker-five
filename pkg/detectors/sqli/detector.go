// Package sqli implements HackerFive's first native SQL-injection detector
// (docs/18-implementation-plan-ph9.md Step 4, closing part of LT-87): before
// this package existed, sqli/xss/lfi were covered solely by the generic
// nuclei corpus, which a WAF routinely blocks and which D6's uniform-wall
// short-circuit (pkg/uniformwall) drops entirely on a walled host.
//
// Three bounded, first-party techniques, each against a param's own
// *existing* value (append, never replace — keeps the query semantically
// close to what the app already accepts):
//
//   - error-based: append a syntax-breaking payload, look for a
//     recognizable DBMS error signature absent from the baseline response.
//   - boolean-based blind: append a tautology ("... AND 1=1") and its
//     negation ("... AND 1=2"); a vulnerable endpoint's "true" response
//     looks like the baseline while its "false" response looks different.
//   - time-based blind: append a DBMS-specific sleep payload and look for a
//     response-time delta repeatable on a second try — the last resort for
//     an endpoint with no visible content or error difference.
//
// Deliberately not a sqlmap-style fuzzing engine (CLAUDE.md's dependency/
// footprint discipline, and this phase's own "explicitly out of scope" list
// in doc18): a small, fixed payload set per param, never unbounded
// mutation. Read/enumerate-only throughout — a payload's only effect is to
// reach the app; no write, no real command execution
// (docs/05-hackerone-and-legal.md).
package sqli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// DefaultAuthHeaderName/DefaultAuthHeaderFormat mirror every other
// parameter-based detector's convention (idor, ssrf, authbypass) — kept as
// a package-level duplicate rather than a shared import, same reasoning
// each of those packages' own doc comments already give.
const (
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderFormat = "Bearer {token}"
)

// Detector runs the built-in SQLi checks against a target.
type Detector struct {
	client     *httpclient.Client
	hostErrors *hosterrors.Cache

	authHeaderName   string
	authHeaderFormat string

	// bodyFillFields/bodyFillValues are RunBodyFields' LT-192 counterpart to
	// ssrf.Detector's own bodyFillFields/bodyFillValues — see WithBodyFill.
	bodyFillFields []string
	bodyFillValues map[string]string

	logFn func(level, msg string)
}

// Option configures a Detector at construction time. Same shape as
// idor.Option/ssrf.Option/misconfig.Option — not a new convention.
type Option func(*Detector)

// WithAuthHeader overrides the header name/value format used to carry an
// auth token on every probe request. "" for either argument preserves the
// package default.
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

// WithBodyFill turns on filling an endpoint's other request-body fields
// (LT-192, docs/follow-up.md — sqli's counterpart to ssrf.WithBodyFill,
// LT-188 a) — runBodyParam sets every name in fields other than the one
// under test, alongside the payload, instead of sending the candidate
// field alone. Each filled field uses values[field]'s literal (the
// target's own recovered true/false/integer default, verbatim, for a
// strictly-typed field) when present, else a generic placeholder. This
// exists for the same reason ssrf's version does: a target's other
// required body fields (e.g. a login endpoint's password) may be validated
// before the SQL query the candidate field feeds into is ever built, so
// the single-field body runBodyParam otherwise sends can never see a
// difference at all — juiceshop-sqli-login-bypass
// (tests/fixtures/known-vulns/juiceshop.json) is exactly this shape.
// Getting past that validation can, if the injection actually succeeds,
// complete a real unauthorized authentication — a consequential action,
// not a read — so the caller is expected to gate this the way
// scanner.Config.AllowSQLiBodyFill does, never pass fields unconditionally.
// nil/empty fields (the package default) keeps the original single-field
// body.
func WithBodyFill(fields []string, values map[string]string) Option {
	return func(d *Detector) { d.bodyFillFields, d.bodyFillValues = fields, values }
}

// WithLogCallback registers fn to receive informational/warning log lines
// produced outside the normal Finding-returning path (e.g. a skipped-host
// circuit-breaker trip). Mirrors idor.WithLogCallback/misconfig.WithLogCallback
// exactly, so pkg/scanner/engine.go can route it through the same e.warnf seam.
func WithLogCallback(fn func(level, msg string)) Option {
	return func(d *Detector) {
		d.logFn = fn
	}
}

// New constructs a Detector.
func New(client *httpclient.Client, opts ...Option) *Detector {
	d := &Detector{
		client:           client,
		hostErrors:       hosterrors.New(hosterrors.DefaultThreshold),
		authHeaderName:   DefaultAuthHeaderName,
		authHeaderFormat: DefaultAuthHeaderFormat,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

func (d *Detector) log(level, msg string) {
	if d.logFn != nil {
		d.logFn(level, msg)
	}
}

// Target pairs one concrete, already-observed URL (its query string intact)
// with the subset of its query-parameter names recon judged worth testing —
// exactly recon.SQLiTarget's shape, restated here so this package stays
// recon-agnostic (same discipline ssrf/idor's detector packages hold: the
// detector package never imports pkg/recon, a caller translates).
type Target struct {
	URL    string
	Params []string
}

// Run checks every param on every target for SQL injection via the three
// techniques described in this package's doc comment. authToken, if
// non-empty, is sent on every probe request per the configured auth header.
func (d *Detector) Run(ctx context.Context, targets []Target, authToken string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, t := range targets {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		host, err := hostOf(t.URL)
		if err != nil {
			continue // an unparseable target URL isn't this detector's job to report
		}
		if d.hostErrors.ShouldSkip(host) {
			d.log("warn", fmt.Sprintf("sqli: skipping remaining probes on %s — too many consecutive request errors", host))
			continue
		}
		for _, param := range t.Params {
			if ctx.Err() != nil {
				return findings, ctx.Err()
			}
			fs := d.runParam(ctx, t.URL, param, authToken, host)
			findings = append(findings, fs...)
		}
	}
	return findings, nil
}

// BodyTarget pairs one endpoint URL (POST target, no query string
// involved) with the JSON request-body field names worth SQLi-testing on
// it — RunBodyFields' counterpart to Target, exactly recon.SQLiBodyTarget's
// shape restated here (LT-192, docs/follow-up.md), same recon-agnostic
// discipline Target's own doc comment describes.
type BodyTarget struct {
	URL    string
	Params []string
}

// RunBodyFields is Run's JSON-request-body counterpart (LT-192): the same
// three techniques (error/boolean/time-based), but POSTing to each
// bodyTarget with one named field carrying the base value ("1" when no
// prior value is known, same convention buildPayloadURL uses) plus the
// payload, instead of mutating a URL query parameter. Exists for a target
// whose vulnerable value lives in the JSON body, not the URL — a login
// endpoint's email field (juiceshop-sqli-login-bypass,
// tests/fixtures/known-vulns/juiceshop.json) rather than a search box's
// query string. authToken, if non-empty, is sent the same way Run's is.
func (d *Detector) RunBodyFields(ctx context.Context, bodyTargets []BodyTarget, authToken string) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, t := range bodyTargets {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		host, err := hostOf(t.URL)
		if err != nil {
			continue // an unparseable target URL isn't this detector's job to report
		}
		if d.hostErrors.ShouldSkip(host) {
			d.log("warn", fmt.Sprintf("sqli: skipping remaining body-field probes on %s — too many consecutive request errors", host))
			continue
		}
		for _, field := range t.Params {
			if ctx.Err() != nil {
				return findings, ctx.Err()
			}
			fs := d.runBodyParam(ctx, t.URL, field, authToken, host)
			findings = append(findings, fs...)
		}
	}
	return findings, nil
}

// runParam runs all three techniques for one (url, param) pair. A baseline
// fetch (the URL exactly as observed) anchors every comparison — never
// judged against an unrelated prior request.
func (d *Detector) runParam(ctx context.Context, target, param, authToken, host string) []detectors.Finding {
	baseline, ok := d.probeWithToken(ctx, target, authToken, host)
	if !ok {
		return nil // can't compare against a baseline that itself failed
	}

	c := sqliCandidate{
		name:        param,
		evidenceKey: "param",
		probe: func(ctx context.Context, suffix string) (probeResult, bool) {
			return d.probeWithToken(ctx, buildPayloadURL(target, param, suffix), authToken, host)
		},
	}
	var findings []detectors.Finding
	findings = append(findings, d.errorBasedCheck(ctx, c, baseline)...)
	findings = append(findings, d.booleanBasedCheck(ctx, c, baseline)...)
	findings = append(findings, d.timeBasedCheck(ctx, c, baseline)...)
	return findings
}

// runBodyParam is runParam's body-field counterpart (LT-192): the baseline
// and every payload probe POST a JSON body carrying field set to "1"+suffix
// (empty suffix for the baseline) — d.bodyFillFields, when WithBodyFill set
// it, additionally fills every other named field with a placeholder/
// recovered literal so a target that validates them before evaluating the
// SQL query can still be reached.
func (d *Detector) runBodyParam(ctx context.Context, target, field, authToken, host string) []detectors.Finding {
	baseline, ok := d.probeBodyWithToken(ctx, target, buildPayloadBody(field, "", d.bodyFillFields, d.bodyFillValues), authToken, host)
	if !ok {
		return nil // can't compare against a baseline that itself failed
	}

	c := sqliCandidate{
		name:        field,
		evidenceKey: "body_field",
		probe: func(ctx context.Context, suffix string) (probeResult, bool) {
			return d.probeBodyWithToken(ctx, target, buildPayloadBody(field, suffix, d.bodyFillFields, d.bodyFillValues), authToken, host)
		},
	}
	var findings []detectors.Finding
	findings = append(findings, d.errorBasedCheck(ctx, c, baseline)...)
	findings = append(findings, d.booleanBasedCheck(ctx, c, baseline)...)
	findings = append(findings, d.timeBasedCheck(ctx, c, baseline)...)
	return findings
}

// probeResult is one HTTP round-trip's shape, enough for every check's
// comparison logic without holding onto the *http.Response.
type probeResult struct {
	req     *http.Request
	status  int
	header  http.Header
	body    []byte
	elapsed time.Duration
}

// probeWithToken fires one GET against rawURL and records its shape. ok is
// false on a transport-level error (recorded against the host circuit
// breaker) or a request-build error — never on a non-2xx status, since a
// 4xx/5xx is itself sometimes the signal a check is looking for.
func (d *Detector) probeWithToken(ctx context.Context, rawURL, authToken, host string) (probeResult, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return probeResult{}, false
	}
	if authToken != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", authToken, 1))
	}

	start := time.Now()
	resp, err := d.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		d.hostErrors.RecordError(host)
		return probeResult{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		d.hostErrors.RecordError(host)
		return probeResult{}, false
	}
	d.hostErrors.RecordSuccess(host)
	return probeResult{req: req, status: resp.StatusCode, header: resp.Header, body: body, elapsed: elapsed}, true
}

// probeBodyWithToken is probeWithToken's JSON-request-body counterpart
// (LT-192): POSTs reqBody instead of firing a bodyless GET. Same
// error/circuit-breaker treatment.
func (d *Detector) probeBodyWithToken(ctx context.Context, target, reqBody, authToken, host string) (probeResult, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(reqBody))
	if err != nil {
		return probeResult{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", authToken, 1))
	}

	start := time.Now()
	resp, err := d.client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		d.hostErrors.RecordError(host)
		return probeResult{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		d.hostErrors.RecordError(host)
		return probeResult{}, false
	}
	d.hostErrors.RecordSuccess(host)
	return probeResult{req: req, status: resp.StatusCode, header: resp.Header, body: body, elapsed: elapsed}, true
}

// buildPayloadURL sets param to its current value (if any, else "1") with
// suffix appended — appended, never replaced, so the injected string stays
// in the syntactic position the app's own query already puts it in.
func buildPayloadURL(target, param, suffix string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	base := q.Get(param)
	if base == "" {
		base = "1"
	}
	q.Set(param, base+suffix)
	u.RawQuery = q.Encode()
	return u.String()
}

// bodyFillPlaceholder is the value buildPayloadBody sends for a fill field
// with no recovered literal — same string ssrf.checks.go's own
// bodyFillPlaceholder uses (not shared across packages: this package stays
// recon/other-detector-agnostic, same discipline Target's doc comment
// describes), so a request log line reads consistently across detectors.
const bodyFillPlaceholder = "hackerfive-probe-value"

// jsonLiteralRe is the same true/false/integer whitelist
// recon.jsValueLiteral produces (and ssrf.checks.go's own jsonLiteralRe
// checks again) — checked here too so a value map from any caller can only
// ever inject one of those three shapes as raw JSON, never arbitrary text.
var jsonLiteralRe = regexp.MustCompile(`^(?:true|false|-?[0-9]{1,9})$`)

// buildPayloadBody builds the JSON body for one probe: field is set to "1"
// (buildPayloadURL's own empty-value fallback) with suffix appended — same
// append-never-replace discipline, so the injected string lands in the same
// syntactic position the app's own value already occupies. fill lists every
// other field name to also set (WithBodyFill, LT-192): each uses
// values[k]'s literal when it's a plain true/false/integer (a
// strictly-typed field would otherwise reject a placeholder string), else
// bodyFillPlaceholder. Empty fill (the package default) sends field alone.
func buildPayloadBody(field, suffix string, fill []string, values map[string]string) string {
	value := "1" + suffix
	if len(fill) == 0 {
		b, err := json.Marshal(map[string]string{field: value})
		if err != nil {
			return fmt.Sprintf(`{%q:%q}`, field, value) // never expected: value is a plain string
		}
		return string(b)
	}
	body := make(map[string]json.RawMessage, len(fill)+1)
	for _, k := range fill {
		if k == field {
			continue
		}
		if lit, ok := values[k]; ok && jsonLiteralRe.MatchString(lit) {
			body[k] = json.RawMessage(lit)
		} else {
			body[k], _ = json.Marshal(bodyFillPlaceholder)
		}
	}
	body[field], _ = json.Marshal(value)
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Sprintf(`{%q:%q}`, field, value) // never expected: every value above is pre-validated
	}
	return string(b)
}

func hostOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing target URL: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("target URL has no host: %s", target)
	}
	return u.Host, nil
}

func evidenceFor(probe probeResult) string {
	return detectors.FormatResponse(probe.status, probe.header, probe.body)
}

func requestEvidenceFor(probe probeResult) string {
	if probe.req == nil {
		return ""
	}
	return detectors.FormatRequest(probe.req.Method, probe.req.URL.String(), probe.req.Header, nil)
}
