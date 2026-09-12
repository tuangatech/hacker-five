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
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// runParam runs all three techniques for one (url, param) pair. A baseline
// fetch (the URL exactly as observed) anchors every comparison — never
// judged against an unrelated prior request.
func (d *Detector) runParam(ctx context.Context, target, param, authToken, host string) []detectors.Finding {
	baseline, ok := d.probeWithToken(ctx, target, authToken, host)
	if !ok {
		return nil // can't compare against a baseline that itself failed
	}

	var findings []detectors.Finding
	findings = append(findings, d.errorBasedCheck(ctx, target, param, authToken, host, baseline)...)
	findings = append(findings, d.booleanBasedCheck(ctx, target, param, authToken, host, baseline)...)
	findings = append(findings, d.timeBasedCheck(ctx, target, param, authToken, host, baseline)...)
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
