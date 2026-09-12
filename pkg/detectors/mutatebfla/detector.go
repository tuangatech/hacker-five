// Package mutatebfla implements HackerFive's mutating-method BFLA/BOLA
// detector (docs/follow-up.md LT-132): a live probe against a resource
// confirmed to belong to an "owner" account, mutated with a DELETE fired
// using a second, unrelated "other" account's token. Every prior
// authorization check in this project (idor's baseline mode, authbypass's
// checkBFLA/checkTokenReuse) is read-only — GET only — so a target whose
// real vulnerability sits behind a non-idempotent method (crAPI's own
// DELETE /workshop/api/merchant/video/delete/{id}, live-observed
// 2026-09-08) was structurally unreachable. This closes that gap for the
// DELETE case; PUT/PATCH are a deliberately deferred, near-identical
// follow-up (same harness, inverted marker polarity + a request body) —
// see this package's own doc note in docs/follow-up.md LT-132.
//
// This is the second detector in the project (after businesslogic) that
// performs a genuinely mutating request, and the first that is
// intentionally destructive when it confirms a real bug: the whole point of
// proving a live BFLA/BOLA delete is that another account's token actually
// deleted the owner's resource. That is real impact on real data, not a
// side-effect-free read — so it is held to a safety-first design, not just
// documented as risky:
//
//   - Gated behind its own flag, --allow-mutating-bfla, never folded into
//     --allow-writes (which CLAUDE.md scopes specifically to
//     businesslogic's coupon checks) or --auto-provision-account (which
//     CLAUDE.md scopes to pkg/provision's account registration) — any new
//     mutating capability gets its own equally-scoped gate.
//   - Requires both an owner token AND an other token; there is no
//     single-token fallback mode (unlike idor's heuristic mode), because a
//     one-account run has no way to know whose resource is under test —
//     ambiguity this detector refuses to guess through.
//   - Requires an explicit Marker: a substring the caller asserts uniquely
//     identifies the resource in VerifyURL's response body (typically the
//     resource's own ID). The detector will not mutate anything unless its
//     own baseline GET (as owner) confirms that marker is genuinely present
//     — refusing to fire against a resource whose ownership it cannot
//     itself verify, rather than trusting the caller's Target blindly.
//   - The finding is only ever recorded from a follow-up GET (as owner,
//     after the other-token DELETE) showing the marker has actually
//     disappeared — never from the DELETE response's own status code. A
//     backend that returns 200/204 without truly deleting anything (a real,
//     observed failure mode) must not read as a false positive here.
//
// The resource under test must be one the operator has independently
// confirmed the owner account created/owns — there is no ID-range
// enumeration here (contrast idor.Detector's Strategy), by design: mutating
// an ID merely guessed to belong to the owner risks destroying an
// unrelated, possibly real third party's data, which this tool's
// read/enumerate-only default exists to prevent (docs/05-hackerone-and-legal.md).
// Not recon-derivable for the same reason idor's EndpointTemplate needed a
// human/spec-confirmed ID before LT-95's UUID work — recon observes that a
// DELETE-shaped route exists, never which concrete ID belongs to which
// account, so this detector is CLI-flag-driven only for now (no
// decisionengine/planexec auto-derivation yet — see docs/follow-up.md
// LT-132's "deliberately deferred" note).
package mutatebfla

import (
	"bytes"
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

// DefaultAuthHeaderName/DefaultAuthHeaderFormat mirror every other
// parameter-based detector's convention (idor, ssrf, authbypass, sqli) —
// kept as a package-level duplicate rather than a shared import, same
// reasoning each of those packages' own doc comments already give.
const (
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderFormat = "Bearer {token}"
)

// Detector runs the mutating-method BFLA/BOLA check against a target.
type Detector struct {
	client     *httpclient.Client
	hostErrors *hosterrors.Cache

	authHeaderName   string
	authHeaderFormat string

	logFn func(level, msg string)
}

// Option configures a Detector at construction time. Same shape as
// idor.Option/sqli.Option — not a new convention.
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
// produced outside the normal Finding-returning path (e.g. a skipped-target
// safety check). Mirrors idor/sqli.WithLogCallback exactly, so
// pkg/scanner/engine.go can route it through the same e.warnf seam.
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

// Target is one DELETE-BFLA candidate: a concrete resource confirmed (by the
// operator, not this detector) to belong to the owner account.
type Target struct {
	// DeleteURL is the concrete URL (real resource ID already substituted)
	// the other account's DELETE is sent against.
	DeleteURL string

	// VerifyURL is the concrete GET URL used to read the resource's state
	// before and after the mutating attempt, as the owner. "" defaults to
	// DeleteURL — the common case for a conventionally-RESTful resource
	// (same path, GET vs DELETE); set explicitly when a target splits them
	// (e.g. crAPI's own DELETE .../video/delete/{id} has no GET-by-id
	// sibling — VerifyURL there would be the owner's own video-list
	// endpoint instead, with Marker set to the video's ID).
	VerifyURL string

	// Marker is a substring the caller asserts is present in VerifyURL's
	// response body while — and only while — the resource still exists and
	// is visible to the owner (typically the resource's own ID). Required:
	// a Target with an empty Marker is never mutated, since there would be
	// no independent way to confirm the baseline really is the owner's
	// resource, or that a later disappearance is real.
	Marker string
}

// Run checks every target for a mutating-method BFLA/BOLA bypass.
// allowMutating gates the whole detector: false means every target is
// skipped without any request being sent at all (the caller — engine.go —
// already prints a stderr warning once per scan when --allow-mutating-bfla
// is absent, mirroring businesslogic's --allow-writes treatment, so this
// returns silently rather than warning a second time per target). Both
// ownerToken and otherToken are required — there is no single-account mode.
func (d *Detector) Run(ctx context.Context, targets []Target, ownerToken, otherToken string, allowMutating bool) ([]detectors.Finding, error) {
	if !allowMutating {
		return nil, nil
	}
	if ownerToken == "" || otherToken == "" {
		d.log("warn", "mutatebfla: both an owner and an other account token are required — skipping (no single-account mode, see package doc comment)")
		return nil, nil
	}

	var findings []detectors.Finding
	for _, t := range targets {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		f, err := d.runTarget(ctx, t, ownerToken, otherToken)
		if err != nil {
			return findings, err
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

func (d *Detector) runTarget(ctx context.Context, t Target, ownerToken, otherToken string) (*detectors.Finding, error) {
	if t.Marker == "" {
		d.log("warn", fmt.Sprintf("mutatebfla: skipping %s — no Marker given, refusing to mutate a resource this detector cannot itself confirm as the owner's", t.DeleteURL))
		return nil, nil
	}
	verifyURL := t.VerifyURL
	if verifyURL == "" {
		verifyURL = t.DeleteURL
	}

	host, err := hostOf(t.DeleteURL)
	if err != nil {
		return nil, nil // an unparseable target URL isn't this detector's job to report
	}
	if d.hostErrors.ShouldSkip(host) {
		d.log("warn", fmt.Sprintf("mutatebfla: skipping remaining probes on %s — too many consecutive request errors", host))
		return nil, nil
	}

	baseline, ok := d.probe(ctx, http.MethodGet, verifyURL, ownerToken, host)
	if !ok {
		return nil, nil
	}
	if baseline.status != http.StatusOK || !bytes.Contains(baseline.body, []byte(t.Marker)) {
		// Can't confirm the owner genuinely has visible access to a
		// marker-bearing resource right now — refuse to mutate an
		// unconfirmed target rather than guess.
		d.log("warn", fmt.Sprintf("mutatebfla: skipping %s — baseline GET as owner did not confirm Marker %q present (status %d)", verifyURL, t.Marker, baseline.status))
		return nil, nil
	}

	mutateResp, ok := d.probe(ctx, http.MethodDelete, t.DeleteURL, otherToken, host)
	if !ok {
		return nil, nil
	}

	after, ok := d.probe(ctx, http.MethodGet, verifyURL, ownerToken, host)
	if !ok {
		return nil, nil
	}
	if after.status == http.StatusOK && bytes.Contains(after.body, []byte(t.Marker)) {
		// Marker still present after the mutating attempt — no real
		// deletion took place, regardless of what status code the DELETE
		// itself returned (some backends misreport success on a no-op).
		return nil, nil
	}

	return &detectors.Finding{
		ID:          fmt.Sprintf("mutatebfla-delete-%s", sanitizeID(t.DeleteURL)),
		Type:        "mutatebfla",
		Severity:    "critical",
		Confidence:  "high",
		Target:      t.DeleteURL,
		Description: "a second, unrelated account's token successfully deleted this resource — confirmed by a follow-up read as the owner showing it genuinely gone, not inferred from the DELETE response's status code alone (BFLA/BOLA via a mutating method)",
		Evidence: map[string]string{
			"marker":               t.Marker,
			"baseline_status":      strconv.Itoa(baseline.status),
			"delete_status":        strconv.Itoa(mutateResp.status),
			"after_status":         strconv.Itoa(after.status),
			"baseline_request":     requestEvidenceFor(baseline),
			"baseline_response":    evidenceFor(baseline),
			"delete_request":       requestEvidenceFor(mutateResp),
			"delete_response":      evidenceFor(mutateResp),
			"after_delete_request": requestEvidenceFor(after),
			"after_response":       evidenceFor(after),
		},
	}, nil
}

// probeResult is one HTTP round-trip's shape.
type probeResult struct {
	req    *http.Request
	status int
	header http.Header
	body   []byte
}

// probe fires one request and records its shape. ok is false on a
// transport-level error (recorded against the host circuit breaker) or a
// request-build error — never on a non-2xx status, which several of this
// package's own comparisons treat as meaningful (a 404 after a DELETE is
// exactly the positive signal, not a failure).
func (d *Detector) probe(ctx context.Context, method, rawURL, token, host string) (probeResult, bool) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return probeResult{}, false
	}
	if token != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", token, 1))
	}

	resp, err := d.client.Do(req)
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
	return probeResult{req: req, status: resp.StatusCode, header: resp.Header, body: body}, true
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

// sanitizeID makes a URL safe to embed in a Finding.ID — same convention as
// ssrf.sanitizeID/sqli.sanitizeParam.
func sanitizeID(s string) string {
	r := strings.NewReplacer("/", "-", "?", "-", "&", "-", "=", "-", ":", "-")
	return strings.Trim(r.Replace(s), "-")
}
