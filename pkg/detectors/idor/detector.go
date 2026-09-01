// Package idor implements the IDOR (Insecure Direct Object Reference)
// detector: baseline mode compares two unrelated accounts' access to the
// same candidate IDs, and heuristic mode falls back to a single-account
// signature diff when only one token is available.
package idor

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
	"github.com/tuangatech/hacker-five/pkg/scanner/vars"
)

// DefaultAuthHeaderName/DefaultAuthHeaderFormat are the header name/value
// shape used unless overridden via WithAuthHeader — plain Bearer-token auth,
// what every target this project has tested against besides vAPI uses.
const (
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderFormat = "Bearer {token}"
)

// Detector ties an ID enumeration Strategy and an HTTP client together to
// find cross-account authorization bypasses.
type Detector struct {
	client   *httpclient.Client
	strategy Strategy

	// hostErrors stops a run early once the target endpoint's host crosses
	// its consecutive-error threshold, instead of burning the rest of the ID
	// range in retries against a target that's gone down mid-enumeration.
	hostErrors *hosterrors.Cache

	authHeaderName   string
	authHeaderFormat string

	// preview/logFn back WithTemplatePreview/WithLogCallback — see those
	// doc comments.
	preview bool
	logFn   func(level, msg string)
}

// Option configures a Detector at construction time.
type Option func(*Detector)

// WithAuthHeader overrides the header name and/or value format fetch uses to
// carry a candidate token — real targets don't all speak
// "Authorization: Bearer <token>" (e.g. vAPI's
// "Authorization-Token: base64(username:password)", see
// docs/10-implementation-plan-ph1b.md's Future Enhancement #6). format must
// contain the literal placeholder "{token}", replaced with the real token at
// request time — not a fmt verb, so a malformed user-supplied format string
// can't misinterpret its own token as a format directive. Either argument
// left "" keeps that half at its default, so a caller overriding just the
// name (or just the format) doesn't need to know the other's default value.
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

// WithTemplatePreview enables a one-shot preflight GET against
// endpointTemplate (substituted with the enumeration strategy's first
// candidate ID) before Run's real loop begins, logged via WithLogCallback —
// closes docs/14-implementation-plan-ph5.md Step 7's named gap that a wrong
// EndpointTemplate otherwise "silently yields zero findings with no
// validation catching it." No Finding is ever emitted from this probe.
func WithTemplatePreview(enabled bool) Option {
	return func(d *Detector) {
		d.preview = enabled
	}
}

// WithLogCallback registers fn to receive informational/warning log lines
// produced outside the normal Finding-returning path — currently only
// WithTemplatePreview's probe. Mirrors pkg/scanner.Engine's own
// WithLogCallback signature so a caller can route both through the same
// seam (see pkg/scanner/engine.go's idorOptions).
func WithLogCallback(fn func(level, msg string)) Option {
	return func(d *Detector) {
		d.logFn = fn
	}
}

// New constructs a Detector.
func New(client *httpclient.Client, strategy Strategy, opts ...Option) *Detector {
	d := &Detector{
		client:           client,
		strategy:         strategy,
		hostErrors:       hosterrors.New(hosterrors.DefaultThreshold),
		authHeaderName:   DefaultAuthHeaderName,
		authHeaderFormat: DefaultAuthHeaderFormat,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// idSample is one candidate ID's request/response outcome.
type idSample struct {
	id           string
	url          string
	sig          Signature
	reqEvidence  string
	respEvidence string
}

// Run enumerates endpointTemplate's {{id}} placeholder and emits a Finding
// for every authorization bypass found.
//
// If both ownerToken and otherToken are non-empty, this is baseline mode
// (high confidence): it establishes what "denied" looks like from otherToken
// across the whole ID range, and flags any ID where otherToken's response
// deviates from that denial *and* ownerToken confirms the ID holds real
// content. Otherwise it falls back to heuristic mode (low confidence, single
// token): any ID whose response differs from the majority signature is
// flagged for manual triage — it cannot distinguish an authorization bypass
// from an ID that legitimately has different, non-sensitive content.
func (d *Detector) Run(ctx context.Context, endpointTemplate, ownerToken, otherToken string) ([]detectors.Finding, error) {
	if d.preview {
		d.previewOnce(ctx, endpointTemplate, ownerToken, otherToken)
	}

	if ownerToken != "" && otherToken != "" {
		return d.runBaseline(ctx, endpointTemplate, ownerToken, otherToken)
	}
	token := otherToken
	if token == "" {
		token = ownerToken
	}
	return d.runHeuristic(ctx, endpointTemplate, token)
}

// previewOnce fires a single substituted-ID GET against endpointTemplate and
// logs its status/body-length, purely informational — never a Finding, and
// never fails Run: a render/fetch error here just logs a warning, since the
// real loop below will hit (and report on) the same problem properly if it's
// real.
func (d *Detector) previewOnce(ctx context.Context, endpointTemplate, ownerToken, otherToken string) {
	ids := d.strategy.Generate()
	if len(ids) == 0 {
		return
	}
	token := ownerToken
	if token == "" {
		token = otherToken
	}

	reqURL, err := renderEndpoint(endpointTemplate, ids[0])
	if err != nil {
		d.log("warn", fmt.Sprintf("idor preview: could not render endpoint template %q: %v", endpointTemplate, err))
		return
	}
	sig, _, _, err := d.fetch(ctx, reqURL, token)
	if err != nil {
		d.log("warn", fmt.Sprintf("idor preview: request to %s failed: %v", reqURL, err))
		return
	}
	d.log("info", fmt.Sprintf("idor preview: %s -> status %d, %d bytes", reqURL, sig.StatusCode, sig.BodySize))
}

// log is a nil-safe wrapper around logFn.
func (d *Detector) log(level, msg string) {
	if d.logFn != nil {
		d.logFn(level, msg)
	}
}

func (d *Detector) runBaseline(ctx context.Context, endpointTemplate, ownerToken, otherToken string) ([]detectors.Finding, error) {
	ids := d.strategy.Generate()
	if len(ids) == 0 {
		return nil, fmt.Errorf("idor baseline: strategy produced no candidate IDs")
	}

	host, err := d.hostFor(endpointTemplate, ids[0])
	if err != nil {
		return nil, fmt.Errorf("idor baseline: %w", err)
	}

	type baselineSample struct {
		id           string
		url          string
		ownerSig     Signature
		otherSig     Signature
		reqEvidence  string // otherToken's request — the one that proves the bypass
		respEvidence string
	}
	var samples []baselineSample

	for _, id := range ids {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if d.hostErrors.ShouldSkip(host) {
			break
		}

		reqURL, err := renderEndpoint(endpointTemplate, id)
		if err != nil {
			return nil, fmt.Errorf("idor baseline: %w", err)
		}

		ownerSig, _, _, err := d.fetch(ctx, reqURL, ownerToken)
		if err != nil {
			d.hostErrors.RecordError(host)
			continue
		}
		otherSig, otherReqEvidence, otherRespEvidence, err := d.fetch(ctx, reqURL, otherToken)
		if err != nil {
			d.hostErrors.RecordError(host)
			continue
		}
		d.hostErrors.RecordSuccess(host)

		samples = append(samples, baselineSample{
			id: id, url: reqURL, ownerSig: ownerSig, otherSig: otherSig,
			reqEvidence: otherReqEvidence, respEvidence: otherRespEvidence,
		})
	}

	otherSigs := make([]Signature, len(samples))
	for i, s := range samples {
		otherSigs[i] = s.otherSig
	}

	baseline, err := Establish(otherSigs)
	if err != nil {
		// Samples too few or too inconsistent to trust a denial baseline —
		// fall back to heuristic mode for this run using otherToken's
		// already-collected signatures, rather than discarding them.
		heuristicSamples := make([]idSample, len(samples))
		for i, s := range samples {
			heuristicSamples[i] = idSample{id: s.id, url: s.url, sig: s.otherSig, reqEvidence: s.reqEvidence, respEvidence: s.respEvidence}
		}
		return heuristicFindings(heuristicSamples), nil
	}

	var findings []detectors.Finding
	for _, s := range samples {
		if !baseline.Bypassed(s.otherSig) {
			continue
		}
		if s.otherSig.StatusCode != http.StatusOK {
			continue // the deviation is itself an error, not evidence of unauthorized *access*
		}
		if s.ownerSig.StatusCode != http.StatusOK || s.ownerSig.BodySize == 0 {
			continue // ownerToken doesn't confirm this ID holds real content
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("idor-%s", s.id),
			Type:        "idor",
			Severity:    "high",
			Confidence:  "high",
			Target:      s.url,
			Description: fmt.Sprintf("otherToken retrieved real user data for ID %s, which does not match the established denied-access baseline for this endpoint", s.id),
			Evidence: map[string]string{
				"id":                          s.id,
				"owner_status":                strconv.Itoa(s.ownerSig.StatusCode),
				"other_status":                strconv.Itoa(s.otherSig.StatusCode),
				"denied_baseline_status":      strconv.Itoa(baseline.denied.StatusCode),
				"denied_baseline_sample_size": strconv.Itoa(len(otherSigs)),
				"request":                     s.reqEvidence,
				"response":                    s.respEvidence,
			},
		})
	}
	return findings, nil
}

func (d *Detector) runHeuristic(ctx context.Context, endpointTemplate, token string) ([]detectors.Finding, error) {
	ids := d.strategy.Generate()
	if len(ids) == 0 {
		return nil, fmt.Errorf("idor heuristic: strategy produced no candidate IDs")
	}

	host, err := d.hostFor(endpointTemplate, ids[0])
	if err != nil {
		return nil, fmt.Errorf("idor heuristic: %w", err)
	}

	var samples []idSample
	for _, id := range ids {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if d.hostErrors.ShouldSkip(host) {
			break
		}

		reqURL, err := renderEndpoint(endpointTemplate, id)
		if err != nil {
			return nil, fmt.Errorf("idor heuristic: %w", err)
		}

		sig, reqEvidence, respEvidence, err := d.fetch(ctx, reqURL, token)
		if err != nil {
			d.hostErrors.RecordError(host)
			continue
		}
		d.hostErrors.RecordSuccess(host)

		samples = append(samples, idSample{id: id, url: reqURL, sig: sig, reqEvidence: reqEvidence, respEvidence: respEvidence})
	}

	return heuristicFindings(samples), nil
}

// heuristicFindings flags every sample whose signature differs from the
// majority signature across all samples. This is the documented limitation
// of heuristic mode, not a bug: it cannot distinguish "IDOR" from "this ID
// legitimately has different, non-sensitive content" (e.g. two different
// public product pages) — every deviation is reported as low-confidence,
// manual-triage material.
func heuristicFindings(samples []idSample) []detectors.Finding {
	if len(samples) == 0 {
		return nil
	}

	sigs := make([]Signature, len(samples))
	for i, s := range samples {
		sigs[i] = s.sig
	}
	majority, _ := largestCluster(sigs)

	var findings []detectors.Finding
	for _, s := range samples {
		if !s.sig.DiffersFrom(majority) {
			continue
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("idor-heuristic-%s", s.id),
			Type:        "idor",
			Severity:    "medium",
			Confidence:  "low",
			Target:      s.url,
			Description: fmt.Sprintf("ID %s returned a response signature that differs from the majority of enumerated IDs — needs manual triage; heuristic mode cannot distinguish an authorization bypass from legitimately varied content", s.id),
			Evidence: map[string]string{
				"id":       s.id,
				"status":   strconv.Itoa(s.sig.StatusCode),
				"request":  s.reqEvidence,
				"response": s.respEvidence,
			},
		})
	}
	return findings
}

// fetch fires one candidate-ID request and returns its Signature alongside
// rendered request/response evidence strings (detectors.FormatRequest/
// FormatResponse) for whichever Finding a caller ends up building from it.
func (d *Detector) fetch(ctx context.Context, reqURL, token string) (Signature, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Signature{}, "", "", fmt.Errorf("building request: %w", err)
	}
	if token != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", token, 1))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return Signature{}, "", "", fmt.Errorf("fetching %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Signature{}, "", "", fmt.Errorf("reading response body: %w", err)
	}

	reqEvidence := detectors.FormatRequest(req.Method, reqURL, req.Header, nil)
	respEvidence := detectors.FormatResponse(resp.StatusCode, resp.Header, body)
	return Sign(resp, body), reqEvidence, respEvidence, nil
}

// hostFor renders endpointTemplate with a representative ID just to extract
// the host hosterrors.Cache tracks — the host never varies across candidate
// IDs, only the path does.
func (d *Detector) hostFor(endpointTemplate, sampleID string) (string, error) {
	rendered, err := renderEndpoint(endpointTemplate, sampleID)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(rendered)
	if err != nil {
		return "", fmt.Errorf("parsing endpoint URL: %w", err)
	}
	return u.Host, nil
}

func renderEndpoint(endpointTemplate, id string) (string, error) {
	return vars.Render(endpointTemplate, vars.Context{Vars: map[string]string{"id": id}})
}
