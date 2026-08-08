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

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/vars"
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
}

// New constructs a Detector.
func New(client *httpclient.Client, strategy Strategy) *Detector {
	return &Detector{
		client:     client,
		strategy:   strategy,
		hostErrors: hosterrors.New(hosterrors.DefaultThreshold),
	}
}

// idSample is one candidate ID's request/response outcome.
type idSample struct {
	id  string
	url string
	sig Signature
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
	if ownerToken != "" && otherToken != "" {
		return d.runBaseline(ctx, endpointTemplate, ownerToken, otherToken)
	}
	token := otherToken
	if token == "" {
		token = ownerToken
	}
	return d.runHeuristic(ctx, endpointTemplate, token)
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
		id       string
		url      string
		ownerSig Signature
		otherSig Signature
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

		ownerSig, err := d.fetch(ctx, reqURL, ownerToken)
		if err != nil {
			d.hostErrors.RecordError(host)
			continue
		}
		otherSig, err := d.fetch(ctx, reqURL, otherToken)
		if err != nil {
			d.hostErrors.RecordError(host)
			continue
		}
		d.hostErrors.RecordSuccess(host)

		samples = append(samples, baselineSample{id: id, url: reqURL, ownerSig: ownerSig, otherSig: otherSig})
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
			heuristicSamples[i] = idSample{id: s.id, url: s.url, sig: s.otherSig}
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

		sig, err := d.fetch(ctx, reqURL, token)
		if err != nil {
			d.hostErrors.RecordError(host)
			continue
		}
		d.hostErrors.RecordSuccess(host)

		samples = append(samples, idSample{id: id, url: reqURL, sig: sig})
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
				"id":     s.id,
				"status": strconv.Itoa(s.sig.StatusCode),
			},
		})
	}
	return findings
}

func (d *Detector) fetch(ctx context.Context, reqURL, token string) (Signature, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Signature{}, fmt.Errorf("building request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return Signature{}, fmt.Errorf("fetching %s: %w", reqURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Signature{}, fmt.Errorf("reading response body: %w", err)
	}

	return Sign(resp, body), nil
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
