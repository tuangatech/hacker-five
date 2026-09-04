package ssrf

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// minFetchedBodyLen is the smallest response body checkInternalTargets/
// checkSchemeBasedTargets will still treat as "looks like the target
// actually fetched something" — short enough to allow a compact real
// response, long enough to skip a bare "{}"/empty-object rejection.
const minFetchedBodyLen = 20

// baselinePayload is syntactically a URL but guaranteed unfetchable (RFC
// 2606 reserves .invalid for exactly this) — used once per param to learn
// what the target's own response looks like when nothing was actually
// fetched, so a real payload's response can be judged against it instead
// of in isolation. Found live, 2026-09-04: a real target ignored its url
// parameter entirely and returned its own homepage for all 15 payloads
// tried (file://, gopher://, dict://, every loopback encoding, every
// RFC1918 sample, every cloud-metadata path) — all flagged "high
// confidence" under the old single-response heuristic, because any normal
// webpage response trivially satisfies looksLikeFetchedContent's generic
// <html/<!DOCTYPE markers.
const baselinePayload = "https://hackerfive-ssrf-baseline-check.invalid/"

// baselineTolerancePct bounds how close a payload's response body length
// must be to its param's own baseline to be treated as indistinguishable
// from "nothing was fetched" — a real fetched resource (metadata JSON, an
// internal admin page, a Redis INFO dump) is not expected to coincidentally
// land within 10% of an unrelated homepage's byte length. The real
// useruby.care evidence: response bodies weren't always byte-identical
// (the payload string itself likely gets reflected somewhere) but every
// one of the 15 false positives was exactly the same length — an
// exact-match requirement would have caught only a handful of them.
const baselineTolerancePct = 0.10

// probeBaseline is one param's captured inert-probe response. ok is false
// when the baseline request itself failed or didn't return 200 — in that
// case comparisons are skipped entirely (conservative: never suppress a
// finding without a good baseline to judge it against).
type probeBaseline struct {
	ok      bool
	bodyLen int
}

// fetchBaseline fires one probe with baselinePayload and records its
// response body length — called once per param, before the real payload
// loops, and reused across every probeAndRecord call for that param.
func (d *Detector) fetchBaseline(ctx context.Context, target, authToken, param string) probeBaseline {
	probeURL := buildProbeURL(target, param, baselinePayload)
	_, resp, body, err := d.doRequest(ctx, probeURL, authToken)
	if err != nil || resp.StatusCode != http.StatusOK {
		return probeBaseline{}
	}
	return probeBaseline{ok: true, bodyLen: len(bytes.TrimSpace(body))}
}

// baselineMatches reports whether body is indistinguishable (within
// baselineTolerancePct) from baseline — see probeAndRecord's own use of
// this for why that means "not evidence of a real fetch."
func baselineMatches(baseline probeBaseline, body []byte) bool {
	if !baseline.ok {
		return false
	}
	bodyLen := len(bytes.TrimSpace(body))
	delta := bodyLen - baseline.bodyLen
	if delta < 0 {
		delta = -delta
	}
	return float64(delta) <= float64(baseline.bodyLen)*baselineTolerancePct
}

// checkInternalTargets probes each param with every loopback-encoding
// variant, RFC1918 sample, and the cloud-metadata address (bare GET only —
// see rules.go's doc comment on why provider-specific headers aren't
// reachable through this vector).
func (d *Detector) checkInternalTargets(ctx context.Context, target, authToken string, params []string, baselines map[string]probeBaseline) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	var payloads []string
	payloads = append(payloads, loopbackEncodings()...)
	payloads = append(payloads, internalNetworkSamples()...)

	for _, param := range params {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		baseline := baselines[param]
		for _, addr := range payloads {
			findings = append(findings, d.probeAndRecord(ctx, target, authToken, param, addr, "http://"+addr+"/",
				"internal-target", fmt.Sprintf("%s parameter accepted an internal-network address (%s) and the response suggests the server fetched it", param, addr), baseline)...)
		}
		for _, path := range cloudMetadataPaths() {
			payloadURL := "http://" + cloudMetadataTarget + path
			findings = append(findings, d.probeAndRecord(ctx, target, authToken, param, cloudMetadataTarget+path, payloadURL,
				"cloud-metadata", fmt.Sprintf("%s parameter accepted a cloud-metadata URL (%s) via a bare GET and the response suggests the server fetched it — note this only proves reachability without provider-specific headers, see this package's doc comment", param, payloadURL), baseline)...)
		}
	}
	return findings, nil
}

// checkSchemeBasedTargets probes each param with file://, gopher://, and
// dict:// payloads — more severe/distinctive than HTTP-to-internal-HTTP.
func (d *Detector) checkSchemeBasedTargets(ctx context.Context, target, authToken string, params []string, baselines map[string]probeBaseline) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	for _, param := range params {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		baseline := baselines[param]
		for _, payload := range schemeBasedPayloads() {
			findings = append(findings, d.probeAndRecord(ctx, target, authToken, param, payload, payload,
				"scheme-based", fmt.Sprintf("%s parameter accepted a %s payload and the response suggests the server fetched it — target's URL-fetch logic doesn't restrict schemes to http(s)", param, schemeOf(payload)), baseline)...)
		}
	}
	return findings, nil
}

func schemeOf(payload string) string {
	if i := strings.Index(payload, "://"); i > 0 {
		return payload[:i]
	}
	return payload
}

// probeAndRecord fires one GET {target}?{param}={payload} request and, if
// the response looks like the target actually fetched the payload, builds
// a Finding. checkKind becomes part of Finding.ID; idSuffix is the short,
// readable identifier for the payload (e.g. "127.0.0.1", not the full
// "http://127.0.0.1/" it's wrapped into) used to build the rest of
// Finding.ID; description is used verbatim.
func (d *Detector) probeAndRecord(ctx context.Context, target, authToken, param, idSuffix, payload, checkKind, description string, baseline probeBaseline) []detectors.Finding {
	probeURL := buildProbeURL(target, param, payload)
	req, resp, body, err := d.doRequest(ctx, probeURL, authToken)
	if err != nil {
		return nil // one bad probe shouldn't abort the whole check family — same convention as engine.go's template loop
	}
	if !looksFetched(resp, body) {
		return nil
	}
	if baselineMatches(baseline, body) {
		return nil // indistinguishable from a known-inert control — not evidence of a fetch
	}
	return []detectors.Finding{{
		ID:          fmt.Sprintf("ssrf-%s-%s-%s", checkKind, param, sanitizeID(idSuffix)),
		Type:        "ssrf",
		Severity:    "high",
		Confidence:  confidenceFor(body),
		Target:      probeURL,
		Description: description,
		Evidence: map[string]string{
			"param":    param,
			"payload":  payload,
			"request":  detectors.FormatRequest(req.Method, req.URL.String(), req.Header, nil),
			"response": detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		},
	}}
}

// buildProbeURL sets param=payload on target's query string, preserving
// any existing query parameters already on target.
func buildProbeURL(target, param, payload string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target + "?" + param + "=" + url.QueryEscape(payload)
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// looksFetched is deliberately simple: a non-error status with a
// non-trivial body is the only target-agnostic signal available — real
// targets vary too much for a stricter universal rule. confidenceFor
// narrows this down further where the response shape allows it.
func looksFetched(resp *http.Response, body []byte) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return len(bytes.TrimSpace(body)) > minFetchedBodyLen
}

// confidenceFor returns "high" when the response body carries a
// recognizable fetched-content marker, "low" (manual triage) otherwise —
// same convention authbypass's checks already use for a heuristic-only
// signal. Checks, in order: a JSON {"data": "<base64>"} shape (vAPI's
// serversurfer, and plausibly other similar proxy-style endpoints) whose
// decoded content contains a recognizable marker; otherwise the raw body
// itself.
func confidenceFor(body []byte) string {
	var parsed struct {
		Data string `json:"data"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Data) > 10 {
		if decoded, err := base64.StdEncoding.DecodeString(parsed.Data); err == nil {
			if looksLikeFetchedContent(decoded) {
				return "high"
			}
		}
	}
	if looksLikeFetchedContent(body) {
		return "high"
	}
	return "low"
}

func looksLikeFetchedContent(content []byte) bool {
	markers := []string{"root:", "redis_version", "STAT ", "instance-id", "computeMetadata", "<html", "<!DOCTYPE"}
	s := string(content)
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// doRequest fires one GET request. Unlike every other detector's
// doRequest, this does not feed pkg/scanner/hosterrors — see this
// package's doc comment for why.
func (d *Detector) doRequest(ctx context.Context, fullURL, token string) (*http.Request, *http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssrf: building request: %w", err)
	}
	if token != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", token, 1))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssrf: fetching %s: %w", fullURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssrf: reading response body: %w", err)
	}
	return req, resp, body, nil
}
