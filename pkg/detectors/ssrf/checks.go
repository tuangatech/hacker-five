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
	"regexp"
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
// only when the baseline request itself failed at the transport level (a
// real error, not any particular status code — see the LT-194 doc comment
// below on divergesFromBaseline for why status is no longer part of the
// capture gate); in that case comparisons are skipped entirely
// (conservative: never suppress a finding without a good baseline to judge
// it against).
type probeBaseline struct {
	ok         bool
	statusCode int
	bodyLen    int
}

// fetchBaseline fires one probe with baselinePayload and records its
// response status and body length — called once per param, before the real
// payload loops, and reused across every probeAndRecord call for that
// param. Captured for any status the request completes with, not just 200
// (LT-194, docs/follow-up.md): a target's own convention for "the fetch
// failed/was rejected" is not always 200, and divergesFromBaseline below
// needs to know what that convention actually looks like to compare a real
// payload's response against it.
func (d *Detector) fetchBaseline(ctx context.Context, target, authToken, param string) probeBaseline {
	probeURL := buildProbeURL(target, param, baselinePayload)
	_, resp, body, err := d.doRequest(ctx, probeURL, authToken)
	if err != nil {
		return probeBaseline{}
	}
	return probeBaseline{ok: true, statusCode: resp.StatusCode, bodyLen: len(bytes.TrimSpace(body))}
}

// divergesFromBaseline reports whether resp/body looks meaningfully
// different from what the same param/field's unreachable-control baseline
// produced — either a different status code, or a body length outside
// baselineTolerancePct. Replaces the old baselineMatches (which only ever
// asked "is this indistinguishable from the baseline," gating on an
// implicit assumption that any real fetch always answers 200 — see
// looksLikeSSRFResponse's doc comment for why that assumption broke on a
// real target).
func divergesFromBaseline(baseline probeBaseline, resp *http.Response, body []byte) bool {
	if !baseline.ok {
		return false
	}
	if resp.StatusCode != baseline.statusCode {
		return true
	}
	bodyLen := len(bytes.TrimSpace(body))
	delta := bodyLen - baseline.bodyLen
	if delta < 0 {
		delta = -delta
	}
	return float64(delta) > float64(baseline.bodyLen)*baselineTolerancePct
}

// checkInternalTargets probes each param with every loopback-encoding
// variant, RFC1918 sample, the target's own origin, and the cloud-metadata
// address (bare GET only — see rules.go's doc comment on why
// provider-specific headers aren't reachable through this vector).
func (d *Detector) checkInternalTargets(ctx context.Context, target, authToken string, params []string, baselines map[string]probeBaseline) ([]detectors.Finding, error) {
	var findings []detectors.Finding
	var payloads []string
	payloads = append(payloads, loopbackEncodings()...)
	payloads = append(payloads, internalNetworkSamples()...)
	// The target's own origin (LT-194, docs/follow-up.md): none of the
	// addresses above is guaranteed to have anything listening — a
	// container's loopback and RFC1918 samples are frequently unreachable
	// from inside it (found live: crAPI's workshop container has nothing
	// on 127.0.0.1). The target's own origin always is, and a target that
	// can be tricked into fetching its own front door is still a real
	// SSRF — a common way to reach an internal-only route that trusts
	// server-to-server calls. Same address WithBodyFill mode already uses
	// as its one internal-target payload (bodyFillSelfOriginHost); a plain
	// GET probe carries none of that mode's live-write risk, so it belongs
	// in the default sweep too, not behind a flag.
	payloads = append(payloads, bodyFillSelfOriginHost(target))

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
	if !looksLikeSSRFResponse(baseline, resp, body) {
		return nil
	}
	return []detectors.Finding{{
		ID:          fmt.Sprintf("ssrf-%s-%s-%s", checkKind, param, sanitizeID(idSuffix)),
		Type:        "ssrf",
		Severity:    "high",
		Confidence:  confidenceFor(resp.StatusCode, body),
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

// looksLikeSSRFResponse reports whether resp/body is evidence the payload's
// address was actually fetched. Two paths (LT-194, docs/follow-up.md):
//
//  1. A usable baseline exists (the unreachable-control probe completed):
//     resp/body counts as evidence when it diverges from that baseline —
//     a different status code, or a body length outside
//     baselineTolerancePct. Found live against crAPI's contact_mechanic:
//     its own success/error convention for a completed fetch is not always
//     HTTP 200 — a reachable payload answers 500 with the fetched content
//     embedded in a JSON field, an unreachable one answers 400, and both
//     differ from the .invalid control's own answer. The old check
//     (looksFetched, since removed) required resp.StatusCode == 200 before
//     ever comparing to a baseline at all, so this whole class of response
//     was invisible regardless of what its body contained.
//  2. No usable baseline (the control probe itself failed at the transport
//     level): falls back to the older absolute signal, 200 plus a
//     non-trivial body — conservative, since there's nothing to compare
//     against and guessing at what "different" means without a control is
//     how the exact false-positive class baselinePayload's own doc comment
//     describes gets reintroduced.
//
// Either path also requires the payload's own response body to clear
// minFetchedBodyLen — an empty or near-empty body is never evidence on its
// own, baseline or not.
func looksLikeSSRFResponse(baseline probeBaseline, resp *http.Response, body []byte) bool {
	if len(bytes.TrimSpace(body)) <= minFetchedBodyLen {
		return false
	}
	if baseline.ok {
		return divergesFromBaseline(baseline, resp, body)
	}
	return resp.StatusCode == http.StatusOK
}

// distinctiveFetchMarkers are specific enough to real external/internal
// service content (a passwd file, a Redis/Memcached stat dump, a cloud
// metadata response) that they're vanishingly unlikely to appear in a
// target's own generic error page — safe evidence of "high" confidence
// regardless of the response's status code.
var distinctiveFetchMarkers = []string{"root:", "redis_version", "STAT ", "instance-id", "computeMetadata"}

// genericHTMLMarkers indicate only "this looks like a rendered HTML page" —
// true of both a genuinely fetched internal page and a target's own
// generic error/exception page, so on their own they're trustworthy
// evidence of a real fetch only paired with a 2xx status. Found live
// against crAPI (LT-194, docs/follow-up.md): a scheme-based payload
// (file://, gopher://, dict://) that Django's requests library doesn't
// recognize raises an InvalidSchema exception the view's own
// except (MissingSchema, InvalidURL) clause doesn't catch, crashing the
// whole endpoint into Django's generic "Server Error (500)" template —
// which also contains "<html" and diverges from the baseline exactly the
// way a real reflected fetch would, but proves nothing was actually
// fetched (confirmed by hand: the body is a fixed, empty-detail crash
// page, identical for all three scheme payloads, never file contents).
var genericHTMLMarkers = []string{"<html", "<!DOCTYPE"}

// confidenceFor returns "high" when the response carries a recognizable
// fetched-content marker, "low" (manual triage) otherwise — same
// convention authbypass's checks already use for a heuristic-only signal.
// statusCode gates the generic HTML markers (see genericHTMLMarkers'
// comment); distinctiveFetchMarkers count at any status, since nothing
// short of a real fetch plausibly produces them. Checks, in order: a JSON
// {"data": "<base64>"} shape (vAPI's serversurfer, and plausibly other
// similar proxy-style endpoints) whose decoded content carries a marker;
// otherwise the raw body itself.
func confidenceFor(statusCode int, body []byte) string {
	successStatus := statusCode/100 == 2
	var parsed struct {
		Data string `json:"data"`
	}
	if json.Unmarshal(body, &parsed) == nil && len(parsed.Data) > 10 {
		if decoded, err := base64.StdEncoding.DecodeString(parsed.Data); err == nil {
			if looksLikeFetchedContent(decoded, successStatus) {
				return "high"
			}
		}
	}
	if looksLikeFetchedContent(body, successStatus) {
		return "high"
	}
	return "low"
}

func looksLikeFetchedContent(content []byte, successStatus bool) bool {
	s := string(content)
	for _, m := range distinctiveFetchMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	if !successStatus {
		return false
	}
	for _, m := range genericHTMLMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// bodyFillPlaceholder is the value WithBodyFill mode (LT-188 a) sends for
// every field it fills besides the one under test — not a real, meaningful
// value, just enough to (often) satisfy a target's own "field present and
// non-empty" required-field validation. Field names recon recovers carry no
// type information, so a field requiring a specific shape (a number, an id
// that must reference something real) may still reject this and 400 — an
// accepted false negative, not a wrong finding, same tradeoff
// checkBodyParamTargets' original single-field body already accepted in the
// other direction.
const bodyFillPlaceholder = "hackerfive-probe-value"

// buildProbeBody returns a JSON body with field set to payload. fill is nil
// in the package's default mode — exactly one field, same "names only, no
// values invented beyond the payload" scope checkBodyParamTargets originally
// held to. Non-empty (WithBodyFill, LT-188 a), every other name in fill also
// gets a value, so a target that validates its other required fields before
// attempting the URL fetch at all (crAPI's contact_mechanic) gets past that
// validation: values[k]'s literal verbatim (a true/false/integer the bundle
// itself declared for a strictly-typed field), else bodyFillPlaceholder.
func buildProbeBody(field, payload string, fill []string, values map[string]string) string {
	if len(fill) == 0 {
		return fmt.Sprintf(`{%q:%q}`, field, payload)
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
	body[field], _ = json.Marshal(payload)
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Sprintf(`{%q:%q}`, field, payload) // never expected: every value above is pre-validated
	}
	return string(b)
}

// jsonLiteralRe is the same true/false/integer whitelist
// recon.jsValueLiteral produces — checked again here so a value map from any
// caller can only ever inject one of those three shapes as raw JSON, never
// arbitrary text.
var jsonLiteralRe = regexp.MustCompile(`^(?:true|false|-?[0-9]{1,9})$`)

// fetchBodyBaseline is fetchBaseline's body-mode counterpart (LT-96,
// docs/follow-up.md). fill is threaded straight to buildProbeBody, so the
// baseline body has the same shape (single field, or field-filled) as the
// payload bodies it's compared against. Captured for any status, same
// LT-194 reasoning as fetchBaseline — this was the direct cause of the
// crAPI miss: the old status==200 gate here meant a target whose own
// unreachable-control answer is itself non-200 (crAPI's own generic 400)
// left baseline.ok permanently false, so no divergence comparison ever ran
// at all for that field.
func (d *Detector) fetchBodyBaseline(ctx context.Context, target, authToken, field string, fill []string, values map[string]string) probeBaseline {
	_, resp, body, err := d.doRequestBody(ctx, target, authToken, buildProbeBody(field, baselinePayload, fill, values))
	if err != nil {
		return probeBaseline{}
	}
	return probeBaseline{ok: true, statusCode: resp.StatusCode, bodyLen: len(bytes.TrimSpace(body))}
}

// probeAndRecordBody is probeAndRecord's body-mode counterpart: POSTs a
// JSON body with field set to payload (plus fill, in WithBodyFill mode)
// rather than injecting into the query string.
func (d *Detector) probeAndRecordBody(ctx context.Context, target, authToken, field, idSuffix, payload, checkKind, description string, baseline probeBaseline, fill []string, values map[string]string) []detectors.Finding {
	reqBody := buildProbeBody(field, payload, fill, values)
	req, resp, body, err := d.doRequestBody(ctx, target, authToken, reqBody)
	if err != nil {
		return nil
	}
	if !looksLikeSSRFResponse(baseline, resp, body) {
		return nil
	}
	return []detectors.Finding{{
		ID:          fmt.Sprintf("ssrf-body-%s-%s-%s", checkKind, field, sanitizeID(idSuffix)),
		Type:        "ssrf",
		Severity:    "high",
		Confidence:  confidenceFor(resp.StatusCode, body),
		Target:      target,
		Description: description,
		Evidence: map[string]string{
			"body_field": field,
			"payload":    payload,
			"request":    detectors.FormatRequest(req.Method, req.URL.String(), req.Header, []byte(reqBody)),
			"response":   detectors.FormatResponse(resp.StatusCode, resp.Header, body),
		},
	}}
}

// bodyFillCloudPath/bodyFillSchemePayload are two of the three representative
// payloads checkBodyParamTargets tries in WithBodyFill mode (LT-188 a),
// instead of the full sweep below — every probe in that mode may complete
// the endpoint's real action, not just read from it, so it stays
// deliberately small rather than multiplying a live-write risk by ~15
// payloads per field. The third, an internal-network address, is
// bodyFillSelfOriginPayload below, not a fixed loopback literal.
var bodyFillCloudPath = cloudMetadataPaths()[0]
var bodyFillSchemePayload = schemeBasedPayloads()[0]

// bodyFillSelfOriginHost returns the target's own host (and port, if any) —
// used as checkBodyParamTargets' one internal-network payload address in
// WithBodyFill mode, wrapped into "http://<host>/" the same way every other
// address in internalPayloads already is. Reachable for any target, unlike a
// fixed 127.0.0.1: in a multi-container deployment the vulnerable service's
// own loopback often isn't where the app it's meant to reach actually
// listens (found live: crAPI's workshop container has nothing on
// 127.0.0.1, so that payload alone proved nothing there), while the target's
// own origin always is. A target that fetches its own front door is still a
// real SSRF (a common way to reach an internal-only route that trusts
// server-to-server calls), and it needs no target-specific knowledge to
// pick. Falls back to the loopback literal only if target doesn't parse.
func bodyFillSelfOriginHost(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "127.0.0.1"
	}
	return u.Host
}

// checkBodyParamTargets is checkInternalTargets/checkSchemeBasedTargets'
// JSON-request-body counterpart (LT-96, docs/follow-up.md): a target may
// take the attacker-controlled URL in a body field rather than a query
// param — e.g. crAPI's contact_mechanic takes it as mechanic_api/repair_url.
// In the package's default mode (d.bodyFillFields empty), the probe body
// contains only the SSRF-candidate field, not the route's other possibly-
// required fields — a target with strict body validation may 400 before the
// payload is ever evaluated (verified live against crAPI's contact_mechanic,
// LT-188 a: the same generic 400 for a reachable and an unreachable payload).
// WithBodyFill trades that read-only safety for the ability to see past that
// validation at all — see its own doc comment for why that's gated.
func (d *Detector) checkBodyParamTargets(ctx context.Context, target, authToken string, bodyParams []string) ([]detectors.Finding, error) {
	if len(bodyParams) == 0 {
		return nil, nil
	}
	fill, values := d.bodyFillFields, d.bodyFillValues
	baselines := make(map[string]probeBaseline, len(bodyParams))
	for _, field := range bodyParams {
		if ctx.Err() != nil {
			break
		}
		baselines[field] = d.fetchBodyBaseline(ctx, target, authToken, field, fill, values)
	}

	var findings []detectors.Finding
	internalPayloads := []string{bodyFillSelfOriginHost(target)}
	cloudPaths := []string{bodyFillCloudPath}
	schemePayloads := []string{bodyFillSchemePayload}
	if len(fill) == 0 {
		// Full sweep, same LT-194 addition as checkInternalTargets: the
		// target's own origin is the one address most likely to actually
		// have something listening, so it belongs alongside the
		// loopback/RFC1918 samples here too, not just in WithBodyFill
		// mode's capped set above.
		internalPayloads = append(append([]string{bodyFillSelfOriginHost(target)}, loopbackEncodings()...), internalNetworkSamples()...)
		cloudPaths = cloudMetadataPaths()
		schemePayloads = schemeBasedPayloads()
	}

	for _, field := range bodyParams {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		baseline := baselines[field]
		for _, addr := range internalPayloads {
			findings = append(findings, d.probeAndRecordBody(ctx, target, authToken, field, addr, "http://"+addr+"/",
				"internal-target", fmt.Sprintf("body field %q accepted an internal-network address (%s) and the response suggests the server fetched it", field, addr), baseline, fill, values)...)
		}
		for _, path := range cloudPaths {
			payloadURL := "http://" + cloudMetadataTarget + path
			findings = append(findings, d.probeAndRecordBody(ctx, target, authToken, field, cloudMetadataTarget+path, payloadURL,
				"cloud-metadata", fmt.Sprintf("body field %q accepted a cloud-metadata URL (%s) via a bare GET and the response suggests the server fetched it", field, payloadURL), baseline, fill, values)...)
		}
		for _, payload := range schemePayloads {
			findings = append(findings, d.probeAndRecordBody(ctx, target, authToken, field, payload, payload,
				"scheme-based", fmt.Sprintf("body field %q accepted a %s payload and the response suggests the server fetched it — target's URL-fetch logic doesn't restrict schemes to http(s)", field, schemeOf(payload)), baseline, fill, values)...)
		}
	}
	return findings, nil
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

// doRequestBody fires one POST request with a JSON body — checkBodyParamTargets'
// counterpart to doRequest's bodyless GET (LT-96, docs/follow-up.md).
func (d *Detector) doRequestBody(ctx context.Context, target, token, reqBody string) (*http.Request, *http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(reqBody))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssrf: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", token, 1))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssrf: fetching %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ssrf: reading response body: %w", err)
	}
	return req, resp, body, nil
}
