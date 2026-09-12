package sqli

import (
	"context"
	"fmt"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// shapeTolerancePct bounds how close two response body lengths must be to
// be treated as "the same page" — a real page isn't expected to render
// byte-identical twice (a nonce, a timestamp), but a structurally different
// result set (the boolean-false case) is expected to differ by far more
// than this. Same tolerance convention as pkg/uniformwall.sameShape.
const shapeTolerancePct = 0.10

// minShapeTolerance is the floor under shapeTolerancePct's relative bound,
// so a tiny baseline body (a handful of bytes) doesn't make the comparison
// unreasonably strict.
const minShapeTolerance = 32

// sameShape reports whether a and b are indistinguishable: same status,
// body lengths within tolerance.
func sameShape(a, b probeResult) bool {
	if a.status != b.status {
		return false
	}
	tol := int(float64(len(a.body)) * shapeTolerancePct)
	if tol < minShapeTolerance {
		tol = minShapeTolerance
	}
	d := len(a.body) - len(b.body)
	if d < 0 {
		d = -d
	}
	return d <= tol
}

// errorBasedCheck appends each errorPayloads entry to param's value and
// looks for a DBMS error signature present in the payload response but
// absent from baseline — the highest-confidence of the three techniques
// since a literal DBMS error string is distinctive and never expected in a
// normal response.
func (d *Detector) errorBasedCheck(ctx context.Context, target, param, authToken, host string, baseline probeResult) []detectors.Finding {
	baselineMatch := matchedErrorPattern(baseline.body)
	var findings []detectors.Finding
	for _, payload := range errorPayloads {
		if ctx.Err() != nil {
			return findings
		}
		probeURL := buildPayloadURL(target, param, payload)
		resp, ok := d.probeWithToken(ctx, probeURL, authToken, host)
		if !ok {
			continue
		}
		dbms := matchedErrorPattern(resp.body)
		if dbms == "" || dbms == baselineMatch {
			continue // no DBMS signature, or the same one the baseline already carries
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("sqli-error-%s-%s", sanitizeParam(param), sanitizeParam(payload)),
			Type:        "sqli",
			Severity:    "high",
			Confidence:  "high",
			Target:      probeURL,
			Description: fmt.Sprintf("parameter %q returned a %s error signature when a syntax-breaking payload was appended to its value, and the unmodified baseline request did not — the value is concatenated directly into a SQL query", param, dbms),
			Evidence: map[string]string{
				"param":    param,
				"payload":  payload,
				"dbms":     dbms,
				"request":  requestEvidenceFor(resp),
				"response": evidenceFor(resp),
			},
		})
		return findings // one confirmed error-based hit per param is enough; stop trying the rest
	}
	return findings
}

// booleanBasedCheck appends each booleanPairs entry's tautology and
// negation suffix and compares both against baseline: a vulnerable
// endpoint's "true" response is indistinguishable from baseline (the same
// row set is still returned) while its "false" response is materially
// different (the WHERE clause now excludes everything it previously
// matched). Requires both conditions — a param with no effect on output at
// all produces true==false==baseline and is correctly never flagged.
func (d *Detector) booleanBasedCheck(ctx context.Context, target, param, authToken, host string, baseline probeResult) []detectors.Finding {
	var findings []detectors.Finding
	for _, pair := range booleanPairs {
		if ctx.Err() != nil {
			return findings
		}
		trueURL := buildPayloadURL(target, param, pair.trueSuffix)
		trueResp, ok := d.probeWithToken(ctx, trueURL, authToken, host)
		if !ok {
			continue
		}
		falseURL := buildPayloadURL(target, param, pair.falseSuffix)
		falseResp, ok := d.probeWithToken(ctx, falseURL, authToken, host)
		if !ok {
			continue
		}
		if !sameShape(trueResp, baseline) {
			continue // the tautology itself already changed the response — not the clean signal this check needs
		}
		if sameShape(falseResp, trueResp) {
			continue // negation had no effect — the param likely isn't reaching a WHERE clause at all
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("sqli-boolean-%s-%s", sanitizeParam(param), pair.name),
			Type:        "sqli",
			Severity:    "high",
			Confidence:  "medium",
			Target:      trueURL,
			Description: fmt.Sprintf("parameter %q: a tautology (%s) appended to its value returned a response indistinguishable from the baseline, while the matching negation (%s) returned a materially different response — consistent with boolean-based blind SQL injection", param, pair.trueSuffix, pair.falseSuffix),
			Evidence: map[string]string{
				"param":          param,
				"true_payload":   pair.trueSuffix,
				"false_payload":  pair.falseSuffix,
				"request":        requestEvidenceFor(trueResp),
				"response":       evidenceFor(trueResp),
				"false_response": evidenceFor(falseResp),
			},
		})
		return findings
	}
	return findings
}

// timeBasedCheck is the last-resort technique for an endpoint with no
// visible content/error difference: append a DBMS-specific sleep payload
// and look for a response delay roughly matching the encoded sleep
// duration, confirmed by a second independent try before ever reporting —
// a noisier signal than the other two (network jitter, a genuinely slow
// backend), so it's held to a stricter bar: skipped entirely if baseline
// itself was already slow (a loaded/slow backend makes timing evidence
// meaningless), and only counted when both the first and the repeat-confirm
// request each independently show the delay.
func (d *Detector) timeBasedCheck(ctx context.Context, target, param, authToken, host string, baseline probeResult) []detectors.Finding {
	if baseline.elapsed >= timeBasedBaselineCeiling {
		return nil
	}
	var findings []detectors.Finding
	for _, tp := range timePayloads {
		if ctx.Err() != nil {
			return findings
		}
		probeURL := buildPayloadURL(target, param, tp.suffix)
		first, ok := d.probeWithToken(ctx, probeURL, authToken, host)
		if !ok || !delayedBy(baseline, first, tp.seconds) {
			continue
		}
		confirm, ok := d.probeWithToken(ctx, probeURL, authToken, host)
		if !ok || !delayedBy(baseline, confirm, tp.seconds) {
			continue // the first delay didn't repeat — likely jitter/a slow network hop, not the DB honoring a sleep
		}
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("sqli-time-%s-%s", sanitizeParam(param), sanitizeParam(tp.dbms)),
			Type:        "sqli",
			Severity:    "high",
			Confidence:  "medium",
			Target:      probeURL,
			Description: fmt.Sprintf("parameter %q: appending a %s sleep payload to its value delayed the response by roughly the encoded duration, repeatably across two independent requests, while the baseline responded quickly — consistent with time-based blind SQL injection", param, tp.dbms),
			Evidence: map[string]string{
				"param":            param,
				"payload":          tp.suffix,
				"dbms":             tp.dbms,
				"baseline_elapsed": baseline.elapsed.String(),
				"first_elapsed":    first.elapsed.String(),
				"confirm_elapsed":  confirm.elapsed.String(),
				"request":          requestEvidenceFor(first),
				"response":         evidenceFor(first),
			},
		})
		return findings
	}
	return findings
}

// timeBasedBaselineCeiling: skip the time-based check entirely when the
// baseline itself already took this long — a backend already slow enough
// to approach timePayloads' encoded sleep duration (5s) makes any timing
// comparison meaningless.
const timeBasedBaselineCeiling = 2 * time.Second

// delayedBy reports whether probe took at least minFraction of seconds
// longer than baseline — a tolerant lower bound (half the encoded sleep),
// not an exact match, since real network/processing overhead adds to the
// raw DB-side delay.
func delayedBy(baseline, probe probeResult, seconds float64) bool {
	delta := probe.elapsed - baseline.elapsed
	return delta.Seconds() >= seconds/2
}

// sanitizeParam turns a param/payload string into a safe Finding.ID
// fragment — same convention as ssrf.sanitizeID/authbypass.sanitizeID.
func sanitizeParam(s string) string {
	var b []byte
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			b = append(b, c)
		default:
			if len(b) == 0 || b[len(b)-1] != '-' {
				b = append(b, '-')
			}
		}
	}
	out := string(b)
	for len(out) > 0 && out[0] == '-' {
		out = out[1:]
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if out == "" {
		return "x"
	}
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}
