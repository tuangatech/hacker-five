package unit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/businesslogic"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func newBusinessLogicClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 20,
	})
}

func TestBusinessLogic_AllowWritesFalse_NoRequestsFired(t *testing.T) {
	var requestCount int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := businesslogic.New(newBusinessLogicClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", false)
	require.NoError(t, err)

	assert.Empty(t, findings)
	assert.Equal(t, int64(0), atomic.LoadInt64(&requestCount), "no HTTP request should be fired when allowWrites is false")
}

// couponMintApplyServer builds a mock crAPI-shaped server: mint accepts any
// coupon_code/amount pair unconditionally, and applyCredit computes the
// "credit" value the apply endpoint returns for a given injected amount —
// tests plug in different applyCredit functions to simulate a vulnerable vs.
// a correctly-validating target.
func couponMintApplyServer(t *testing.T, applyCredit func(amount float64) float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case businesslogic.DefaultCouponMintPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`"Coupon Added in database"`))
		case businesslogic.DefaultCouponApplyPath:
			var body struct {
				Amount json.Number `json:"amount"`
			}
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &body)
			amount, _ := body.Amount.Float64()
			credit := applyCredit(amount)
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"credit":%v,"message":"Coupon successfully applied!"}`, credit)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestBusinessLogic_CouponSelfMintCredit_Hit(t *testing.T) {
	// Vulnerable: reflects whatever amount the client supplied, plus a
	// small pre-existing baseline balance — same shape as the real,
	// live-confirmed crAPI response (2026-08-29).
	srv := couponMintApplyServer(t, func(amount float64) float64 { return amount + 100 })
	defer srv.Close()

	detector := businesslogic.New(newBusinessLogicClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", true)
	require.NoError(t, err)

	got := withPrefix(findings, "businesslogic-coupon-self-mint-credit")
	require.Len(t, got, 1)
	assert.Equal(t, "critical", got[0].Severity)
	assert.Equal(t, "high", got[0].Confidence)
}

func TestBusinessLogic_CouponSelfMintCredit_ServerValidatesAmount_NoFinding(t *testing.T) {
	// Safe: ignores the client-supplied amount entirely, always grants a
	// small, fixed legitimate value — must NOT trigger the finding, or the
	// check would be flagging every successful apply, not just an
	// unearned-credit one (the real false-positive risk this check's own
	// design comment documents).
	srv := couponMintApplyServer(t, func(_ float64) float64 { return 5 })
	defer srv.Close()

	detector := businesslogic.New(newBusinessLogicClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", true)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "businesslogic-coupon-self-mint-credit"))
}

// couponRaceServer builds a mock server whose apply endpoint has a
// check-then-act window keyed by coupon_code (matching real crAPI's own
// per-coupon_code SELECT) — vulnerable when raced, unless serialize is true
// (a mutex held for the whole check-then-act window, simulating a target
// that got this right). Keying by coupon_code, not a single global flag,
// matters: checkCouponSelfMintCredit and checkCouponApplyRace each mint and
// apply their own distinct coupon in the same Run, so a global flag would
// let the first check's real apply silently "consume" the race check's
// window for an unrelated coupon.
func couponRaceServer(t *testing.T, serialize bool) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	claimed := map[string]bool{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case businesslogic.DefaultCouponMintPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`"Coupon Added in database"`))
		case businesslogic.DefaultCouponApplyPath:
			// Read the full body first, same as crAPI's real view (Django
			// REST's request.data) — this is what makes withholding the
			// race client's last body byte an effective synchronization
			// point: the handler can't reach its check-then-act logic below
			// until the full body (including that final byte) has arrived.
			raw, _ := io.ReadAll(r.Body)
			var parsed struct {
				CouponCode string `json:"coupon_code"`
			}
			_ = json.Unmarshal(raw, &parsed)
			code := parsed.CouponCode

			if serialize {
				// Correct shape: check-then-act happens under one
				// continuous lock, so no second request for the same
				// coupon_code can slip in between the check and the write.
				mu.Lock()
				defer mu.Unlock()
				if claimed[code] {
					w.WriteHeader(http.StatusConflict)
					return
				}
				time.Sleep(20 * time.Millisecond) // simulated DB round trip
				claimed[code] = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"credit":1000099.0,"message":"Coupon successfully applied!"}`))
				return
			}
			// Vulnerable shape, mirroring crAPI's real SELECT-then-INSERT:
			// each individual read/write of claimed[code] is protected, but
			// the window between the check and the act is not — the actual
			// bug.
			mu.Lock()
			alreadyClaimed := claimed[code]
			mu.Unlock()
			if alreadyClaimed {
				w.WriteHeader(http.StatusConflict)
				return
			}
			time.Sleep(20 * time.Millisecond) // simulated check-then-act DB round trip
			mu.Lock()
			claimed[code] = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"credit":1000099.0,"message":"Coupon successfully applied!"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestBusinessLogic_CouponApplyRace_Hit(t *testing.T) {
	srv := couponRaceServer(t, false)
	defer srv.Close()

	detector := businesslogic.New(newBusinessLogicClient(), businesslogic.WithRaceConcurrency(10))
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", true)
	require.NoError(t, err)

	got := withPrefix(findings, "businesslogic-coupon-apply-race")
	require.Len(t, got, 1)
	assert.Equal(t, "high", got[0].Severity)
	assert.Equal(t, "high", got[0].Confidence)
}

func TestBusinessLogic_CouponApplyRace_Serialized_NoFinding(t *testing.T) {
	srv := couponRaceServer(t, true)
	defer srv.Close()

	detector := businesslogic.New(newBusinessLogicClient(), businesslogic.WithRaceConcurrency(10))
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", true)
	require.NoError(t, err)

	assert.Empty(t, withPrefix(findings, "businesslogic-coupon-apply-race"))
}
