package scanner

import (
	"errors"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
)

func TestAdaptiveThrottle_SustainedThrottling_HalvesThenAborts(t *testing.T) {
	lim := ratelimit.New(10)
	var logs int
	a := newAdaptiveThrottle(lim, 10, func(string, string, ...any) { logs++ })
	// Force each observe() past the time-window gate.
	a.windowStart = time.Now().Add(-adaptiveWindow - time.Second)

	// Window 1: 25 requests, 10 of them 429 (40% >= 30% threshold) -> degrade.
	for i := 0; i < 25; i++ {
		status := 200
		if i%2 == 0 && i < 20 {
			status = 429
		}
		a.observe(status, nil)
	}
	if lim.QPS() != 5 {
		t.Fatalf("expected rate halved to 5 after the first bad window, got %d", lim.QPS())
	}
	if a.tripped() != "" {
		t.Fatalf("must not abort on the first bad window")
	}

	// Window 2: still bad -> abort with the rate-limited reason.
	a.windowStart = time.Now().Add(-adaptiveWindow - time.Second)
	for i := 0; i < 25; i++ {
		status := 200
		if i < 15 {
			status = 503
		}
		a.observe(status, nil)
	}
	if got := a.tripped(); got != "rate-limited" {
		t.Fatalf("expected abort reason \"rate-limited\", got %q", got)
	}
}

func TestAdaptiveThrottle_ConnFailureSpike_NeedsPriorSuccess(t *testing.T) {
	lim := ratelimit.New(8)
	a := newAdaptiveThrottle(lim, 8, func(string, string, ...any) {})

	// No prior success yet: a pure connect-failure window must NOT trip
	// (could just be an unreachable target from the start).
	a.windowStart = time.Now().Add(-adaptiveWindow - time.Second)
	for i := 0; i < 25; i++ {
		a.observe(0, errors.New("dial tcp: connection refused"))
	}
	if a.tripped() != "" || a.degraded {
		t.Fatalf("a target that never answered must not trigger the unreachable path")
	}

	// Now with an earlier success on record, the same spike degrades then aborts.
	a.sawSuccess = true
	a.windowStart = time.Now().Add(-adaptiveWindow - time.Second)
	for i := 0; i < 25; i++ {
		a.observe(0, errors.New("dial tcp: connection refused"))
	}
	a.windowStart = time.Now().Add(-adaptiveWindow - time.Second)
	for i := 0; i < 25; i++ {
		a.observe(0, errors.New("dial tcp: connection refused"))
	}
	if got := a.tripped(); got != "unreachable" {
		t.Fatalf("expected abort reason \"unreachable\", got %q", got)
	}
}

func TestAdaptiveThrottle_HealthyTraffic_NoAction(t *testing.T) {
	lim := ratelimit.New(10)
	a := newAdaptiveThrottle(lim, 10, func(string, string, ...any) {})
	for i := 0; i < 200; i++ {
		a.windowStart = time.Now().Add(-adaptiveWindow - time.Second)
		a.observe(200, nil)
	}
	if lim.QPS() != 10 || a.tripped() != "" {
		t.Fatalf("healthy traffic must not throttle or abort (qps=%d tripped=%q)", lim.QPS(), a.tripped())
	}
}

func TestNilAdaptiveThrottle_IsSafe(t *testing.T) {
	var a *adaptiveThrottle
	a.observe(429, nil) // must not panic
	if a.tripped() != "" {
		t.Fatal("nil throttle is never tripped")
	}
}
