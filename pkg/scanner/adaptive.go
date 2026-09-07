package scanner

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
)

// adaptiveThrottle watches the rolling outcome of the scan's own HTTP
// requests and reacts when a target turns hostile mid-run
// (docs/follow-up.md LT-74 / LT-88):
//
//   - sustained 429/503 (the target is throttling us) — halve the effective
//     rate limit; if it persists through the next window, abort the target
//     with a scan-target-rate-limited finding;
//   - a spike of connect-timeout / connection-refused after we had already
//     been getting real responses (the target — or an origin IP — dropped
//     us) — same halve-then-abort, ending in a
//     scan-target-unreachable-mid-run finding.
//
// One monitor per scan. State is global rather than per-host: a bug-bounty
// scan is effectively single-host, and the emitted finding is labelled with
// whichever target the engine was working when the trip was noticed.
type adaptiveThrottle struct {
	limiter *ratelimit.Limiter
	baseQPS int
	warnf   func(level, format string, args ...any)

	mu          sync.Mutex
	windowStart time.Time
	total       int
	throttled   int // 429 / 503
	unreachable int // connect timeout / refused / reset
	sawSuccess  bool
	degraded    bool
	tripReason  string // "" until a trip; then "rate-limited" | "unreachable"
}

const (
	adaptiveWindow          = 20 * time.Second
	adaptiveMinSamples      = 20
	adaptiveThrottleBadFrac = 0.30
	adaptiveUnreachBadFrac  = 0.50
)

func newAdaptiveThrottle(limiter *ratelimit.Limiter, baseQPS int, warnf func(string, string, ...any)) *adaptiveThrottle {
	return &adaptiveThrottle{
		limiter:     limiter,
		baseQPS:     baseQPS,
		warnf:       warnf,
		windowStart: time.Now(),
	}
}

// observe records one fully-resolved request outcome (status 0 = transport
// error). Safe to call from every scan worker concurrently.
func (a *adaptiveThrottle) observe(status int, err error) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.tripReason != "" {
		return // already decided; stop accounting
	}

	a.total++
	switch {
	case status == 429 || status == 503:
		a.throttled++
	case err != nil && isConnFailure(err):
		a.unreachable++
	case status >= 200 && status < 500:
		a.sawSuccess = true
	}

	if time.Since(a.windowStart) < adaptiveWindow || a.total < adaptiveMinSamples {
		return
	}
	a.evaluateLocked()
}

// evaluateLocked runs at each window boundary with the mutex held.
func (a *adaptiveThrottle) evaluateLocked() {
	throttleFrac := float64(a.throttled) / float64(a.total)
	unreachFrac := float64(a.unreachable) / float64(a.total)

	switch {
	case throttleFrac >= adaptiveThrottleBadFrac:
		a.reactLocked("rate-limited",
			"upstream is returning sustained 429/503 (%.0f%% of the last %d requests)", throttleFrac*100, a.total)
	case unreachFrac >= adaptiveUnreachBadFrac && a.sawSuccess:
		a.reactLocked("unreachable",
			"connect failures spiked mid-scan (%.0f%% of the last %d requests) against a host that was answering earlier", unreachFrac*100, a.total)
	default:
		// Healthy window — recover toward the base rate and clear the flag.
		if a.degraded {
			a.degraded = false
			if cur := a.limiter.QPS(); cur < a.baseQPS {
				a.limiter.SetQPS(a.baseQPS)
				a.warnf("info", "adaptive throttle: target recovered — rate limit restored to %d req/s", a.baseQPS)
			}
		}
	}
	a.resetWindowLocked()
}

// reactLocked degrades on the first bad window, aborts on the second.
func (a *adaptiveThrottle) reactLocked(reason, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	if !a.degraded {
		a.degraded = true
		newQPS := a.limiter.QPS() / 2
		a.limiter.SetQPS(newQPS)
		a.warnf("warn", "adaptive throttle: %s — halving rate limit to %d req/s; will abort this target if it continues", detail, a.limiter.QPS())
		return
	}
	a.tripReason = reason
	a.warnf("error", "adaptive throttle: %s — aborting remaining templates for this target (%s)", detail, reason)
}

func (a *adaptiveThrottle) resetWindowLocked() {
	a.windowStart = time.Now()
	a.total, a.throttled, a.unreachable = 0, 0, 0
}

// tripped reports the abort reason once the monitor has given up on the
// current target, or "" while the scan should continue.
func (a *adaptiveThrottle) tripped() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tripReason
}

// isConnFailure reports whether err is a connection-establishment failure
// (timeout, refused, reset) rather than a normal HTTP answer — the LT-88
// "the target dropped us" signal, distinct from a 429/503 the target chose
// to send.
func isConnFailure(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "eof")
}
