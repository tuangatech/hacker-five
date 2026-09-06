package httpclient

import (
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
)

// retryAfterCeiling caps how long a server's Retry-After header can push a
// retry back. A 429/503 asking for a longer cooldown than this is returned to
// the caller as the answer rather than stalling a scan worker for minutes —
// an unattended run should back off and fail cleanly, not grind (doc15 Step 3,
// docs/follow-up.md).
const retryAfterCeiling = 30 * time.Second

// Middleware decorates a RoundTripper. Proxy support is not a middleware —
// it's set directly on the underlying http.Transport.Proxy in New.
type Middleware func(http.RoundTripper) http.RoundTripper

// roundTripperFunc adapts a plain function to the http.RoundTripper interface.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// WithLogging logs method, URL, outcome, and duration for every request.
func WithLogging() Middleware {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			start := time.Now()
			resp, err := next.RoundTrip(req)
			elapsed := time.Since(start)
			if err != nil {
				log.Printf("%s %s -> error: %v (%s)", req.Method, req.URL, err, elapsed)
				return resp, err
			}
			log.Printf("%s %s -> %d (%s)", req.Method, req.URL, resp.StatusCode, elapsed)
			return resp, nil
		})
	}
}

// WithHeaders sets extra headers on every outgoing request.
func WithHeaders(headers map[string]string) Middleware {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			return next.RoundTrip(req)
		})
	}
}

// WithRateLimit paces every actual outgoing request through limiter — one
// shared limiter across every worker in a scan, so --rate-limit caps real
// requests/sec regardless of concurrency. Must be passed to New() *before*
// WithRetry (i.e. as the innermost middleware — see New's doc comment on
// ordering): a live 100-target benchmark found that gating only once per
// target job (the previous design, in scanner.Engine.Run) let a single
// target's own dozens of detector requests fire completely unthrottled —
// passing this innermost instead means every retry attempt also re-enters
// the limiter, not just each target's first request. See
// docs/10-implementation-plan-ph1b.md's Definition of Done for the
// benchmark that found this.
func WithRateLimit(limiter *ratelimit.Limiter) Middleware {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if err := limiter.Wait(req.Context()); err != nil {
				return nil, err
			}
			return next.RoundTrip(req)
		})
	}
}

// WithRetry retries connection errors and 5xx/429 responses up to
// maxAttempts, with exponential backoff (capped at 2*backoff) plus up to
// ±20% jitter to avoid a thundering-herd retry pattern.
//
// A 429/503 carrying a Retry-After header (delta-seconds or HTTP-date form)
// overrides that computed delay: the wait becomes max(computed, Retry-After)
// so a server's stated cooldown is never undershot — no negative jitter is
// applied to it. A Retry-After beyond retryAfterCeiling is treated as "give
// up": the response is returned as the answer instead of blocking a worker.
//
// A 401/403/404 (or any other non-retried 4xx) is a real answer, not a
// transient failure — retrying it would corrupt IDOR baseline sampling, where
// a flaky retry could turn a clean "denied" signature into a mixed one.
func WithRetry(maxAttempts int, backoff time.Duration) Middleware {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			var resp *http.Response
			var err error
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				attemptReq := req
				if attempt > 1 && req.GetBody != nil {
					if body, gerr := req.GetBody(); gerr == nil {
						attemptReq = req.Clone(req.Context())
						attemptReq.Body = body
					}
				}

				resp, err = next.RoundTrip(attemptReq)
				if !shouldRetry(resp, err) || attempt == maxAttempts {
					return resp, err
				}

				delay := retryDelay(attempt, backoff)
				if resp != nil {
					if wait, ok := parseRetryAfter(resp, time.Now()); ok {
						if wait > retryAfterCeiling {
							// Longer than an unattended run should stall for —
							// hand the 429/503 back as the answer.
							return resp, err
						}
						if wait > delay {
							delay = wait
						}
					}
					_ = resp.Body.Close()
				}

				select {
				case <-req.Context().Done():
					return nil, req.Context().Err()
				case <-time.After(delay):
				}
			}
			return resp, err
		})
	}
}

// parseRetryAfter reads an RFC 9110 Retry-After header off resp — either
// delta-seconds ("120") or an HTTP-date — and returns how long to wait
// relative to now. ok is false when the header is absent or unparseable (a
// negative delta or a past date clamps to zero, still ok).
func parseRetryAfter(resp *http.Response, now time.Time) (wait time.Duration, ok bool) {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0, true
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

func shouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true // connection errors: refused/reset/timeout
	}
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
}

func retryDelay(attempt int, backoff time.Duration) time.Duration {
	delay := backoff * time.Duration(uint(1)<<uint(attempt-1))
	if max := 2 * backoff; delay > max {
		delay = max
	}
	jitter := 1 + (rand.Float64()*0.4 - 0.2) // ±20%
	return time.Duration(float64(delay) * jitter)
}
