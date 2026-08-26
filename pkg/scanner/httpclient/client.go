// Package httpclient wraps net/http with the middleware, timeout, redirect,
// TLS, and proxy behavior the scanner needs.
package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Config controls how a Client's underlying transport and http.Client behave.
type Config struct {
	Timeout             time.Duration // per-request; applied via context.WithTimeout in Do, not http.Client.Timeout, so a stuck request can't hold a worker-pool slot past this
	MaxRedirects        int           // 0 = don't follow; net/http follows by default, this makes it explicit
	InsecureSkipVerify  bool          // TLS verify off — only for lab targets with self-signed certs; defaults to false (verify on)
	MaxIdleConnsPerHost int           // explicit connection-pool size instead of relying on http.DefaultTransport's default of 2
	ProxyURL            string        // e.g. http://127.0.0.1:8080; parsed here — an invalid value is caught by scanner.Config.Validate() before a Client is ever constructed
}

// Client is a scanner-configured HTTP client with a middleware-decorated transport.
type Client struct {
	http    *http.Client
	timeout time.Duration
}

// New builds a Client. Each middleware wraps the previous result, so the
// *last* argument ends up outermost (its RoundTrip runs first on every
// request) and the *first* argument ends up innermost, closest to the real
// transport (its RoundTrip runs last, right before the network call) —
// verified against the wrapping loop below, not just asserted. This matters
// for e.g. WithRateLimit vs WithRetry: WithRateLimit needs to be innermost
// (passed first) so every retry attempt re-enters it, not just each
// request's first attempt.
func New(cfg Config, mws ...Middleware) *Client {
	transport := &http.Transport{
		MaxIdleConnsPerHost: cfg.MaxIdleConnsPerHost,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec // opt-in via --insecure, for lab targets only
	}
	if cfg.ProxyURL != "" {
		if proxyURL, err := url.Parse(cfg.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	var rt http.RoundTripper = transport
	for _, mw := range mws {
		rt = mw(rt)
	}

	return &Client{
		timeout: cfg.Timeout,
		http: &http.Client{
			Transport: rt,
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) > cfg.MaxRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// Do executes req with the client's per-request timeout applied. The
// returned response's Body, once fully read and closed by the caller,
// releases the timeout context — closing early does not leave the timer
// running for longer than necessary, and reading late does not get cut off
// as soon as RoundTrip returns.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(req.Context(), c.timeout)
	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("performing request: %w", err)
	}
	resp.Body = &cancelOnCloseBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

// cancelOnCloseBody ties a context's cancellation to the lifetime of the
// response body it belongs to, instead of to the Do call that returned it.
type cancelOnCloseBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelOnCloseBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}
