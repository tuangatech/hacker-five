package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scanner/workerpool"
)

const (
	// maxRedirects caps how many redirects the scanner's HTTP client follows
	// before returning the last response as-is.
	maxRedirects = 5
	// Retry policy for transient connection errors and 5xx/429 responses.
	retryMaxAttempts = 3
	retryBackoff     = 500 * time.Millisecond
	// idEnumRangeStart/End bound the sequential ID strategy used for IDOR
	// enumeration in Phase 1a — no wordlist/config surface for this yet.
	idEnumRangeStart = 1
	idEnumRangeEnd   = 100
)

// Engine orchestrates a single scan run across every configured target.
type Engine struct {
	cfg    Config
	client *httpclient.Client
}

// New constructs an Engine from a validated Config.
func New(cfg Config) *Engine {
	client := httpclient.New(httpclient.Config{
		Timeout:             cfg.Timeout,
		MaxRedirects:        maxRedirects,
		InsecureSkipVerify:  cfg.Insecure,
		MaxIdleConnsPerHost: cfg.Concurrency,
		ProxyURL:            cfg.ProxyURL,
	}, httpclient.WithRetry(retryMaxAttempts, retryBackoff))

	return &Engine{cfg: cfg, client: client}
}

// Run executes the scan and returns every finding across all targets.
//
// Unrecognized Detector values are already rejected by Config.Validate()
// before Run is ever called, so runDetector's default branch below can
// never actually be reached in practice — it exists only as a safety net.
func (e *Engine) Run(ctx context.Context) ([]detectors.Finding, error) {
	threshold := e.cfg.HostErrorThreshold
	if threshold == 0 {
		threshold = hosterrors.DefaultThreshold
	}
	hostCache := hosterrors.New(threshold)
	limiter := ratelimit.New(e.cfg.RateLimit)
	pool := workerpool.New(ctx, e.cfg.Concurrency, 2*e.cfg.Concurrency)

	var (
		mu       sync.Mutex
		findings []detectors.Finding
	)

	for _, target := range e.cfg.Targets {
		target := target
		host, err := hostOf(target)
		if err != nil {
			return nil, fmt.Errorf("parsing target %q: %w", target, err)
		}

		err = pool.Submit(func(ctx context.Context) error {
			if hostCache.ShouldSkip(host) {
				return nil
			}
			if err := limiter.Wait(ctx); err != nil {
				return err
			}

			results, err := e.runDetector(ctx, target)
			if err != nil {
				hostCache.RecordError(host)
				return fmt.Errorf("running %s detector against %s: %w", e.cfg.Detector, target, err)
			}
			hostCache.RecordSuccess(host)

			mu.Lock()
			findings = append(findings, results...)
			mu.Unlock()
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("submitting scan job for %s: %w", target, err)
		}
	}

	if errs := pool.Wait(); len(errs) > 0 {
		return findings, fmt.Errorf("scan completed with %d error(s), first: %w", len(errs), errs[0])
	}
	return findings, nil
}

func (e *Engine) runDetector(ctx context.Context, target string) ([]detectors.Finding, error) {
	switch e.cfg.Detector {
	case "idor":
		endpointTemplate := strings.TrimRight(target, "/") + e.cfg.EndpointTemplate
		strategy := idor.SequentialIntStrategy{Start: idEnumRangeStart, End: idEnumRangeEnd}
		detector := idor.New(e.client, strategy)
		return detector.Run(ctx, endpointTemplate, e.cfg.AuthToken, e.cfg.OtherAuthToken)
	default:
		return nil, fmt.Errorf("unsupported detector %q", e.cfg.Detector)
	}
}

func hostOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	return u.Host, nil
}
