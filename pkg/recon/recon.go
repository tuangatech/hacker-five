package recon

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// DefaultRateLimit/DefaultConcurrency match scan's own --rate-limit/
// --concurrency defaults (cmd/hackerfive/scan.go) — the numbers passed to
// every external binary's own native rate/concurrency flag (naabu -rate,
// httpx -rl/-threads, katana -rl/-c, dnsx -rl), since a separate OS process
// structurally cannot route through pkg/scanner/httpclient's Go middleware.
// This is the real, honest reconciliation with "recon requests respect the
// existing rate-limit/concurrency defaults" — same configured numbers,
// enforced by each tool's own limiting flag rather than our own transport.
const (
	// DefaultRateLimit lowered 50 -> 10 on 2026-09-05 (follow-up.md's
	// Security & Scope Hardening section): 50 req/sec is a reasonable lab-
	// benchmark rate but too aggressive as a default for a real bounty/VDP
	// program's own limits. Raise it explicitly per engagement.
	DefaultRateLimit   = 10
	DefaultConcurrency = 25
)

// Recon runs the recon waves against a single target.
type Recon struct {
	client      *httpclient.Client
	hostErrors  *hosterrors.Cache
	scope       *scope.Scope // nil = no enforcement (a warning is appended, same posture as scan's --scope)
	rateLimit   int
	concurrency int
	run         runFunc
	progress    func(wave, status string)
}

// Option configures a Recon at construction time.
type Option func(*Recon)

// WithScope enforces s against every host discovered in Wave 1+ — hosts
// failing the check are excluded from every subsequent wave and recorded in
// ReconResult.OutOfScope, per docs/91-research-recon-phase.md's corrected
// Wave 1 ordering (the check runs immediately after passive enumeration,
// before Wave 2's first active probe).
func WithScope(s *scope.Scope) Option {
	return func(r *Recon) { r.scope = s }
}

// WithRateLimit overrides DefaultRateLimit.
func WithRateLimit(qps int) Option {
	return func(r *Recon) {
		if qps > 0 {
			r.rateLimit = qps
		}
	}
}

// WithConcurrency overrides DefaultConcurrency.
func WithConcurrency(n int) Option {
	return func(r *Recon) {
		if n > 0 {
			r.concurrency = n
		}
	}
}

// withRun overrides the binary-execution function — test-only, unexported:
// production callers always get defaultRun.
func withRun(fn runFunc) Option {
	return func(r *Recon) { r.run = fn }
}

// WithProgressCallback registers fn to be invoked as "wave0"/"wave1"/
// "wave2"/"wave3" transitions between "running" and "done" — Run has no
// other incremental signal (unlike scanner.Engine's WithFindingCallback/
// WithLogCallback), so a caller wanting to show live progress across a
// multi-wave run (pkg/webui's Guided Scan) has nothing else to hook into.
// Defaults to a no-op, same zero-behavior-change-when-unused shape as
// scanner.Engine's own callbacks.
func WithProgressCallback(fn func(wave, status string)) Option {
	return func(r *Recon) {
		if fn != nil {
			r.progress = fn
		}
	}
}

// ClientConfig returns cfg with InsecureSkipVerify forced to true — recon's
// own direct HTTP requests (Wave 0's security.txt fetch, Wave 3's
// probeCommonPaths/tagAuthBoundary) should default to the same TLS posture
// every external binary already in this pipeline stage hardcodes
// unconditionally: katana (pkg/engine/common/http.go) and httpx
// (common/httpx/httpx.go) both set InsecureSkipVerify: true with no flag to
// turn it off (confirmed against their own source, 2026-09-04). Without
// this, a host fronted by a self-signed/internal-CA cert made every direct
// probe fail with a TLS handshake error while katana crawled the same host
// fine moments earlier — silently, since nothing logged the failure either
// (LT-4, docs/follow-up.md). Every recon.New call site should build its
// Config through this function rather than setting InsecureSkipVerify
// itself; a caller-set value on cfg is deliberately overridden, not merely
// defaulted, so a stale `false` copy-pasted from a scan-oriented Config
// can't quietly reintroduce the mismatch. This has no effect on scan's own
// detector requests — the *httpclient.Client passed to New is a separate
// instance at every call site, never shared with scanner.Engine's.
func ClientConfig(cfg httpclient.Config) httpclient.Config {
	cfg.InsecureSkipVerify = true
	return cfg
}

// New builds a Recon. client is used for this package's own direct HTTP
// calls (Wave 0's security.txt fetch, Wave 3's probeCommonPaths) — the same
// rate-limited, circuit-broken client every detector already uses.
func New(client *httpclient.Client, opts ...Option) *Recon {
	r := &Recon{
		client:      client,
		hostErrors:  hosterrors.New(hosterrors.DefaultThreshold),
		rateLimit:   DefaultRateLimit,
		concurrency: DefaultConcurrency,
		run:         defaultRun,
		progress:    func(string, string) {},
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run executes Wave 0 through the wave depth permits, returning the
// aggregated ReconResult. target is normalized to a full URL first (a bare
// domain like "www.example.com" defaults to https://, the same assumption
// a browser's address bar makes on schemeless input — found live: an
// operator typing a bare domain into the Web UI's /recon form got an
// opaque "not a valid target URL" error instead of the obviously-intended
// https:// target); Run derives the bare domain for passive enumeration
// from the resulting URL.
func (r *Recon) Run(ctx context.Context, target string, depth Depth) (*ReconResult, error) {
	target = defaultScheme(target)
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("recon: %q is not a valid target URL", target)
	}
	domain := u.Hostname()

	agg := &aggregator{target: target}

	// Mirrors scan's own convention (pkg/scanner/engine.go's loadScope):
	// an explicitly-given target that --scope itself excludes is skipped
	// entirely, not touched by any wave including Wave 0 — a --scope file
	// governs every host recon would otherwise contact, not only ones it
	// discovers along the way.
	if r.scope != nil && !r.scope.Allowed(target) {
		agg.addOutOfScope(domain)
		agg.addWarning("target %s is not covered by --scope — recon skipped entirely", target)
		return agg.finalize(), nil
	}

	// Wave 0: zero-touch.
	r.progress("wave0", "running")
	r.runWave0(ctx, agg, target)
	r.progress("wave0", "done")

	// Wave 1: passive enumeration, then the scope cross-check — before any
	// active wave ever sees a host (docs/91-research-recon-phase.md's
	// corrected ordering).
	r.progress("wave1", "running")
	passiveHosts := r.runWave1(ctx, agg, domain)
	inScope := r.filterScope(agg, passiveHosts)
	r.progress("wave1", "done")

	if depth == DepthPassive {
		return agg.finalize(), nil
	}

	// Wave 2: active, low-noise — only against Wave 1's scope-filtered hosts.
	// target's own host:port is always included for httpx specifically
	// (runWave2), even when it differs from the bare domain subfinder/tlsx
	// queried (a non-default port, common for lab/staging targets) — Wave 1's
	// passive tools have no way to discover that port on their own.
	r.progress("wave2", "running")
	liveHosts := r.runWave2(ctx, agg, u.Host, inScope)
	r.progress("wave2", "done")

	if depth == DepthFull {
		// Wave 3: bounded crawl + common-path probing.
		r.progress("wave3", "running")
		r.runWave3(ctx, agg, target, liveHosts)
		r.progress("wave3", "done")

		// P1-3 (docs/follow-up.md): a third tech-signature layer, alongside
		// httpx's own -tech-detect and pkg/fingerprint's header/body/port
		// matching (runWave2) — parses wp-content plugin/theme asset paths
		// Wave 3's crawl just collected, no new network round trip. Only
		// reachable at DepthFull since Endpoints (agg.endpoints) are empty
		// before Wave 3 runs.
		for _, t := range wordPressPluginFacts(agg.endpoints) {
			agg.addTech(t)
		}
	}

	return agg.finalize(), nil
}

// defaultScheme prepends "https://" to target when it has no scheme —
// "www.example.com" and "https://www.example.com" should behave
// identically, matching what a browser's own address bar does with
// schemeless input. Anything already containing "://" (including a scheme
// this package doesn't expect, e.g. "ftp://") passes through unchanged;
// url.Parse in Run is still the real validity check, this only fixes the
// single most common way to type a target without one.
func defaultScheme(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	return "https://" + target
}

// waveTimeout bounds each external-binary invocation so one hung wave
// can't stall the whole Run past a caller's own context deadline going
// unnoticed.
const waveTimeout = 60 * time.Second
