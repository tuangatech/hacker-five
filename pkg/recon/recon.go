package recon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
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
	// DefaultCrawlDepth is katana's -depth for Wave 3. Kept at 2 so a run
	// with no explicit --crawl-depth is byte-for-byte the crawl it was
	// before the knob existed (docs/follow-up.md LT-8, Phase 8 Step 5).
	DefaultCrawlDepth = 2
)

// DefaultHeadlessCrawlTimeout is the wall-clock cap on the Wave 3 katana
// invocation when --headless-crawl is set — larger than DefaultWaveTimeout
// because a headless (real-browser, JS-rendering) crawl is materially slower
// per page than the link-following default, and the first run on a host with
// no local Chrome also pays a one-time Chromium download (LT-99,
// docs/follow-up.md). An explicit WithWaveTimeout larger than this still
// wins. Override process-wide with HACKERFIVE_RECON_HEADLESS_TIMEOUT (a Go
// duration string, e.g. "300s"); an invalid or non-positive value is ignored.
const DefaultHeadlessCrawlTimeout = 180 * time.Second

// headlessCrawlTimeoutEnv is the process-wide override for
// DefaultHeadlessCrawlTimeout.
const headlessCrawlTimeoutEnv = "HACKERFIVE_RECON_HEADLESS_TIMEOUT"

// envHeadlessCrawlTimeout returns the duration in headlessCrawlTimeoutEnv, or
// 0 if it is unset, empty, unparseable, or non-positive.
func envHeadlessCrawlTimeout() time.Duration {
	v, ok := os.LookupEnv(headlessCrawlTimeoutEnv)
	if !ok || strings.TrimSpace(v) == "" {
		return 0
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// DefaultWaveTimeout bounds each external-binary invocation (subfinder,
// tlsx, dnsx, naabu, httpx, katana) so one hung or slow wave can't stall
// the whole Run past a caller's own context deadline unnoticed. It was a
// hard-coded const with no override until LT-111 (docs/follow-up.md): a
// subfinder enumeration of a broad apex routinely finishes right around
// 60s, so one run returned 24 hosts and the next returned 3, non-
// deterministically starving every later wave. Override
// per run with WithWaveTimeout, or process-wide with the
// HACKERFIVE_RECON_WAVE_TIMEOUT env var (a Go duration string, e.g.
// "180s"); an invalid or non-positive value is ignored and this default
// stands.
const DefaultWaveTimeout = 60 * time.Second

// waveTimeoutEnv is the process-wide override for DefaultWaveTimeout.
const waveTimeoutEnv = "HACKERFIVE_RECON_WAVE_TIMEOUT"

// envWaveTimeout returns the duration in waveTimeoutEnv, or 0 if it is
// unset, empty, unparseable, or non-positive (callers keep their default).
func envWaveTimeout() time.Duration {
	v, ok := os.LookupEnv(waveTimeoutEnv)
	if !ok || strings.TrimSpace(v) == "" {
		return 0
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// DefaultBrowserUserAgent is the User-Agent recon's own direct HTTP probes
// send unless an operator overrides it with a --header of the same name.
// Recon's client previously sent Go's default ("Go-http-client/1.1"), which
// a UA-sniffing origin or a selective bot-challenge treats very differently
// from a browser: a plain nginx/PHP target answered 200 to Chrome and 302
// to the default UA, and a Cloudflare managed-challenge 403'd the default
// UA on every path — in both cases recon's own canary/common-path probes
// came back uniformly "blocked" while katana/httpx (which send a
// browser-ish UA, LT-4) had already crawled real content into the same
// result, and D6 then short-circuited the whole scan on a verdict the
// recon data itself refuted (docs/follow-up.md LT-75 / LT-81). Kept in
// sync in spirit with a current desktop Chrome release; the exact build
// number is not load-bearing.
const DefaultBrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// hasUserAgentOverride reports whether h carries a User-Agent key under any
// casing — HTTP header names are case-insensitive and an operator may pass
// "user-agent" or "User-Agent".
func hasUserAgentOverride(h map[string]string) bool {
	for k := range h {
		if strings.EqualFold(k, "User-Agent") {
			return true
		}
	}
	return false
}

// Recon runs the recon waves against a single target.
type Recon struct {
	client      *httpclient.Client
	hostErrors  *hosterrors.Cache
	scope       *scope.Scope // nil = no enforcement (a warning is appended, same posture as scan's --scope)
	rateLimit   int
	concurrency int
	crawlDepth  int
	waveTimeout time.Duration // per external-binary invocation; DefaultWaveTimeout unless overridden (LT-111)

	// headlessCrawl runs Wave 3's katana crawl in its real-browser headless
	// mode so a SPA's fetch()/XHR API surface — invisible to a link-following
	// crawl — is recovered (LT-99, docs/follow-up.md). Opt-in: heavy (renders
	// every page, pulls a Chromium on first use), so it only ever moves off
	// false when an operator passes --headless-crawl, and only takes effect at
	// DepthFull.
	headlessCrawl bool

	// paramMining runs Wave 3's hidden-parameter pass (LT-100,
	// docs/follow-up.md): probe a curated candidate-name list against the most
	// promising endpoints and emit the params the app measurably honours as
	// wave3-param-mining EndpointFacts. Opt-in, DepthFull only, hard per-run
	// request cap shared across every target (paramMineRequestCap, 0 =
	// maxParamMineRequests).
	paramMining         bool
	paramMiningWordlist string
	paramMineRequestCap int

	// contentDiscovery runs Wave 3's bounded unlinked-path sweep (Phase 8
	// Step 5 remainder, docs/17-implementation-plan-ph8.md): probe a curated
	// wordlist of common admin/backup/config-shaped paths a link-following
	// crawl can't reach, via httpx's own -path flag. Opt-in, DepthFull only,
	// same structural gate as headlessCrawl/paramMining above.
	contentDiscovery         bool
	contentDiscoveryWordlist string

	runBinary runFunc
	progress  func(wave, status string)
	headers   map[string]string // static request headers applied to every direct HTTP call and passed to httpx/katana via -H (LT-36)

	openAPISpecRefs []string // operator-supplied OpenAPI docs to walk into api-spec EndpointFacts (LT-89)
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

// WithCrawlDepth overrides DefaultCrawlDepth for Wave 3's katana crawl.
// Values below 1 are ignored (the default stands). A deeper crawl widens
// the endpoint set resolveEndpointFacts turns into idor/authbypass/ssrf
// candidates, at a proportional request-volume and wall-clock cost — so
// it moves off the default only when an operator asks for it
// (docs/follow-up.md LT-8, Phase 8 Step 5).
func WithCrawlDepth(d int) Option {
	return func(r *Recon) {
		if d >= 1 {
			r.crawlDepth = d
		}
	}
}

// WithHeadlessCrawl enables the real-browser (JS-rendering) katana mode for
// Wave 3, recovering the fetch()/XHR endpoints a SPA never exposes as links
// (LT-99, docs/follow-up.md — measured against crAPI: 4 endpoints
// link-crawled vs 40 from the OpenAPI spec). false is the pre-knob default
// crawl, byte-for-byte. Only takes effect at DepthFull; the katana
// invocation then runs under DefaultHeadlessCrawlTimeout rather than the
// per-wave timeout.
func WithHeadlessCrawl(on bool) Option {
	return func(r *Recon) {
		if on {
			r.headlessCrawl = true
		}
	}
}

// WithParamMining enables LT-100's hidden-parameter pass for Wave 3 —
// probing a curated candidate-name list against the top endpoints and
// emitting the params the app measurably honours (>= 2 diff-oracle signals)
// as `wave3-param-mining` EndpointFacts. Opt-in, DepthFull only. false is a
// no-op.
func WithParamMining(on bool) Option {
	return func(r *Recon) {
		if on {
			r.paramMining = true
		}
	}
}

// WithParamMiningWordlist points the LT-100 pass at an operator-supplied
// candidate-name list (one name per line, `#` comments ok) instead of the
// small built-in one. Empty keeps the built-in list.
func WithParamMiningWordlist(path string) Option {
	return func(r *Recon) {
		if strings.TrimSpace(path) != "" {
			r.paramMiningWordlist = path
		}
	}
}

// WithParamMiningRequestCap overrides the per-run request ceiling (shared
// across every target) for the LT-100 pass (default maxParamMineRequests).
// Values <= 0 keep the default.
func WithParamMiningRequestCap(n int) Option {
	return func(r *Recon) {
		if n > 0 {
			r.paramMineRequestCap = n
		}
	}
}

// WithContentDiscovery enables Phase 8 Step 5's bounded unlinked-path sweep
// for Wave 3 — a curated wordlist of common admin/backup/config-shaped
// paths probed via httpx's own -path flag against every seed, recorded as
// `wave3-content-discovery` EndpointFacts. Opt-in, DepthFull only. false is
// a no-op.
func WithContentDiscovery(on bool) Option {
	return func(r *Recon) {
		if on {
			r.contentDiscovery = true
		}
	}
}

// WithContentDiscoveryWordlist points the content-discovery sweep at an
// operator-supplied path list instead of the embedded default (SecLists'
// Discovery/Web-Content/common.txt, MIT-licensed, 4,751 entries — see
// contentdiscovery.go). Unlike WithParamMiningWordlist's capped override,
// a larger list here is the operator's own explicit choice and cost to
// bear — httpx's own -rl/-threads and this run's --wave-timeout are the
// only limits. Empty keeps the embedded default.
func WithContentDiscoveryWordlist(path string) Option {
	return func(r *Recon) {
		if strings.TrimSpace(path) != "" {
			r.contentDiscoveryWordlist = path
		}
	}
}

// WithOpenAPISpecs registers one or more operator-supplied OpenAPI/Swagger
// documents (a local file path or an http(s) URL each) to walk into
// api-spec EndpointFacts during Run — LT-89 (docs/follow-up.md). For the
// common case where the real spec is on disk or behind auth and so an
// unauthenticated recon never finds it served, this feeds the same
// walkOpenAPISpec path Wave 3's probeCommonPaths uses. Empty slice is a
// no-op. See IngestOpenAPISpecs for the walk/scope semantics.
func WithOpenAPISpecs(refs []string) Option {
	return func(r *Recon) {
		r.openAPISpecRefs = append(r.openAPISpecRefs, refs...)
	}
}

// WithHeaders registers static "Name: Value" request headers to attach to
// every request recon makes against the target — its own direct HTTP calls
// (Wave 0's security.txt/robots.txt, Wave 3's common-path/auth-boundary
// probes) and, via each tool's own -H flag, the httpx and katana subprocess
// crawls. The originating use is a bug-bounty program that mandates an
// identifying header on every test request (Meesho's `X-Hackerone: <user>`,
// .engagements/meesho/policy.md) — scan already threads one through
// (cmd/hackerfive/scan.go's --header); recon, plan's recon pass, and the
// standalone `recon` command did not, so that traffic went out unattributed
// (LT-36, docs/follow-up.md). dnsx/naabu/subfinder/tlsx take no HTTP header
// (DNS/port/passive-source work) and are unaffected. A nil or empty map is
// a no-op — same zero-behaviour-when-unused shape as the other options.
func WithHeaders(h map[string]string) Option {
	return func(r *Recon) {
		if len(h) == 0 {
			return
		}
		r.headers = make(map[string]string, len(h))
		for k, v := range h {
			r.headers[k] = v
		}
	}
}

// WithWaveTimeout overrides DefaultWaveTimeout — the wall-clock cap on each
// external-binary invocation (subfinder/tlsx/dnsx/naabu/httpx/katana).
// Values <= 0 are ignored (the default, or any HACKERFIVE_RECON_WAVE_TIMEOUT
// already applied, stands). LT-111 (docs/follow-up.md): 60s is too tight for
// subfinder against a broad apex, and a truncated enumeration silently
// starved every later wave.
func WithWaveTimeout(d time.Duration) Option {
	return func(r *Recon) {
		if d > 0 {
			r.waveTimeout = d
		}
	}
}

// withRun overrides the binary-execution function — test-only, unexported:
// production callers always get defaultRun.
func withRun(fn runFunc) Option {
	return func(r *Recon) { r.runBinary = fn }
}

// run executes one external recon binary under the caller-provided
// (wave-bounded) ctx. It wraps r.runBinary so that a bare errWaveTimeout
// from defaultRun — which has no way to know the configured cap — is
// re-stamped with r.waveTimeout, keeping the operator-facing "hit the Ns
// wave time cap" warning honest when WithWaveTimeout /
// HACKERFIVE_RECON_WAVE_TIMEOUT raised it (LT-111).
func (r *Recon) run(ctx context.Context, stdin, name string, args ...string) ([]byte, error) {
	out, err := r.runBinary(ctx, stdin, name, args...)
	var wt *errWaveTimeout
	if errors.As(err, &wt) && wt.cap == 0 {
		return out, &errWaveTimeout{cap: r.waveTimeout}
	}
	return out, err
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
		crawlDepth:  DefaultCrawlDepth,
		waveTimeout: DefaultWaveTimeout,
		runBinary:   defaultRun,
		progress:    func(string, string) {},
	}
	if d := envWaveTimeout(); d > 0 {
		r.waveTimeout = d // an explicit WithWaveTimeout option below still wins
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

	// LT-89 (docs/follow-up.md): fold any operator-supplied OpenAPI document
	// into api-spec EndpointFacts here — same walkOpenAPISpec path Wave 3's
	// probeCommonPaths uses for a spec it finds served, for the common case
	// where the real doc is on disk or behind auth. Independent of the wave
	// depth: a spec feed is useful even for a passive run.
	if len(r.openAPISpecRefs) > 0 {
		ing := IngestOpenAPISpecs(ctx, r.client, r.scope, r.headers, r.openAPISpecRefs, target)
		for _, ef := range ing.Endpoints {
			agg.addEndpoint(ef)
		}
		if ing.APISpec != nil {
			agg.addAPISpec(*ing.APISpec)
		}
		if ing.SignupEndpoint != nil {
			agg.setSignupEndpoint(*ing.SignupEndpoint)
		}
		if ing.CouponEndpoint != nil {
			agg.setCouponEndpoint(*ing.CouponEndpoint)
		}
		for _, h := range ing.OutOfScope {
			agg.addOutOfScope(h)
		}
		for _, w := range ing.Warnings {
			agg.addWarning("%s", w)
		}
	}

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
		pluginFacts := wordPressPluginFacts(agg.endpoints)
		for _, t := range pluginFacts {
			agg.addTech(t)
		}
		// LT-105 (docs/follow-up.md): must run after the tech facts above
		// (needs the "WordPress" core fact httpx-tech-detect may already
		// have added in Wave 2) and after pluginFacts is computed (its own
		// versions are the sanitizer's comparison set).
		agg.sanitizeWordPressCoreVersion(pluginFacts)
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

// applyHeaders sets every configured static header on req (LT-36), plus a
// default desktop-browser User-Agent (LT-75 / LT-81) whenever the operator
// hasn't overridden it. Called at each of this package's own
// http.NewRequestWithContext sites; a nil r.headers still gets the UA.
func (r *Recon) applyHeaders(req *http.Request) {
	if !hasUserAgentOverride(r.headers) {
		req.Header.Set("User-Agent", DefaultBrowserUserAgent)
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
}

// headerArgs renders the configured static headers as repeated "-H", "Name:
// Value" argument pairs for httpx and katana, which both accept -H exactly
// this way (verified against their -h output). A default desktop-browser
// User-Agent is included unless the operator overrode it, so the subprocess
// crawls observe the same thing recon's own client does (LT-75 / LT-81).
// Order is sorted so a run is reproducible and tests are stable.
func (r *Recon) headerArgs() []string {
	effective := make(map[string]string, len(r.headers)+1)
	if !hasUserAgentOverride(r.headers) {
		effective["User-Agent"] = DefaultBrowserUserAgent
	}
	for k, v := range r.headers {
		effective[k] = v
	}
	if len(effective) == 0 {
		return nil
	}
	names := make([]string, 0, len(effective))
	for k := range effective {
		names = append(names, k)
	}
	sort.Strings(names)
	args := make([]string, 0, len(names)*2)
	for _, k := range names {
		args = append(args, "-H", k+": "+effective[k])
	}
	return args
}
