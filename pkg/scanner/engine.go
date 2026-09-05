package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/detectors/authbypass"
	"github.com/tuangatech/hacker-five/pkg/detectors/businesslogic"
	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/detectors/misconfig"
	"github.com/tuangatech/hacker-five/pkg/detectors/ssrf"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
	"github.com/tuangatech/hacker-five/pkg/scanner/workerpool"
	"github.com/tuangatech/hacker-five/pkg/template/native"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
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

	// promptInjectionTag/promptInjectionSafeConcurrency back loadTemplates'
	// cost/latency guardrail (see docs/13-implementation-plan-ph4.md Step
	// 1): unlike every other template, a prompt-injection template's
	// request can trigger a real, metered/compute-heavy LLM inference call
	// on the target's own backend, so firing the default worker pool at it
	// imposes real cost/load in a way nothing else here does.
	promptInjectionTag             = "prompt-injection"
	promptInjectionSafeConcurrency = 5

	// defaultTemplateConcurrency is the per-target template fan-out (doc15
	// Step 6b) used when Config.TemplateConcurrency is unset. Sized to hide
	// per-request round-trip latency behind the shared rate limiter without a
	// large goroutine footprint once multiplied by the cross-target pool size
	// — the rate limiter (ratelimit.New(cfg.RateLimit)), not this number, is
	// the real throughput cap.
	defaultTemplateConcurrency = 10
)

// templateConcurrency resolves Config.TemplateConcurrency to its effective
// value, applying the default when unset. The prompt-injection cap is applied
// separately in Run (it needs the loaded template set to know whether any
// prompt-injection template is present).
func templateConcurrency(cfg Config) int {
	if cfg.TemplateConcurrency > 0 {
		return cfg.TemplateConcurrency
	}
	return defaultTemplateConcurrency
}

// Engine orchestrates a single scan run across every configured target.
type Engine struct {
	cfg    Config
	client *httpclient.Client

	findingCB func(detectors.Finding)
	logCB     func(level, msg string)
}

// WithFindingCallback registers fn to be invoked for every finding as its
// batch becomes available during Run (see emitFinding's granularity note),
// in addition to Run's existing return value — additive, not a replacement.
// The CLI (cmd/hackerfive/scan.go) never calls this, so its batch-only
// behavior is unchanged; only pkg/webui wires it, per
// docs/12-implementation-plan-ph3.md's "Live findings and logs" design.
func (e *Engine) WithFindingCallback(fn func(detectors.Finding)) *Engine {
	e.findingCB = fn
	return e
}

// WithLogCallback registers fn to be invoked alongside every stderr warning
// Run already prints (level is "warn" for scope/skip/summary notices, a
// rejected template, or a single template's execution error; "error" is
// reserved for a failed detector run against one target) — additive,
// stderr output is unchanged either way. See
// docs/12-implementation-plan-ph3.md's "Live findings and logs" design.
func (e *Engine) WithLogCallback(fn func(level, msg string)) *Engine {
	e.logCB = fn
	return e
}

// warnf prints a stderr warning exactly as Run always has, then also invokes
// logCB if one is registered — the single seam every stderr call site in this
// file now goes through, so CLI output never changes regardless of whether a
// caller (pkg/webui) is also listening.
func (e *Engine) warnf(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, msg)
	if e.logCB != nil {
		e.logCB(level, msg)
	}
}

// emitFinding invokes findingCB if one is registered. Called once per
// finding in each batch a detector or template run returns — not per
// individual HTTP response, since every detector's Run already returns
// ([]detectors.Finding, error) as one batch. True per-response streaming
// inside a single detector call would mean touching every detector's
// internals; per-batch granularity is still a large usability win over
// waiting for the whole multi-target scan, and is what
// docs/12-implementation-plan-ph3.md's Week 19 scope covers.
func (e *Engine) emitFinding(f detectors.Finding) {
	if e.findingCB != nil {
		e.findingCB(f)
	}
}

// New constructs an Engine from a validated Config.
func New(cfg Config) *Engine {
	// WithRateLimit before WithRetry: rate-limiting must be innermost so
	// every retry attempt re-enters it too, not just each request's first
	// attempt — see httpclient.New's ordering doc comment. Constructed here
	// (not in Run) so --rate-limit caps every actual HTTP request across the
	// whole scan, not just once per target job (a real gap a live 100-target
	// benchmark found — see docs/10-implementation-plan-ph1b.md's Definition
	// of Done).
	// MaxIdleConnsPerHost covers both fan-out axes: up to cfg.Concurrency
	// targets in flight across the cross-target pool, and (doc15 Step 6b) up to
	// templateConcurrency(cfg) templates in flight against any one of them —
	// summed so a single-target full-corpus scan's per-host connection reuse
	// isn't starved into per-request TCP/TLS churn that would add back the
	// round-trip dead time Step 6b removes.
	client := httpclient.New(httpclient.Config{
		Timeout:             cfg.Timeout,
		MaxRedirects:        maxRedirects,
		InsecureSkipVerify:  cfg.Insecure,
		MaxIdleConnsPerHost: cfg.Concurrency + templateConcurrency(cfg),
		ProxyURL:            cfg.ProxyURL,
	}, httpclient.WithRateLimit(ratelimit.New(cfg.RateLimit)), httpclient.WithRetry(retryMaxAttempts, retryBackoff))

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
	pool := workerpool.New(ctx, e.cfg.Concurrency, 2*e.cfg.Concurrency)

	sc, err := e.loadScope()
	if err != nil {
		return nil, err
	}
	e.warnIfWritesUngated()

	nucleiTemplates, nativeTemplates := e.loadTemplates()
	// WithOOBServers reuses the same cfg.OOBServers --oob-server/--no-oob
	// value the ssrf detector's own blind check already uses (see
	// cfg.OOBServers' doc comment) — one config surface, not a second
	// OOB-server flag just for template-driven interactsh_ checks.
	// Registration against it only actually happens (nuclei.Executor.
	// ensureOOBPoller) the first time a loaded template embeds
	// {{interactsh-url}}, so a scan/--templates set with none never talks
	// to an OOB server at all, default or not.
	nucleiExec := nuclei.New(e.client).WithHeaders(e.cfg.ExtraHeaders).WithOOBServers(e.cfg.OOBServers)
	defer nucleiExec.Close()
	nativeExec := native.New(e.client, e.idorOptions()...).WithHeaders(e.cfg.ExtraHeaders)

	// tmplConc is the per-target template fan-out (doc15 Step 6b). A
	// prompt-injection template forces the safe cap regardless of the
	// configured/default value — see promptInjectionSafeConcurrency.
	tmplConc := templateConcurrency(e.cfg)
	if tmplConc > promptInjectionSafeConcurrency && anyTemplateHasTag(nucleiTemplates, nativeTemplates, promptInjectionTag) {
		e.warnf("info", "per-target template concurrency capped at %d (from %d): a prompt-injection template is loaded — its request can trigger a real, metered LLM call on the target's backend",
			promptInjectionSafeConcurrency, tmplConc)
		tmplConc = promptInjectionSafeConcurrency
	}

	var (
		mu       sync.Mutex
		findings []detectors.Finding
	)

	for _, target := range e.cfg.Targets {
		target := target

		if sc != nil && !sc.Allowed(target) {
			e.warnf("warn", "skipping %s: not covered by --scope %s", target, e.cfg.ScopeFile)
			continue
		}

		host, err := hostOf(target)
		if err != nil {
			return nil, fmt.Errorf("parsing target %q: %w", target, err)
		}

		err = pool.Submit(func(ctx context.Context) error {
			if hostCache.ShouldSkip(host) {
				return nil
			}

			results, err := e.runDetector(ctx, target)
			if err != nil {
				hostCache.RecordError(host)
				e.warnf("error", "running %s detector against %s: %v", e.cfg.Detector, target, err)
				return fmt.Errorf("running %s detector against %s: %w", e.cfg.Detector, target, err)
			}
			hostCache.RecordSuccess(host)
			for _, f := range results {
				e.emitFinding(f)
			}

			// Templates are additive on top of the built-in detector, not an
			// alternative to it (see docs/10-implementation-plan-ph1b.md
			// Step 1's rationale) — every loaded template runs against every
			// target, in addition to whichever --detector was selected above.
			// Fired with bounded intra-target concurrency (doc15 Step 6b); the
			// shared rate limiter still caps aggregate req/s, so this only
			// removes a sequential loop's per-request round-trip dead time.
			results = append(results, e.runTemplates(ctx, target, nucleiTemplates, nativeTemplates, nucleiExec, nativeExec, tmplConc)...)

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

// runTemplates fires every loaded template (both formats) against one target
// with up to conc running concurrently — the doc15 Step 6b inner fan-out on
// top of Run's cross-target worker pool. It returns every finding produced and
// also passes each to emitFinding as its batch lands, keeping the old
// sequential loop's per-batch callback granularity.
//
// The shared httpclient rate limiter still caps aggregate req/s across every
// worker here and every other in-flight target job, so conc only removes the
// per-request round-trip dead time of a sequential loop — it can't push the
// scan past --rate-limit. Finding order in the returned slice is completion
// order, not template-file order; nothing downstream relies on it
// (reporter.Dedup keys on Finding.ID, the report sorts by severity).
//
// ctx cancellation stops dispatch of any not-yet-started template (acquire
// selects on ctx.Done()); a template already in flight runs to its own
// ctx-aware completion. A single template's execution error is warn-logged and
// skipped, exactly as the pre-6b loop did — unless ctx is already done, where
// it's silent (the scan itself is stopping, logging the rest is just noise).
func (e *Engine) runTemplates(
	ctx context.Context,
	target string,
	nucleiTemplates []*nuclei.Template,
	nativeTemplates []*native.Template,
	nucleiExec *nuclei.Executor,
	nativeExec *native.Executor,
	conc int,
) []detectors.Finding {
	if conc < 1 {
		conc = 1
	}
	var (
		mu       sync.Mutex
		findings []detectors.Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, conc)
	)

	// acquire takes a concurrency slot, or reports false if ctx ends first so
	// the caller stops dispatching. Slots are released in fire's defer.
	acquire := func() bool {
		select {
		case sem <- struct{}{}:
			return true
		case <-ctx.Done():
			return false
		}
	}
	fire := func(id string, run func() ([]detectors.Finding, error)) {
		defer wg.Done()
		defer func() { <-sem }()
		fs, err := run()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.warnf("warn", "template %s against %s: %v", id, target, err)
			return
		}
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
		for _, f := range fs {
			e.emitFinding(f)
		}
	}

	for _, tmpl := range nucleiTemplates {
		if !acquire() {
			break
		}
		tmpl := tmpl
		wg.Add(1)
		go fire(tmpl.ID, func() ([]detectors.Finding, error) { return nucleiExec.Run(ctx, target, tmpl) })
	}
	for _, tmpl := range nativeTemplates {
		if !acquire() {
			break
		}
		tmpl := tmpl
		wg.Add(1)
		go fire(tmpl.ID, func() ([]detectors.Finding, error) {
			return nativeExec.Run(ctx, target, tmpl, e.cfg.AuthToken, e.cfg.OtherAuthToken)
		})
	}
	wg.Wait()
	return findings
}

// loadScope returns e.cfg.Scope if the caller already supplied a pre-parsed
// Scope (pkg/mcpserver's tool handlers do — doc15 Step 1), else parses
// e.cfg.ScopeFile if given. Returns (nil, nil) when neither is set — the
// documented "no enforcement" default (see docs/11-implementation-plan-ph2.md
// Step 0) — but prints a one-line stderr warning first, so a real-target run
// without scoping is visibly, not silently, unguarded. This warn-and-continue
// behavior is for a human-typed CLI command; an agent-initiated call is
// expected to reject a missing scope before ever constructing an Engine
// (doc15 Step 1's D3), not rely on this warning.
func (e *Engine) loadScope() (*scope.Scope, error) {
	if e.cfg.Scope != nil {
		return e.cfg.Scope, nil
	}
	if e.cfg.ScopeFile == "" {
		e.warnf("warn", "no --scope file provided — all targets will be scanned without authorization-scope validation")
		return nil, nil
	}
	sc, err := scope.Parse(e.cfg.ScopeFile)
	if err != nil {
		return nil, fmt.Errorf("loading --scope: %w", err)
	}
	return sc, nil
}

// warnIfWritesUngated mirrors loadScope's "warn, don't silently proceed"
// shape exactly: if --detector businesslogic was selected without
// --allow-writes, every mutating check in that detector's Run will
// self-gate to a silent no-op (see businesslogic.Detector.Run) — this is
// the one place that gets surfaced to the user, once per scan, so a
// businesslogic run that finds nothing because writes were never allowed
// doesn't look identical to one that genuinely found nothing.
func (e *Engine) warnIfWritesUngated() {
	if e.cfg.Detector == "businesslogic" && !e.cfg.AllowWrites {
		e.warnf("warn", "--allow-writes not set — businesslogic's mutating checks (coupon self-mint/apply, apply-race) will be skipped; pass --allow-writes to run them")
	}
}

// loadTemplates parses every template directory in cfg.TemplatePaths once,
// via both template formats, before any target is scanned — parsing is
// target-independent, so doing it once here (not per-target inside the pool)
// avoids re-parsing the same files once per target. Prints a one-line
// summary to stderr: this CLI has no other log output, so a typo'd
// --templates path silently loading zero templates would otherwise be
// invisible.
func (e *Engine) loadTemplates() ([]*nuclei.Template, []*native.Template) {
	var (
		nucleiTemplates []*nuclei.Template
		nativeTemplates []*native.Template
		rejected        []rejectedTemplate
	)
	for _, dir := range e.cfg.TemplatePaths {
		if dir == "" {
			continue
		}
		nt, nErrs := nuclei.LoadDirDetailed(dir)
		nucleiTemplates = append(nucleiTemplates, nt...)

		vt, vErrs := native.LoadDirDetailed(dir)
		nativeTemplates = append(nativeTemplates, vt...)

		// A file valid in one format is expected to fail the other format's
		// own parser (it's simply not written in that format) — only a
		// file rejected by *both* is a genuine problem worth surfacing. See
		// pkg/templatesync.List's countRejectedByBothFormats, the same fix
		// applied there for the Web UI's template count.
		rejected = append(rejected, rejectedByBothFormats(nErrs, vErrs)...)
	}
	for _, rt := range rejected {
		e.warnf("warn", "rejected template %s: not valid in either format (nuclei: %v; native: %v)", rt.Path, rt.NucleiErr, rt.NativeErr)
	}

	loadedNuclei, loadedNative := len(nucleiTemplates), len(nativeTemplates)
	// Effective tag scoping (doc15 Step 6a): an explicit --tags (cfg.Tags) is
	// authoritative and wins untouched; otherwise, unless --all-templates was
	// passed, scope to the detector-category floor ∪ tech-matched tags a
	// frontend composed into cfg.DerivedTags. Empty DerivedTags (e.g.
	// --detector businesslogic, which has no floor) falls through to the full
	// corpus, same as before this change.
	scopeTags := e.cfg.Tags
	scopeSource := "explicit --tags"
	if len(scopeTags) == 0 && !e.cfg.AllTemplates {
		scopeTags = e.cfg.DerivedTags
		scopeSource = "detector/tech scoping"
	}
	if len(scopeTags) > 0 {
		nucleiTemplates = filterNucleiByTags(nucleiTemplates, scopeTags)
		nativeTemplates = filterNativeByTags(nativeTemplates, scopeTags)
	}
	if e.cfg.TemplateID != "" {
		nucleiTemplates = filterNucleiByID(nucleiTemplates, e.cfg.TemplateID)
		nativeTemplates = filterNativeByID(nativeTemplates, e.cfg.TemplateID)
	}
	filtered := (loadedNuclei - len(nucleiTemplates)) + (loadedNative - len(nativeTemplates))
	if filtered > 0 && len(scopeTags) > 0 {
		e.warnf("info", "scoped to %d template tag(s) via %s: %s", len(scopeTags), scopeSource, strings.Join(scopeTags, ", "))
	}

	if e.cfg.Concurrency > promptInjectionSafeConcurrency && anyTemplateHasTag(nucleiTemplates, nativeTemplates, promptInjectionTag) {
		e.warnf("warn", "loaded template(s) tagged %q with --concurrency %d (safe default: %d) — unlike other templates, a prompt-injection request can trigger a real, metered LLM call on the target's backend; consider a lower --concurrency",
			promptInjectionTag, e.cfg.Concurrency, promptInjectionSafeConcurrency)
	}

	e.warnf("info", "loaded %d nuclei-compatible, %d native templates (%d rejected, %d filtered by tag)",
		len(nucleiTemplates), len(nativeTemplates), len(rejected), filtered)
	return nucleiTemplates, nativeTemplates
}

// rejectedTemplate is one file rejected by both template-format loaders —
// a genuine problem, as opposed to a file simply written in the other
// format (which is expected to fail one loader and succeed the other).
type rejectedTemplate struct {
	Path                 string
	NucleiErr, NativeErr error
}

// rejectedByBothFormats returns every path appearing in both nErrs and
// vErrs, paired with each format's own rejection reason — a file neither
// loader could parse. Duplicated (small, proportionate) from
// pkg/templatesync.List's own copy rather than shared: pkg/scanner doesn't
// otherwise depend on pkg/templatesync, and pulling in that whole package
// for one small helper isn't a good trade.
func rejectedByBothFormats(nErrs []nuclei.LoadError, vErrs []native.LoadError) []rejectedTemplate {
	nFailed := make(map[string]error, len(nErrs))
	for _, e := range nErrs {
		nFailed[e.Path] = e.Err
	}
	var rejected []rejectedTemplate
	for _, e := range vErrs {
		if nErr, ok := nFailed[e.Path]; ok {
			rejected = append(rejected, rejectedTemplate{Path: e.Path, NucleiErr: nErr, NativeErr: e.Err})
		}
	}
	return rejected
}

// anyTemplateHasTag reports whether any loaded template (either format)
// carries tag — used by loadTemplates' prompt-injection concurrency
// guardrail. Shares tagSet/normalizeTag with filterNucleiByTags/
// filterNativeByTags so "prompt-injection", "Prompt-Injection", etc. all
// match the same way --tags filtering already does.
func anyTemplateHasTag(nucleiTemplates []*nuclei.Template, nativeTemplates []*native.Template, tag string) bool {
	set := tagSet([]string{tag})
	for _, tmpl := range nucleiTemplates {
		for _, t := range strings.Split(tmpl.Info.Tags, ",") {
			if set[normalizeTag(t)] {
				return true
			}
		}
	}
	for _, tmpl := range nativeTemplates {
		for _, t := range tmpl.Tags {
			if set[normalizeTag(t)] {
				return true
			}
		}
	}
	return false
}

// filterNucleiByTags keeps only templates whose comma-separated info.tags
// intersects wanted — OR match, same semantics as upstream Nuclei's -tags
// flag: any one shared tag is enough to include the template.
func filterNucleiByTags(templates []*nuclei.Template, wanted []string) []*nuclei.Template {
	set := tagSet(wanted)
	var kept []*nuclei.Template
	for _, tmpl := range templates {
		for _, tag := range strings.Split(tmpl.Info.Tags, ",") {
			if set[normalizeTag(tag)] {
				kept = append(kept, tmpl)
				break
			}
		}
	}
	return kept
}

// filterNativeByTags is filterNucleiByTags's native-format counterpart —
// native.Template.Tags is already a slice, unlike nuclei's comma-separated
// string, so no split step is needed here.
func filterNativeByTags(templates []*native.Template, wanted []string) []*native.Template {
	set := tagSet(wanted)
	var kept []*native.Template
	for _, tmpl := range templates {
		for _, tag := range tmpl.Tags {
			if set[normalizeTag(tag)] {
				kept = append(kept, tmpl)
				break
			}
		}
	}
	return kept
}

// filterNucleiByID keeps only the template whose id: exactly matches id —
// unlike filterNucleiByTags (an OR match against a template's tags: block,
// which can match many templates), an id: is a stable, unique identifier,
// so this narrows to at most one entry. Used for a PlanTree leaf whose
// Detector names a specific template rather than one of the 5 built-in
// detectors (pkg/mcpserver's executor, doc15 Step 2 addendum).
func filterNucleiByID(templates []*nuclei.Template, id string) []*nuclei.Template {
	var kept []*nuclei.Template
	for _, tmpl := range templates {
		if tmpl.ID == id {
			kept = append(kept, tmpl)
		}
	}
	return kept
}

// filterNativeByID is filterNucleiByID's native-format counterpart.
func filterNativeByID(templates []*native.Template, id string) []*native.Template {
	var kept []*native.Template
	for _, tmpl := range templates {
		if tmpl.ID == id {
			kept = append(kept, tmpl)
		}
	}
	return kept
}

// tagSet normalizes wanted into a lookup set. Normalizing here (not just at
// the CLI flag) keeps filtering correct regardless of how Config.Tags was
// built — e.g. constructed directly in a test, not parsed from --tags.
func tagSet(tags []string) map[string]bool {
	set := make(map[string]bool, len(tags))
	for _, t := range tags {
		if t = normalizeTag(t); t != "" {
			set[t] = true
		}
	}
	return set
}

func normalizeTag(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}

func (e *Engine) runDetector(ctx context.Context, target string) ([]detectors.Finding, error) {
	switch e.cfg.Detector {
	case "":
		// A templates-only run — no built-in detector to dispatch (see
		// Config.TemplateID/ValidateOptions.SkipDetectorRequired). Run
		// already executes the loaded/filtered template set unconditionally
		// after this call returns, so there's nothing more to do here.
		return nil, nil
	case "idor":
		endpointTemplate := strings.TrimRight(target, "/") + e.cfg.EndpointTemplate
		strategy := idor.SequentialIntStrategy{Start: idEnumRangeStart, End: idEnumRangeEnd}
		// WithTemplatePreview/WithLogCallback are appended here, not folded
		// into idorOptions() — that set is also shared with the idor-tagged
		// native-template path (native.Executor.runIDOR), which shouldn't
		// fire an extra preview probe/log line per template. This
		// flag-driven --detector idor path is the one doc14 Step 7's
		// preview probe actually targets.
		opts := append(e.idorOptions(),
			idor.WithTemplatePreview(e.cfg.IDORPreview),
			idor.WithLogCallback(func(level, msg string) { e.warnf(level, "%s", msg) }),
		)
		detector := idor.New(e.client, strategy, opts...)
		return detector.Run(ctx, endpointTemplate, e.cfg.AuthToken, e.cfg.OtherAuthToken)
	case "misconfig":
		detector := misconfig.New(e.client)
		return detector.Run(ctx, target, e.cfg.AuthToken)
	case "authbypass":
		detector := authbypass.New(e.client, e.authbypassOptions()...)
		return detector.Run(ctx, target, e.cfg.AuthToken, e.cfg.OtherAuthToken, e.cfg.ProtectedPaths)
	case "ssrf":
		detector := ssrf.New(e.client, e.ssrfOptions()...)
		return detector.Run(ctx, target, e.cfg.AuthToken, e.cfg.SSRFParams, e.cfg.OOBServers)
	case "businesslogic":
		detector := businesslogic.New(e.client, e.businesslogicOptions()...)
		return detector.Run(ctx, target, e.cfg.AuthToken, e.cfg.AllowWrites)
	default:
		return nil, fmt.Errorf("unsupported detector %q", e.cfg.Detector)
	}
}

// idorOptions builds the idor.Option set every idor.Detector this Engine
// constructs is given — both the flag-driven --detector idor path
// (runDetector) and the template-driven idor-tagged-native-template path
// (native.Executor.runIDOR, via New). Safe to include unconditionally:
// idor.WithAuthHeader no-ops on empty strings, so an unset
// AuthHeaderName/AuthHeaderFormat leaves idor.Detector's own default in
// place.
func (e *Engine) idorOptions() []idor.Option {
	return []idor.Option{idor.WithAuthHeader(e.cfg.AuthHeaderName, e.cfg.AuthHeaderFormat)}
}

// authbypassOptions builds the authbypass.Option set the flag-driven
// --detector authbypass path applies (runDetector's "authbypass" case).
// WithAuthHeader is unconditional, same no-op-on-empty-string reasoning as
// idorOptions; WithLoginPaths/WithLogoutPaths are only appended when
// non-empty, since authbypass.New's own defaults (LoginPaths/LogoutPaths)
// already handle the omitted-flag case correctly on their own.
func (e *Engine) authbypassOptions() []authbypass.Option {
	opts := []authbypass.Option{authbypass.WithAuthHeader(e.cfg.AuthHeaderName, e.cfg.AuthHeaderFormat)}
	if len(e.cfg.LoginPaths) > 0 {
		opts = append(opts, authbypass.WithLoginPaths(e.cfg.LoginPaths))
	}
	if len(e.cfg.LogoutPaths) > 0 {
		opts = append(opts, authbypass.WithLogoutPaths(e.cfg.LogoutPaths))
	}
	return opts
}

// ssrfOptions builds the ssrf.Option set the flag-driven --detector ssrf
// path applies. WithAuthHeader is unconditional, same no-op-on-empty-string
// reasoning as idorOptions/authbypassOptions.
func (e *Engine) ssrfOptions() []ssrf.Option {
	return []ssrf.Option{ssrf.WithAuthHeader(e.cfg.AuthHeaderName, e.cfg.AuthHeaderFormat)}
}

// businesslogicOptions builds the businesslogic.Option set the flag-driven
// --detector businesslogic path applies. WithAuthHeader/WithInsecure are
// unconditional, same no-op-on-empty-string/pure-passthrough reasoning as
// idorOptions/ssrfOptions.
func (e *Engine) businesslogicOptions() []businesslogic.Option {
	opts := []businesslogic.Option{
		businesslogic.WithAuthHeader(e.cfg.AuthHeaderName, e.cfg.AuthHeaderFormat),
		businesslogic.WithInsecure(e.cfg.Insecure),
		businesslogic.WithCouponPaths(e.cfg.CouponMintPath, e.cfg.CouponApplyPath),
	}
	if e.cfg.RaceConcurrency > 0 {
		opts = append(opts, businesslogic.WithRaceConcurrency(e.cfg.RaceConcurrency))
	}
	return opts
}

func hostOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	return u.Host, nil
}
