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
	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/detectors/misconfig"
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
)

// Engine orchestrates a single scan run across every configured target.
type Engine struct {
	cfg    Config
	client *httpclient.Client
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
	client := httpclient.New(httpclient.Config{
		Timeout:             cfg.Timeout,
		MaxRedirects:        maxRedirects,
		InsecureSkipVerify:  cfg.Insecure,
		MaxIdleConnsPerHost: cfg.Concurrency,
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

	nucleiTemplates, nativeTemplates := e.loadTemplates()
	nucleiExec := nuclei.New(e.client).WithHeaders(e.cfg.ExtraHeaders)
	nativeExec := native.New(e.client, e.idorOptions()...).WithHeaders(e.cfg.ExtraHeaders)

	var (
		mu       sync.Mutex
		findings []detectors.Finding
	)

	for _, target := range e.cfg.Targets {
		target := target

		if sc != nil && !sc.Allowed(target) {
			fmt.Fprintf(os.Stderr, "skipping %s: not covered by --scope %s\n", target, e.cfg.ScopeFile)
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
				return fmt.Errorf("running %s detector against %s: %w", e.cfg.Detector, target, err)
			}
			hostCache.RecordSuccess(host)

			// Templates are additive on top of the built-in detector, not an
			// alternative to it (see docs/10-implementation-plan-ph1b.md
			// Step 1's rationale) — every loaded template runs against every
			// target, in addition to whichever --detector was selected
			// above. Sequential per target, not fanned into further pool
			// jobs: matches the default (small, curated) --templates set;
			// scanning the full opt-in synced corpus against many targets
			// will be slower, a pre-existing characteristic, not a new one.
			for _, tmpl := range nucleiTemplates {
				fs, err := nucleiExec.Run(ctx, target, tmpl)
				if err != nil {
					continue // one bad template shouldn't abort the whole target's scan
				}
				results = append(results, fs...)
			}
			for _, tmpl := range nativeTemplates {
				fs, err := nativeExec.Run(ctx, target, tmpl, e.cfg.AuthToken, e.cfg.OtherAuthToken)
				if err != nil {
					continue
				}
				results = append(results, fs...)
			}

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

// loadScope parses e.cfg.ScopeFile, if given. Returns (nil, nil) when
// ScopeFile is "" — the documented "no enforcement" default (see
// docs/11-implementation-plan-ph2.md Step 0) — but prints a one-line stderr
// warning first, so a real-target run without scoping is visibly, not
// silently, unguarded.
func (e *Engine) loadScope() (*scope.Scope, error) {
	if e.cfg.ScopeFile == "" {
		fmt.Fprintln(os.Stderr, "no --scope file provided — all targets will be scanned without authorization-scope validation")
		return nil, nil
	}
	sc, err := scope.Parse(e.cfg.ScopeFile)
	if err != nil {
		return nil, fmt.Errorf("loading --scope: %w", err)
	}
	return sc, nil
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
		rejected        int
	)
	for _, dir := range e.cfg.TemplatePaths {
		if dir == "" {
			continue
		}
		nt, nErrs := nuclei.LoadDir(dir)
		nucleiTemplates = append(nucleiTemplates, nt...)
		rejected += len(nErrs)

		vt, vErrs := native.LoadDir(dir)
		nativeTemplates = append(nativeTemplates, vt...)
		rejected += len(vErrs)
	}

	loadedNuclei, loadedNative := len(nucleiTemplates), len(nativeTemplates)
	if len(e.cfg.Tags) > 0 {
		nucleiTemplates = filterNucleiByTags(nucleiTemplates, e.cfg.Tags)
		nativeTemplates = filterNativeByTags(nativeTemplates, e.cfg.Tags)
	}
	filtered := (loadedNuclei - len(nucleiTemplates)) + (loadedNative - len(nativeTemplates))

	fmt.Fprintf(os.Stderr, "loaded %d nuclei-compatible, %d native templates (%d rejected, %d filtered by tag)\n",
		len(nucleiTemplates), len(nativeTemplates), rejected, filtered)
	return nucleiTemplates, nativeTemplates
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
	case "idor":
		endpointTemplate := strings.TrimRight(target, "/") + e.cfg.EndpointTemplate
		strategy := idor.SequentialIntStrategy{Start: idEnumRangeStart, End: idEnumRangeEnd}
		detector := idor.New(e.client, strategy, e.idorOptions()...)
		return detector.Run(ctx, endpointTemplate, e.cfg.AuthToken, e.cfg.OtherAuthToken)
	case "misconfig":
		detector := misconfig.New(e.client)
		return detector.Run(ctx, target, e.cfg.AuthToken)
	case "authbypass":
		detector := authbypass.New(e.client, e.authbypassOptions()...)
		return detector.Run(ctx, target, e.cfg.AuthToken, e.cfg.OtherAuthToken, e.cfg.ProtectedPaths)
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

func hostOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing URL: %w", err)
	}
	return u.Host, nil
}
