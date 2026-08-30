// Package businesslogic implements HackerFive's business-logic-flaw
// detector: the first (and only) detector in the project that performs
// mutating requests against a target, gated behind an explicit --allow-writes
// flag (see CLAUDE.md's Rules and docs/13-implementation-plan-ph4.md Step 3).
//
// Both built-in checks target crAPI's real coupon flow, confirmed via source
// and a live exploit chain (2026-08-29), not guessed:
//   - checkCouponSelfMintCredit: any authenticated user can mint an
//     arbitrary-value coupon (community service's AddNewCoupon has no
//     admin/role check) and apply it for real, unearned credit (workshop
//     service's ApplyCouponView never cross-checks the client-supplied
//     amount against the coupon's real stored value).
//   - checkCouponApplyRace: ApplyCouponView's own check-then-act (a raw-SQL
//     SELECT for "already applied", then an INSERT) has no visible
//     transaction/locking — firing concurrent applies of the same coupon via
//     a last-byte-sync raw connection (see raceclient.go) can win that race
//     and apply a should-be-single-use coupon more than once.
//
// Every check here needs --allow-writes; there is no read-only variant of
// either (doc13's Step 3 Design originally hoped crAPI's validate-coupon
// endpoint might let a check ship read-only — it's real and genuinely
// read-only, but it isn't the interesting bug; the real findings need the
// two write calls above). Run gates once at the top rather than per-check,
// since nothing currently built here is read-only.
package businesslogic

import (
	"context"
	"fmt"
	"net/url"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// Detector runs the built-in business-logic checks against a target.
type Detector struct {
	client *httpclient.Client

	// hostErrors stops a run early once the target host crosses its
	// consecutive-error threshold — this package's checks are a handful of
	// normal sequential/pooled requests through the shared client, the same
	// shape authbypass already uses it for (unlike ssrf, which dropped it
	// for a stated, different reason).
	hostErrors *hosterrors.Cache

	authHeaderName   string
	authHeaderFormat string
	couponMintPath   string
	couponApplyPath  string
	raceConcurrency  int

	// insecure mirrors httpclient.Config.InsecureSkipVerify, duplicated here
	// because checkCouponApplyRace's raw net.Conn/tls.Dial path
	// (raceclient.go) bypasses httpclient.Client entirely and needs its own
	// TLS config.
	insecure bool
}

// Option configures a Detector at construction time. Mirrors
// authbypass.Option's shape exactly — same convention, not a new pattern.
type Option func(*Detector)

// WithAuthHeader overrides the header name/value format every request in
// this package carries authToken through. Same shape and
// same-argument-left-"" default-preserving behavior as
// authbypass.WithAuthHeader.
func WithAuthHeader(name, format string) Option {
	return func(d *Detector) {
		if name != "" {
			d.authHeaderName = name
		}
		if format != "" {
			d.authHeaderFormat = format
		}
	}
}

// WithCouponPaths overrides DefaultCouponMintPath/DefaultCouponApplyPath for
// a target other than crAPI. Either argument left "" preserves that half's
// package default.
func WithCouponPaths(mintPath, applyPath string) Option {
	return func(d *Detector) {
		if mintPath != "" {
			d.couponMintPath = mintPath
		}
		if applyPath != "" {
			d.couponApplyPath = applyPath
		}
	}
}

// WithRaceConcurrency overrides DefaultRaceConcurrency. n <= 0 is a no-op,
// preserving the package default.
func WithRaceConcurrency(n int) Option {
	return func(d *Detector) {
		if n > 0 {
			d.raceConcurrency = n
		}
	}
}

// WithInsecure mirrors httpclient.Config.InsecureSkipVerify for
// checkCouponApplyRace's raw-connection TLS handshake — see Detector.insecure.
func WithInsecure(insecure bool) Option {
	return func(d *Detector) {
		d.insecure = insecure
	}
}

// New constructs a Detector.
func New(client *httpclient.Client, opts ...Option) *Detector {
	d := &Detector{
		client:           client,
		hostErrors:       hosterrors.New(hosterrors.DefaultThreshold),
		authHeaderName:   DefaultAuthHeaderName,
		authHeaderFormat: DefaultAuthHeaderFormat,
		couponMintPath:   DefaultCouponMintPath,
		couponApplyPath:  DefaultCouponApplyPath,
		raceConcurrency:  DefaultRaceConcurrency,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Run checks target's coupon flow for business-logic flaws. allowWrites
// gates the whole detector: false means every check here is skipped (the
// caller — pkg/scanner/engine.go — already prints a stderr warning once per
// scan when --allow-writes is absent, so this returns silently rather than
// warning a second time per target).
func (d *Detector) Run(ctx context.Context, target, authToken string, allowWrites bool) ([]detectors.Finding, error) {
	if !allowWrites {
		return nil, nil
	}
	host, err := hostOf(target)
	if err != nil {
		return nil, fmt.Errorf("businesslogic: %w", err)
	}

	var findings []detectors.Finding
	// checkCouponApplyRace mints its own, separate coupon from
	// checkCouponSelfMintCredit — deliberately, so the two checks stay
	// order-independent (neither depends on state the other left behind).
	checks := []func(context.Context, string, string, string) ([]detectors.Finding, error){
		d.checkCouponSelfMintCredit,
		d.checkCouponApplyRace,
	}
	for _, check := range checks {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		if d.hostErrors.ShouldSkip(host) {
			break
		}
		fs, err := check(ctx, target, host, authToken)
		if err != nil {
			return findings, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

func hostOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing target URL: %w", err)
	}
	return u.Host, nil
}
