// Package ssrf implements the SSRF (Server-Side Request Forgery) detector:
// internal-network/cloud-metadata targeting (with explicit blocklist-bypass
// encodings), scheme-based payloads (file/gopher/dict), and a blind,
// self-hosted-OOB-based check. See docs/13-implementation-plan-ph4.md Step
// 2 for the full design, including why cloud-metadata provider-specific
// headers (GCP/Azure/AWS IMDSv2) are out of reach for a pure
// single-URL-parameter SSRF vector — see rules.go's doc comment.
//
// Deliberately does not use pkg/scanner/hosterrors' per-host circuit
// breaker every other detector shares: that breaker exists to stop
// hammering a genuinely dead/unreachable host across potentially hundreds
// of sequential requests (idor's ID enumeration). SSRF's probe set is
// small and fixed (~20 payloads), and a request *timing out* is itself an
// expected, sometimes meaningful signal here — a target's backend hanging
// while it attempts to fetch an attacker-controlled internal/encoded
// address is not evidence the target itself is down. Sharing that
// circuit-breaker state caused a real, live-verified bug during Step 2's
// own verification: three consecutive encoded-bypass payloads (hex, two
// IPv6 forms) that made vAPI's own backend hang past the client timeout
// tripped the breaker and silently skipped checkSchemeBasedTargets
// entirely — including a real file:///etc/passwd finding that a direct
// curl confirmed works. See docs/13-implementation-plan-ph4.md Step 2's
// dated verification note.
package ssrf

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// Detector runs the built-in SSRF checks against a target.
type Detector struct {
	client *httpclient.Client

	authHeaderName   string
	authHeaderFormat string
}

// Option configures a Detector at construction time. Mirrors
// authbypass.Option's shape exactly — same convention, not a new pattern.
type Option func(*Detector)

// WithAuthHeader overrides the header name/value format used to carry an
// auth token on every probe request, for an SSRF-vulnerable endpoint that
// sits behind auth. "" for either argument preserves the package default
// ("Authorization"/"Bearer {token}"), same behavior as
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

// New constructs a Detector.
func New(client *httpclient.Client, opts ...Option) *Detector {
	d := &Detector{
		client:           client,
		authHeaderName:   DefaultAuthHeaderName,
		authHeaderFormat: DefaultAuthHeaderFormat,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Run checks target for SSRF via each of params — candidate query
// parameter names the target accepts a URL through (e.g. "url", "webhook",
// "callback"). authToken, if non-empty, is sent on every probe request per
// the configured auth header. If oobServers is non-empty (Interactsh-
// protocol server URLs, tried in order — see oob.NewClientWithFallback), the
// blind OOB check additionally runs; left empty, it's silently skipped — no
// warning, since omitting --oob-server is a normal, documented mode, unlike
// --scope's warn-on-absence.
func (d *Detector) Run(ctx context.Context, target, authToken string, params []string, oobServers []string) ([]detectors.Finding, error) {
	if _, err := hostOf(target); err != nil {
		return nil, fmt.Errorf("ssrf: %w", err)
	}

	// One inert baseline probe per param, up front — establishes what the
	// target's own response looks like when nothing was actually fetched,
	// so every real payload below can be judged against it instead of in
	// isolation. See probeBaseline's own doc comment (checks.go) for the
	// real false-positive class this closes.
	baselines := make(map[string]probeBaseline, len(params))
	for _, param := range params {
		if ctx.Err() != nil {
			break
		}
		baselines[param] = d.fetchBaseline(ctx, target, authToken, param)
	}

	var findings []detectors.Finding
	// checkSchemeBasedTargets first, deliberately: checkInternalTargets'
	// encoded-bypass payloads (hex/IPv6 forms especially) can make a
	// target's own outbound fetch hang indefinitely — live-verified
	// against vAPI (2026-08-29) to exhaust its worker pool for several
	// minutes under the shared httpclient's 3x retry-on-timeout, which
	// then starved later probes (including a real, independently
	// curl-confirmed file:// finding) of a working connection. Running the
	// higher-value, non-hanging scheme-based family first means a
	// resource-exhaustion cascade from the other family can't suppress it.
	checks := []func(context.Context, string, string, []string, map[string]probeBaseline) ([]detectors.Finding, error){
		d.checkSchemeBasedTargets,
		d.checkInternalTargets,
	}
	for _, check := range checks {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		fs, err := check(ctx, target, authToken, params, baselines)
		if err != nil {
			return findings, err
		}
		findings = append(findings, fs...)
	}

	if len(oobServers) > 0 && ctx.Err() == nil {
		fs, err := d.checkOOBCallback(ctx, target, authToken, params, oobServers)
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

// sanitizeID turns a payload/path string into a safe Finding.ID suffix,
// same convention as authbypass.sanitizeID, extended to also strip the
// bracket characters an IPv6-literal payload carries.
func sanitizeID(s string) string {
	r := strings.NewReplacer(
		"/", "-", "?", "-", "&", "-", "=", "-", ":", "-", ".", "-",
		"[", "", "]", "",
	)
	out := strings.Trim(r.Replace(s), "-")
	if out == "" {
		return "root"
	}
	return out
}
