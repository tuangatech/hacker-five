// Package massassignment implements HackerFive's native mass-assignment
// detector (docs/follow-up.md LT-133): a write endpoint (a self-service
// PUT/PATCH update) that binds a JSON request body straight onto its
// internal model with no field allow-list, so a client can set a field the
// API never documented or intended to expose (OWASP API6:2023). Live-
// observed as a miss on crAPI (2026-09-08) — the idor/authbypass/ssrf
// detectors already built here had nothing that tested this.
//
// Design constraints (this package's own "needs its own design pass" note
// in follow-up.md):
//
//   - **v1 scope: PUT/PATCH self-update only, POST-create deliberately
//     deferred.** The common, safe case is a self-service update route
//     (crAPI/most REST APIs: PATCH /users/me-shaped) where VerifyURL is the
//     same URL — no dynamic resource-ID discovery needed. A POST-create
//     endpoint mints a fresh server-side ID the detector would have to
//     recover from the write's own response before it could verify
//     anything — a harder, separate problem, logged as a follow-up rather
//     than guessed at here. Mirrors pkg/detectors/mutatebfla's own phased
//     build (DELETE shipped, PUT/PATCH explicitly deferred) — just inverted.
//
//   - **The probe field is always inert.** Every request adds exactly one
//     freshly-random, HackerFive-namespaced field (a "hackerfive_probe_"
//     key with a random hex value) alongside the caller's own legitimate
//     body — never a real, sensitive-shaped field name (role/is_admin/
//     balance/...). This is the key safety property: this detector can
//     never actually escalate privilege or corrupt real functionality by
//     running; it can only prove the *absence* of a field allow-list on
//     the endpoint under test. A Finding's own Description says so plainly
//     — confirmed real-world impact from an attacker who knows and targets
//     an actual sensitive field name is a distinct, unverified risk this
//     detector does not itself demonstrate.
//
//   - **Persistence is confirmed only by an independent follow-up read,
//     never the write's own response** — the same discipline
//     mutatebfla's DELETE-then-GET established: some backends echo
//     request input back in a write's response without ever having
//     actually stored it, which would otherwise read as a false positive.
//     A Finding fires only when the canary value survives to a *separate*
//     GET against VerifyURL.
//
//   - **No cleanup attempted** afterward — same documented convention as
//     pkg/provision's account-registration check (LT-123): the risk is
//     bounded to inert junk data left on the tester's own resource, which
//     this package's design accepts rather than adds delete-after-probe
//     complexity for.
//
//   - **Gated behind its own flag, --allow-mutating-massassignment**,
//     never folded into --allow-writes (CLAUDE.md scopes that specifically
//     to pkg/detectors/businesslogic's coupon checks) or
//     --allow-mutating-bfla (scoped to mutatebfla's DELETE probe) — any new
//     mutating capability gets its own equally-scoped gate.
//
//   - **CLI-flag-driven only for now, like mutatebfla.** Body must be the
//     operator's own confirmed-working legitimate JSON body for the
//     endpoint. Recon's EndpointFact.BodyParamKeys only ever gives field
//     *names* ("names only — no values invented", its own doc comment) —
//     assembling a realistic body needs real values recon has no safe way
//     to invent, so there is no decisionengine/planexec auto-derivation
//     yet (logged as a follow-up, not guessed at).
package massassignment

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// DefaultAuthHeaderName/DefaultAuthHeaderFormat mirror every other
// parameter-based detector's convention (idor, ssrf, authbypass, sqli,
// mutatebfla) — kept as a package-level duplicate rather than a shared
// import, same reasoning each of those packages' own doc comments give.
const (
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderFormat = "Bearer {token}"
)

// canaryPrefix namespaces the probe field so it is never mistaken for a
// real application field, and so its presence in a read-back is
// unambiguous evidence of this detector's own probe having round-tripped.
const canaryPrefix = "hackerfive_probe_"

// Detector runs the mass-assignment check against a target.
type Detector struct {
	client     *httpclient.Client
	hostErrors *hosterrors.Cache

	authHeaderName   string
	authHeaderFormat string

	logFn func(level, msg string)
}

// Option configures a Detector at construction time. Same shape as
// mutatebfla.Option/idor.Option — not a new convention.
type Option func(*Detector)

// WithAuthHeader overrides the header name/value format used to carry an
// auth token on every probe request. "" for either argument preserves the
// package default.
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

// WithLogCallback registers fn to receive informational/warning log lines
// produced outside the normal Finding-returning path (e.g. a skipped-target
// safety check). Mirrors mutatebfla/idor/sqli.WithLogCallback exactly, so
// pkg/scanner/engine.go can route it through the same e.warnf seam.
func WithLogCallback(fn func(level, msg string)) Option {
	return func(d *Detector) {
		d.logFn = fn
	}
}

// New constructs a Detector.
func New(client *httpclient.Client, opts ...Option) *Detector {
	d := &Detector{
		client:           client,
		hostErrors:       hosterrors.New(hosterrors.DefaultThreshold),
		authHeaderName:   DefaultAuthHeaderName,
		authHeaderFormat: DefaultAuthHeaderFormat,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

func (d *Detector) log(level, msg string) {
	if d.logFn != nil {
		d.logFn(level, msg)
	}
}

// Target is one mass-assignment candidate: a self-service PUT/PATCH update
// endpoint the caller has a confirmed-legitimate body for.
type Target struct {
	// URL is the write endpoint under test.
	URL string

	// Method must be "PUT" or "PATCH" (case-insensitive); anything else is
	// skipped. POST-create endpoints are a deliberately deferred follow-up
	// — see the package doc comment.
	Method string

	// Body is the caller's own confirmed-working, legitimate JSON body for
	// URL — never recon-synthesized (see package doc comment). A nil/empty
	// Body is refused: there would be no legitimate request to attach the
	// probe field to.
	Body map[string]any

	// VerifyURL is the independent, read-only GET used to confirm whether
	// the probe field actually persisted. "" defaults to URL — the common
	// self-update case (PATCH /users/me, GET /users/me).
	VerifyURL string
}

// Run checks every target for mass assignment. allowMutating gates the
// whole detector: false means every target is skipped without a single
// request being sent (the caller — engine.go — already prints a stderr
// warning once per scan when --allow-mutating-massassignment is absent,
// mirroring mutatebfla/businesslogic's treatment, so this returns silently
// rather than warning a second time per target).
func (d *Detector) Run(ctx context.Context, targets []Target, authToken string, allowMutating bool) ([]detectors.Finding, error) {
	if !allowMutating {
		return nil, nil
	}
	if authToken == "" {
		d.log("warn", "massassignment: no auth token given — skipping (a self-update probe needs an authenticated account)")
		return nil, nil
	}

	var findings []detectors.Finding
	for _, t := range targets {
		if ctx.Err() != nil {
			return findings, ctx.Err()
		}
		f, err := d.runTarget(ctx, t, authToken)
		if err != nil {
			return findings, err
		}
		if f != nil {
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

func (d *Detector) runTarget(ctx context.Context, t Target, authToken string) (*detectors.Finding, error) {
	method := strings.ToUpper(t.Method)
	if method != http.MethodPut && method != http.MethodPatch {
		d.log("warn", fmt.Sprintf("massassignment: skipping %s — Method must be PUT or PATCH (got %q); POST-create endpoints are a deferred follow-up, see package doc comment", t.URL, t.Method))
		return nil, nil
	}
	if len(t.Body) == 0 {
		d.log("warn", fmt.Sprintf("massassignment: skipping %s — no Body given, refusing to guess a legitimate request body", t.URL))
		return nil, nil
	}

	verifyURL := t.VerifyURL
	if verifyURL == "" {
		verifyURL = t.URL
	}

	host, err := hostOf(t.URL)
	if err != nil {
		return nil, nil // an unparseable target URL isn't this detector's job to report
	}
	if d.hostErrors.ShouldSkip(host) {
		d.log("warn", fmt.Sprintf("massassignment: skipping remaining probes on %s — too many consecutive request errors", host))
		return nil, nil
	}

	canaryKey, canaryValue, err := newCanary()
	if err != nil {
		return nil, fmt.Errorf("massassignment: generating canary: %w", err)
	}

	mutatedBody := make(map[string]any, len(t.Body)+1)
	for k, v := range t.Body {
		mutatedBody[k] = v
	}
	mutatedBody[canaryKey] = canaryValue

	bodyJSON, err := json.Marshal(mutatedBody)
	if err != nil {
		return nil, fmt.Errorf("massassignment: encoding body: %w", err)
	}

	writeResp, ok := d.probe(ctx, method, t.URL, bodyJSON, authToken, host)
	if !ok {
		return nil, nil
	}

	// Independent read — never trust the write's own response (some
	// backends echo request input back without ever having stored it).
	verifyResp, ok := d.probe(ctx, http.MethodGet, verifyURL, nil, authToken, host)
	if !ok {
		return nil, nil
	}
	if verifyResp.status != http.StatusOK || !bytes.Contains(verifyResp.body, []byte(canaryValue)) {
		return nil, nil
	}

	return &detectors.Finding{
		ID:          fmt.Sprintf("massassignment-%s", sanitizeID(t.URL)),
		Type:        "massassignment",
		Severity:    "medium",
		Confidence:  "high",
		Target:      t.URL,
		Description: "an undeclared JSON field injected alongside this write request's legitimate body was accepted and persisted — confirmed by an independent follow-up read, not inferred from the write's own response — indicating this endpoint binds the request body directly onto its internal model with no field allow-list (mass assignment, OWASP API6:2023). The probe field itself is inert; an attacker who knows a real privileged field name (role, is_admin, balance, plan, ...) may be able to set it the same way — this finding does not itself confirm that.",
		Evidence: map[string]string{
			"method":          method,
			"canary_field":    canaryKey,
			"canary_value":    canaryValue,
			"write_status":    strconv.Itoa(writeResp.status),
			"verify_status":   strconv.Itoa(verifyResp.status),
			"write_request":   requestEvidenceFor(writeResp),
			"write_response":  evidenceFor(writeResp),
			"verify_request":  requestEvidenceFor(verifyResp),
			"verify_response": evidenceFor(verifyResp),
		},
	}, nil
}

// newCanary generates a fresh, HackerFive-namespaced field name and a
// random value — unique per probe, unguessable, and never a real
// sensitive-shaped field name (see package doc comment's safety note).
func newCanary() (key, value string, err error) {
	keyBytes := make([]byte, 4)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", err
	}
	valueBytes := make([]byte, 8)
	if _, err := rand.Read(valueBytes); err != nil {
		return "", "", err
	}
	return canaryPrefix + hex.EncodeToString(keyBytes), hex.EncodeToString(valueBytes), nil
}

// probeResult is one HTTP round-trip's shape.
type probeResult struct {
	req    *http.Request
	status int
	header http.Header
	body   []byte
}

// probe fires one request and records its shape. ok is false on a
// transport-level error (recorded against the host circuit breaker) or a
// request-build error — never on a non-2xx status, which runTarget's own
// comparisons treat as meaningful (a non-2xx write that still persisted the
// canary is exactly the positive signal, not a failure).
func (d *Detector) probe(ctx context.Context, method, rawURL string, body []byte, token, host string) (probeResult, bool) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bodyReader)
	if err != nil {
		return probeResult{}, false
	}
	if token != "" {
		req.Header.Set(d.authHeaderName, strings.Replace(d.authHeaderFormat, "{token}", token, 1))
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := d.client.Do(req)
	if err != nil {
		d.hostErrors.RecordError(host)
		return probeResult{}, false
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		d.hostErrors.RecordError(host)
		return probeResult{}, false
	}
	d.hostErrors.RecordSuccess(host)
	return probeResult{req: req, status: resp.StatusCode, header: resp.Header, body: respBody}, true
}

func hostOf(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parsing target URL: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("target URL has no host: %s", target)
	}
	return u.Host, nil
}

func evidenceFor(probe probeResult) string {
	return detectors.FormatResponse(probe.status, probe.header, probe.body)
}

func requestEvidenceFor(probe probeResult) string {
	if probe.req == nil {
		return ""
	}
	var body []byte
	if probe.req.Method == http.MethodPut || probe.req.Method == http.MethodPatch {
		// The request body reader was already consumed by client.Do; the
		// evidence text notes the method/URL/headers, same as every other
		// probe helper here — reconstructing the exact sent bytes isn't
		// worth buffering every request body just for evidence text.
		body = nil
	}
	return detectors.FormatRequest(probe.req.Method, probe.req.URL.String(), probe.req.Header, body)
}

// sanitizeID makes a URL safe to embed in a Finding.ID — same convention as
// mutatebfla.sanitizeID/ssrf.sanitizeID/sqli.sanitizeParam.
func sanitizeID(s string) string {
	r := strings.NewReplacer("/", "-", "?", "-", "&", "-", "=", "-", ":", "-")
	return strings.Trim(r.Replace(s), "-")
}
