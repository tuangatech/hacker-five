// Package tls implements Phase 8 Step 2's passive TLS/SSL checks
// (docs/17-implementation-plan-ph8.md's Design section, docs/follow-up.md
// Detection Coverage's "Add — passive checks (expired/weak certs,
// deprecated protocols, weak ciphers) via stdlib crypto/tls, no new
// dependency"). Every check here is a bounded TLS handshake — never an
// HTTP request, never data sent beyond the handshake itself — so it works
// against any in-scope host:port that speaks TLS at all, independent of
// what (if anything) is listening at the HTTP layer above it. Read-only
// throughout, matching every other detector's boundary
// (docs/05-hackerone-and-legal.md).
//
// Dispatched by registry.resolveTLSFact promoting a host with a live
// https:// endpoint or an open 443/8443 port to a real dispatchable "tls"
// leaf — see pkg/scanner.Engine's "tls" runDetector case. Target arrives in
// the same "scheme://host[:port]" shape every other HTTP-ish detector gets
// (registry.reconHostBaseURL); the scheme itself is ignored — this package
// always dials the TLS port (the target's own port when the URL carries
// one, else 443, since a bare "http://host" target with no port still
// means "check this host's TLS story," not "check port 80").
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// DefaultTimeout bounds each individual handshake attempt (Run makes up to
// three — see downgradeProbe/weakCipherProbe). Longer than
// tcpproto.DefaultTimeout's 5s: a TLS handshake is a full round-trip plus
// certificate-chain exchange, not tcpproto's bare connect-and-read-banner.
const DefaultTimeout = 10 * time.Second

// nearExpiryWindow is how far out a still-valid certificate's NotAfter can
// be and still earn its own low-severity heads-up finding — 14 days is
// long enough to be actionable (time to renew before an outage) without
// firing on every cert an operator's ACME auto-renewal will quietly
// replace days before it would ever matter.
const nearExpiryWindow = 14 * 24 * time.Hour

// Detector runs the built-in passive TLS/SSL checks.
type Detector struct {
	timeout time.Duration
	// roots is the pool certFindings' chain-trust check verifies against.
	// nil (the production default, set by every real caller) means "use
	// the platform's own system root pool," x509.Verify's normal behavior
	// when Roots is nil. Only ever overridden by WithRootPool, so a test
	// can register its own throwaway CA as trusted and exercise a genuine
	// "clean, fully-verifying chain" case — every real handshake in this
	// package would otherwise always fail chain trust against whatever
	// self-signed cert a test spins up.
	roots *x509.CertPool
}

// Option configures a Detector at construction time — same functional-
// options shape netservice.Detector/ssrf.Detector already use.
type Option func(*Detector)

// WithTimeout overrides the per-handshake deadline. A zero/negative d is a
// no-op, leaving DefaultTimeout as the effective value.
func WithTimeout(d time.Duration) Option {
	return func(det *Detector) {
		if d > 0 {
			det.timeout = d
		}
	}
}

// WithRootPool overrides the root CA pool certFindings' chain-trust check
// verifies against — test-only seam (see Detector.roots); no production
// caller sets this, so every real scan still verifies against the
// platform's own system root pool.
func WithRootPool(pool *x509.CertPool) Option {
	return func(det *Detector) {
		det.roots = pool
	}
}

// New constructs a Detector.
func New(opts ...Option) *Detector {
	d := &Detector{}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Run performs a default TLS handshake against target for the cert/
// protocol checks, plus an always-attempted, independent weak-cipher probe
// — deliberately not gated on the default handshake's own success. A
// server that enables *only* suites Go's own client refuses to offer in a
// normal ClientHello (every real insecure suite: Go's default enabled set
// for TLS ≤1.2 already excludes them) would otherwise never be reachable
// by the default handshake at all, hiding the exact "will still speak a
// weak suite" finding this probe exists to catch — a worse server
// deserves a *more* complete report, not a silently empty one. A target
// that fails every handshake this package attempts (nothing listening,
// nothing TLS-speaking at all, a firewalled port) returns (nil, nil):
// that is not this detector's finding to make, and not a scan error, the
// same convention netservice.Detector.Run's port-dispatch miss and
// dial-failure paths use.
func (d *Detector) Run(ctx context.Context, target string) ([]detectors.Finding, error) {
	addr, hostname, err := dialAddr(target)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}

	var findings []detectors.Finding

	// MinVersion is deliberately permissive (TLS 1.0, the oldest version
	// crypto/tls's client still speaks at all) rather than left at Go's own
	// modern default floor — the whole point of this handshake is to learn
	// what the *server* actually negotiates when given the choice, not what
	// a strict client would have accepted anyway. InsecureSkipVerify defers
	// certificate trust/date/hostname judgment to this package's own checks
	// below (which can then report a *specific* reason), rather than
	// aborting the handshake before any of that evidence is even collected.
	state, baseErr := d.handshake(ctx, addr, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if baseErr == nil {
		findings = append(findings, d.certFindings(hostname, target, state)...)
		if pf := protocolFinding(hostname, target, state); pf != nil {
			findings = append(findings, *pf)
		} else {
			// The default handshake already negotiated TLS 1.2+ — still worth
			// checking whether the server would *also* accept something older
			// when that's all a client offers (a real downgrade-attack surface
			// a "what did it negotiate by default" check alone would miss).
			findings = append(findings, d.downgradeProbe(ctx, addr, hostname, target)...)
		}
	}

	weak := d.weakCipherProbe(ctx, addr, hostname, target)
	findings = append(findings, weak...)

	if baseErr != nil && len(weak) == 0 {
		return nil, nil
	}
	return findings, nil
}

// handshake dials addr fresh and completes one TLS handshake under cfg,
// bounded by both ctx and this Detector's timeout. Returns the resulting
// ConnectionState, or the handshake/dial error unchanged — every caller in
// this package treats that error as "this specific protocol/cipher variant
// isn't accepted here," not a scan failure, so none of it is wrapped.
func (d *Detector) handshake(ctx context.Context, addr string, cfg *tls.Config) (*tls.ConnectionState, error) {
	hctx, cancel := context.WithTimeout(ctx, timeoutOrDefault(d.timeout))
	defer cancel()
	rawConn, err := tcpproto.Dial(hctx, addr, d.timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rawConn.Close() }()

	tlsConn := tls.Client(rawConn, cfg)
	defer func() { _ = tlsConn.Close() }()
	if err := tlsConn.HandshakeContext(hctx); err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	return &state, nil
}

// downgradeProbe re-dials with MaxVersion capped below TLS 1.2 — if the
// handshake still succeeds, the server accepts a deprecated protocol under
// duress even though it prefers something newer by default. A failed probe
// here (the common, healthy case) is silently clean: it means the server
// correctly refuses every protocol this offers.
func (d *Detector) downgradeProbe(ctx context.Context, addr, hostname, target string) []detectors.Finding {
	state, err := d.handshake(ctx, addr, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
	})
	if err != nil {
		return nil
	}
	return []detectors.Finding{{
		ID:          fmt.Sprintf("tls-deprecated-protocol-%s", sanitizeID(hostname)),
		Type:        "misconfig",
		Severity:    "medium",
		Confidence:  "high",
		Target:      target,
		Description: fmt.Sprintf("%s still accepts %s when a client offers nothing newer, even though it negotiates a modern protocol by default", hostname, tlsVersionName(state.Version)),
		Evidence:    map[string]string{"negotiated_version": tlsVersionName(state.Version)},
	}}
}

// weakCipherProbe re-dials offering only the cipher suites Go's own
// standard library flags as insecure (tls.InsecureCipherSuites() — RC4,
// 3DES, and the other suites the stdlib itself refuses to select by
// default). A successful handshake here means the server will use one of
// them when nothing better is offered — Confidence stays "low" (this is a
// worst-case-offer heuristic, not evidence the server prefers or is
// reachable via a weak suite under normal negotiation), per doc17 Step 2's
// design. TLS 1.3's own cipher suites aren't user-configurable and contain
// none of InsecureCipherSuites' entries, so MaxVersion caps at 1.2 — a
// TLS-1.3-only server simply, correctly, fails this probe.
func (d *Detector) weakCipherProbe(ctx context.Context, addr, hostname, target string) []detectors.Finding {
	insecure := tls.InsecureCipherSuites()
	if len(insecure) == 0 {
		return nil
	}
	ids := make([]uint16, len(insecure))
	for i, cs := range insecure {
		ids[i] = cs.ID
	}
	state, err := d.handshake(ctx, addr, &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       ids,
	})
	if err != nil {
		return nil
	}
	return []detectors.Finding{{
		ID:          fmt.Sprintf("tls-weak-cipher-%s", sanitizeID(hostname)),
		Type:        "misconfig",
		Severity:    "low",
		Confidence:  "low",
		Target:      target,
		Description: fmt.Sprintf("%s accepted the stdlib-flagged-insecure cipher suite %s when it was the only kind offered", hostname, tls.CipherSuiteName(state.CipherSuite)),
		Evidence:    map[string]string{"cipher_suite": tls.CipherSuiteName(state.CipherSuite), "negotiated_version": tlsVersionName(state.Version)},
	}}
}

// certFindings inspects the leaf certificate the default handshake
// presented for date validity, hostname match, and chain trust — three
// independent checks, each producing its own finding so a report reader
// sees exactly which is wrong rather than one vague "bad cert" line.
// Hostname match and chain trust are skipped from re-deriving an
// already-reported expired/not-yet-valid verdict a second time: an expired
// cert will also, trivially, fail chain verification, and that second
// finding would tell a reader nothing certFindings' date check hasn't
// already said more specifically.
func (d *Detector) certFindings(hostname, target string, state *tls.ConnectionState) []detectors.Finding {
	if len(state.PeerCertificates) == 0 {
		return nil
	}
	cert := state.PeerCertificates[0]
	now := time.Now()
	var findings []detectors.Finding

	dateValid := true
	switch {
	case now.After(cert.NotAfter):
		dateValid = false
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("tls-cert-expired-%s", sanitizeID(hostname)),
			Type:        "misconfig",
			Severity:    "medium",
			Confidence:  "high",
			Target:      target,
			Description: fmt.Sprintf("TLS certificate for %s expired %s", hostname, cert.NotAfter.Format(time.RFC3339)),
			Evidence:    map[string]string{"subject": cert.Subject.String(), "not_after": cert.NotAfter.Format(time.RFC3339)},
		})
	case now.Before(cert.NotBefore):
		dateValid = false
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("tls-cert-not-yet-valid-%s", sanitizeID(hostname)),
			Type:        "misconfig",
			Severity:    "low",
			Confidence:  "high",
			Target:      target,
			Description: fmt.Sprintf("TLS certificate for %s is not valid until %s", hostname, cert.NotBefore.Format(time.RFC3339)),
			Evidence:    map[string]string{"subject": cert.Subject.String(), "not_before": cert.NotBefore.Format(time.RFC3339)},
		})
	case cert.NotAfter.Sub(now) <= nearExpiryWindow:
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("tls-cert-near-expiry-%s", sanitizeID(hostname)),
			Type:        "misconfig",
			Severity:    "low",
			Confidence:  "high",
			Target:      target,
			Description: fmt.Sprintf("TLS certificate for %s expires %s (within %s)", hostname, cert.NotAfter.Format(time.RFC3339), nearExpiryWindow),
			Evidence:    map[string]string{"subject": cert.Subject.String(), "not_after": cert.NotAfter.Format(time.RFC3339)},
		})
	}

	if err := cert.VerifyHostname(hostname); err != nil {
		findings = append(findings, detectors.Finding{
			ID:          fmt.Sprintf("tls-hostname-mismatch-%s", sanitizeID(hostname)),
			Type:        "misconfig",
			Severity:    "medium",
			Confidence:  "high",
			Target:      target,
			Description: fmt.Sprintf("TLS certificate for %s does not cover the connected hostname: %v", hostname, err),
			Evidence:    map[string]string{"subject": cert.Subject.String(), "dns_names": strings.Join(cert.DNSNames, ", ")},
		})
	}

	if dateValid {
		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		// DNSName deliberately left empty: hostname match is VerifyHostname's
		// job above, so a mismatch alone (chain otherwise trusted) doesn't
		// also trip this as a second, redundant chain-trust finding.
		if _, verifyErr := cert.Verify(x509.VerifyOptions{
			Roots:         d.roots,
			Intermediates: intermediates,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); verifyErr != nil {
			findings = append(findings, detectors.Finding{
				ID:          fmt.Sprintf("tls-chain-verification-failed-%s", sanitizeID(hostname)),
				Type:        "misconfig",
				Severity:    "medium",
				Confidence:  "high",
				Target:      target,
				Description: fmt.Sprintf("TLS certificate chain for %s does not verify against a trusted root: %v", hostname, verifyErr),
				Evidence:    map[string]string{"subject": cert.Subject.String(), "issuer": cert.Issuer.String()},
			})
		}
	}

	return findings
}

// protocolFinding reports the default handshake's own negotiated version
// when it's already below TLS 1.2 — the unambiguous case: the server's
// *preferred* protocol, not just one it grudgingly still accepts, is
// deprecated. Returns nil (not an empty slice) so Run's else-branch can
// treat "did the default handshake already prove this" as a plain nil
// check.
func protocolFinding(hostname, target string, state *tls.ConnectionState) *detectors.Finding {
	if state.Version >= tls.VersionTLS12 {
		return nil
	}
	return &detectors.Finding{
		ID:          fmt.Sprintf("tls-deprecated-protocol-%s", sanitizeID(hostname)),
		Type:        "misconfig",
		Severity:    "medium",
		Confidence:  "high",
		Target:      target,
		Description: fmt.Sprintf("%s negotiates %s by default — below the TLS 1.2 floor modern browsers and PCI-DSS both require", hostname, tlsVersionName(state.Version)),
		Evidence:    map[string]string{"negotiated_version": tlsVersionName(state.Version), "cipher_suite": tls.CipherSuiteName(state.CipherSuite)},
	}
}

// tlsVersionName names a crypto/tls version constant — the stdlib exports
// tls.CipherSuiteName for cipher suites but no equivalent for the version
// constants, so this is a small first-party lookup rather than a new
// dependency for four fixed strings.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown TLS version 0x%04x", v)
	}
}

// dialAddr turns a leaf's Target — normally "scheme://host[:port]"
// (registry.reconHostBaseURL's shape) — into the "host:port" dial address
// this package always TLS-handshakes against, plus the bare hostname for
// SNI/hostname-verification. An explicit port in Target is honored as-is;
// otherwise this always defaults to 443, deliberately ignoring an
// http-scheme Target's own default port 80 — a "tls" leaf's whole purpose
// is checking the host's TLS story, not whatever scheme happened to label
// the URL recon built. Also tolerates a bare "host" or "host:port" with no
// scheme at all, for a hand-typed `--detector tls -t example.com` run.
func dialAddr(target string) (addr, hostname string, err error) {
	if u, uerr := url.Parse(target); uerr == nil && u.Hostname() != "" {
		hostname = u.Hostname()
		port := u.Port()
		if port == "" {
			port = "443"
		}
		return net.JoinHostPort(hostname, port), hostname, nil
	}
	if h, p, serr := net.SplitHostPort(target); serr == nil && h != "" {
		return net.JoinHostPort(h, p), h, nil
	}
	if target == "" {
		return "", "", fmt.Errorf("empty target")
	}
	return net.JoinHostPort(target, "443"), target, nil
}

// sanitizeID mirrors netservice.sanitizeID's convention for turning a
// hostname into a safe Finding.ID suffix.
func sanitizeID(s string) string {
	return strings.NewReplacer(":", "-", ".", "-").Replace(s)
}

func timeoutOrDefault(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return DefaultTimeout
}
