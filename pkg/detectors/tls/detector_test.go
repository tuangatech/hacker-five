package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// generateCert builds a throwaway, self-signed, IsCA-true RSA certificate
// for 127.0.0.1 (or whatever ips/dnsNames the caller wants) valid over
// [notBefore, notAfter]. IsCA lets the exact same cert double as its own
// trust anchor via rootPoolFor, below — the only way a test can exercise a
// genuinely "clean, fully-verifying chain" case, since every cert this
// helper makes is otherwise untrusted by anything real.
func generateCert(t *testing.T, notBefore, notAfter time.Time, ips []net.IP, dnsNames []string) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "hackerfive-tls-test"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           ips,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func rootPoolFor(cert tls.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	return pool
}

// startTLSServer binds a real TLS listener on 127.0.0.1:0 presenting cert,
// MinVersion TLS 1.2 by default — configure can override any field (a
// version-only or weak-cipher-only test server). Every accepted connection
// completes exactly one server-side handshake then blocks on a Read so it
// stays open until the client (this package's Detector) closes it —
// otherwise a fast server-side close could race the client's own
// ConnectionState read on some platforms.
func startTLSServer(t *testing.T, cert tls.Certificate, configure func(*tls.Config)) string {
	t.Helper()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if configure != nil {
		configure(cfg)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				tc, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				if err := tc.Handshake(); err != nil {
					return
				}
				buf := make([]byte, 1)
				_, _ = tc.Read(buf)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func idsOf(findings []detectors.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	return ids
}

var localIP = []net.IP{net.ParseIP("127.0.0.1")}

func TestRun_CleanTrustedCert_NoFindings(t *testing.T) {
	cert := generateCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, nil)

	d := New(WithTimeout(3*time.Second), WithRootPool(rootPoolFor(cert)))
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	assert.Empty(t, findings, "a valid-date, correct-hostname, trusted-chain, TLS-1.2+-only server should produce zero findings")
}

func TestRun_ExpiredCert_ReportsExpiredOnly(t *testing.T) {
	cert := generateCert(t, time.Now().Add(-365*24*time.Hour), time.Now().Add(-24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, nil)

	d := New(WithTimeout(3 * time.Second)) // no root pool: dateValid is false, so the chain-trust check is skipped anyway
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "tls-cert-expired-127-0-0-1", findings[0].ID)
	assert.Equal(t, "medium", findings[0].Severity)
}

func TestRun_NotYetValidCert_ReportsNotYetValidOnly(t *testing.T) {
	cert := generateCert(t, time.Now().Add(24*time.Hour), time.Now().Add(365*24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, nil)

	d := New(WithTimeout(3 * time.Second))
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "tls-cert-not-yet-valid-127-0-0-1", findings[0].ID)
}

func TestRun_NearExpiryTrustedCert_ReportsNearExpiryOnly(t *testing.T) {
	cert := generateCert(t, time.Now().Add(-30*24*time.Hour), time.Now().Add(5*24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, nil)

	d := New(WithTimeout(3*time.Second), WithRootPool(rootPoolFor(cert)))
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "tls-cert-near-expiry-127-0-0-1", findings[0].ID)
	assert.Equal(t, "low", findings[0].Severity)
}

func TestRun_UntrustedChain_ReportsChainVerificationFailed(t *testing.T) {
	cert := generateCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, nil)

	d := New(WithTimeout(3 * time.Second)) // no WithRootPool: this cert is trusted by nobody
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "tls-chain-verification-failed-127-0-0-1", findings[0].ID)
}

func TestRun_HostnameMismatch_ReportsMismatch(t *testing.T) {
	// Valid dates, but the cert only names 10.0.0.9 — never the 127.0.0.1
	// this test actually connects to.
	cert := generateCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), []net.IP{net.ParseIP("10.0.0.9")}, nil)
	addr := startTLSServer(t, cert, nil)

	d := New(WithTimeout(3 * time.Second))
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	assert.Contains(t, idsOf(findings), "tls-hostname-mismatch-127-0-0-1")
}

func TestRun_TLS10OnlyServer_ReportsDeprecatedProtocolByDefault(t *testing.T) {
	cert := generateCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, func(cfg *tls.Config) {
		cfg.MinVersion = tls.VersionTLS10
		cfg.MaxVersion = tls.VersionTLS10
	})

	d := New(WithTimeout(3*time.Second), WithRootPool(rootPoolFor(cert)))
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	require.Len(t, findings, 1, "a trusted, correctly-named, TLS-1.0-only server should report exactly the deprecated-protocol finding")
	assert.Equal(t, "tls-deprecated-protocol-127-0-0-1", findings[0].ID)
	assert.Contains(t, findings[0].Description, "by default")
}

func TestRun_ModernServerThatStillAcceptsOldProtocol_ReportsDowngradeAccepted(t *testing.T) {
	cert := generateCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, func(cfg *tls.Config) {
		cfg.MinVersion = tls.VersionTLS10 // still accepts old protocols under duress
		cfg.MaxVersion = 0                // 0 = Go's own default ceiling (TLS 1.3), so the default handshake negotiates modern
	})

	d := New(WithTimeout(3*time.Second), WithRootPool(rootPoolFor(cert)))
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	require.Len(t, findings, 1, "a server that negotiates TLS 1.3 by default but still accepts TLS 1.1 when offered should report exactly the downgrade-accepted finding")
	assert.Equal(t, "tls-deprecated-protocol-127-0-0-1", findings[0].ID)
	assert.Contains(t, findings[0].Description, "even though")
}

func TestRun_ServerOnlyOffersWeakCiphers_ReportsWeakCipher(t *testing.T) {
	insecure := tls.InsecureCipherSuites()
	require.NotEmpty(t, insecure, "this test needs at least one stdlib-flagged-insecure suite to exist")
	ids := make([]uint16, len(insecure))
	for i, cs := range insecure {
		ids[i] = cs.ID
	}

	cert := generateCert(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour), localIP, nil)
	addr := startTLSServer(t, cert, func(cfg *tls.Config) {
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CipherSuites = ids
	})

	d := New(WithTimeout(3*time.Second), WithRootPool(rootPoolFor(cert)))
	findings, err := d.Run(context.Background(), addr)
	require.NoError(t, err)
	require.Len(t, findings, 1, "a server whose only offered suites are all stdlib-flagged-insecure should report exactly the weak-cipher finding")
	assert.Equal(t, "tls-weak-cipher-127-0-0-1", findings[0].ID)
	assert.Equal(t, "low", findings[0].Confidence)
}

func TestRun_NothingListening_NoFindingNoError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close()) // nothing listening now

	d := New(WithTimeout(500 * time.Millisecond))
	findings, err := d.Run(context.Background(), "https://"+addr)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestRun_PlainTCPListener_NoFindingNoError(t *testing.T) {
	// Something is listening, but it never speaks TLS at all — the
	// handshake itself fails, same "not this detector's finding" outcome
	// as nothing listening.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf) // drain the ClientHello bytes, never respond
	}()

	d := New(WithTimeout(500 * time.Millisecond))
	findings, err := d.Run(context.Background(), ln.Addr().String())
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestDialAddr_ExplicitPortHonored(t *testing.T) {
	addr, hostname, err := dialAddr("https://example.test:8443")
	require.NoError(t, err)
	assert.Equal(t, "example.test:8443", addr)
	assert.Equal(t, "example.test", hostname)
}

func TestDialAddr_HTTPSchemeStillDefaultsToPort443(t *testing.T) {
	// A "tls" leaf's whole point is checking the host's TLS story — an
	// http-scheme Target (a host recon only ever saw on port 80) must not
	// default to port 80.
	addr, hostname, err := dialAddr("http://example.test")
	require.NoError(t, err)
	assert.Equal(t, "example.test:443", addr)
	assert.Equal(t, "example.test", hostname)
}

func TestDialAddr_BareHostPort_NoScheme(t *testing.T) {
	addr, hostname, err := dialAddr("127.0.0.1:9443")
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:9443", addr)
	assert.Equal(t, "127.0.0.1", hostname)
}

func TestDialAddr_Empty_ReturnsError(t *testing.T) {
	_, _, err := dialAddr("")
	require.Error(t, err)
}
