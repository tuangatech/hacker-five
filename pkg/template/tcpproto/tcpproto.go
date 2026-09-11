// Package tcpproto implements the small, read-only connect/send/read-banner
// primitive that backs both the nuclei.Executor's tcp: protocol path and
// pkg/detectors/netservice's first-party checks (Phase 8 Step 1,
// docs/17-implementation-plan-ph8.md). Deliberately minimal: this project's
// TCP support is bounded to "connect, optionally send a fixed byte string,
// read whatever comes back within a deadline" — never a raw socket left
// open for a caller to drive an arbitrary multi-step protocol beyond that
// (each netservice check that needs more than one round-trip, e.g. FTP's
// USER/PASS exchange, does so by calling Probe/Write/Read directly against
// its own net.Conn — see netservice.checkFTPAnonymous). No script/code
// execution of any kind touches this package, matching the same
// read/enumerate-only boundary every other detector holds
// (docs/05-hackerone-and-legal.md).
package tcpproto

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DefaultTimeout is used for both the dial and each individual read when a
// caller passes a zero timeout — mirrors the CLI's own --timeout default
// order of magnitude (cmd/hackerfive/root.go's 30s --timeout is an HTTP
// per-request budget; TCP banner grabs settle far faster in practice, so
// this package's own default is deliberately shorter) while still letting
// pkg/scanner.Engine thread its configured --timeout through explicitly.
const DefaultTimeout = 5 * time.Second

// MaxReadBytes caps how much of a service's response this package will ever
// buffer for one Read call, regardless of what the caller asks for — a
// banner-grab primitive has no legitimate reason to hold more than a few KB
// in memory, and an unbounded read against a malicious or misbehaving
// listener would otherwise be an easy memory-exhaustion foot-gun.
const MaxReadBytes = 8192

func effectiveTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return DefaultTimeout
	}
	return d
}

// Dial opens a TCP connection to addr ("host:port"), honoring both ctx and
// timeout (effectiveTimeout's zero-fallback applies) — whichever fires
// first aborts the dial. Never sends or reads anything; callers that just
// need a banner without writing first can go straight to Read.
func Dial(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: effectiveTimeout(timeout)}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcpproto: dialing %s: %w", addr, err)
	}
	return conn, nil
}

// Write sends data on conn under a write deadline (effectiveTimeout's
// zero-fallback applies). A no-op, returning (0, nil), when data is empty —
// plenty of real checks (e.g. reading a service's unsolicited greeting
// banner) never send anything at all.
func Write(conn net.Conn, data []byte, timeout time.Duration) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if err := conn.SetWriteDeadline(time.Now().Add(effectiveTimeout(timeout))); err != nil {
		return 0, fmt.Errorf("tcpproto: setting write deadline: %w", err)
	}
	n, err := conn.Write(data)
	if err != nil {
		return n, fmt.Errorf("tcpproto: writing: %w", err)
	}
	return n, nil
}

// Read reads up to maxBytes (capped at MaxReadBytes; <=0 means "use the
// cap") from conn under a read deadline (effectiveTimeout's zero-fallback
// applies), returning whatever arrived. A read deadline expiring with zero
// or partial bytes already read is NOT an error here — many services (a
// port-scanning-resistant listener, or one whose banner trails a short
// pause) never send anything unsolicited, and "nothing came back within the
// deadline" is itself a legitimate, honestly-reportable outcome for a
// banner-grab primitive, not a failure worth propagating as one. A genuine
// connection-level error (reset, closed) still returns as an error.
func Read(conn net.Conn, maxBytes int, timeout time.Duration) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > MaxReadBytes {
		maxBytes = MaxReadBytes
	}
	if err := conn.SetReadDeadline(time.Now().Add(effectiveTimeout(timeout))); err != nil {
		return nil, fmt.Errorf("tcpproto: setting read deadline: %w", err)
	}
	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return buf[:n], nil // partial (possibly zero) read on deadline — not an error, see doc comment
		}
		if err.Error() == "EOF" {
			return buf[:n], nil // service closed the connection right after its banner — same non-error treatment
		}
		return buf[:n], fmt.Errorf("tcpproto: reading: %w", err)
	}
	return buf[:n], nil
}

// Probe is the one-shot convenience path nuclei.Executor's tcp: requests
// use: dial addr, optionally write send, then read up to maxRead bytes —
// one connection, one exchange, always closed before returning. netservice's
// multi-step checks (FTP's USER/PASS exchange) instead call Dial/Write/Read
// directly so they can hold the connection open across several exchanges.
func Probe(ctx context.Context, addr string, timeout time.Duration, send []byte, maxRead int) ([]byte, error) {
	conn, err := Dial(ctx, addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()

	if len(send) > 0 {
		if _, err := Write(conn, send, timeout); err != nil {
			return nil, err
		}
	}
	return Read(conn, maxRead, timeout)
}
