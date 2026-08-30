package businesslogic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// raceRequestOptions describes the one HTTP request fireRace sends
// concurrently over n separate connections.
type raceRequestOptions struct {
	Method   string
	Headers  map[string]string
	Body     []byte
	Insecure bool // mirrors httpclient.Config.InsecureSkipVerify for the TLS handshake below
}

// raceResponse is one connection's outcome. Err is set (and StatusCode/
// Header/Body left zero) when that connection's write or response parse
// failed — a per-connection failure, not fatal to the overall race attempt.
type raceResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Err        error
}

// fireRace opens n separate connections to target+path, writes the full
// HTTP request on each connection except its final byte, then releases that
// final byte on every connection back-to-back — the "last-byte-sync"
// technique (docs/13-implementation-plan-ph4.md Step 3's Design) that lands
// concurrent requests inside a real check-then-act window far more reliably
// than N independent net/http calls fired via goroutines, whose TCP
// handshake timing and Go scheduler jitter tend to spread requests out wide
// enough that a naive concurrent-fire check under-reports real races (a
// well-documented false-negative mode — the same reason tools like Burp's
// Turbo Intruder exist).
//
// Bypasses pkg/scanner/httpclient entirely (dials target directly) — no
// rate-limit/retry middleware applies to this one technique, and no proxy
// support: CONNECT-tunneling a last-byte-sync write through an HTTP proxy is
// real added complexity with no requirement driving it yet, a stated
// limitation rather than a silent gap.
func fireRace(ctx context.Context, target, path string, opts raceRequestOptions, n int) ([]raceResponse, error) {
	if n <= 0 {
		return nil, fmt.Errorf("businesslogic: race concurrency must be > 0, got %d", n)
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("businesslogic: parsing target for race client: %w", err)
	}
	addr, useTLS := dialAddr(u)
	full := buildRawRequest(opts.Method, u.Host, path, opts.Headers, opts.Body)
	if len(full) == 0 {
		return nil, fmt.Errorf("businesslogic: race request is empty")
	}
	prefix, lastByte := full[:len(full)-1], full[len(full)-1:]

	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		conn, err := dialRace(ctx, addr, useTLS, opts.Insecure)
		if err != nil {
			closeAll(conns)
			return nil, fmt.Errorf("businesslogic: dialing race connection %d: %w", i, err)
		}
		if _, err := conn.Write(prefix); err != nil {
			closeAll(conns)
			_ = conn.Close()
			return nil, fmt.Errorf("businesslogic: writing race prefix on connection %d: %w", i, err)
		}
		conns = append(conns, conn)
	}

	// Two-phase barrier: every goroutine signals arrival via ready.Done()
	// before blocking on release.Wait(); the caller only calls
	// release.Done() (unblocking every goroutine's Write(lastByte) at once)
	// after ready.Wait() confirms all n have actually arrived — tighter than
	// a single WaitGroup, which can't guarantee every goroutine reached its
	// wait point before being released.
	var ready sync.WaitGroup
	ready.Add(len(conns))
	var release sync.WaitGroup
	release.Add(1)

	var wg sync.WaitGroup
	results := make([]raceResponse, len(conns))
	for i, conn := range conns {
		wg.Add(1)
		go func(i int, conn net.Conn) {
			defer wg.Done()
			defer func() { _ = conn.Close() }()
			ready.Done()
			release.Wait()
			if _, err := conn.Write(lastByte); err != nil {
				results[i] = raceResponse{Err: err}
				return
			}
			results[i] = readRaceResponse(conn)
		}(i, conn)
	}
	ready.Wait()
	release.Done()
	wg.Wait()

	return results, nil
}

func closeAll(conns []net.Conn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

// readRaceResponse parses one raw HTTP/1.1 response off conn.
func readRaceResponse(conn net.Conn) raceResponse {
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return raceResponse{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return raceResponse{Err: err}
	}
	return raceResponse{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}
}

// buildRawRequest renders one complete HTTP/1.1 request (request line,
// headers, body) as raw bytes — headers are written in sorted order for
// determinism, same convention as pkg/detectors/evidence.go's writeHeaders.
func buildRawRequest(method, hostHeader, path string, headers map[string]string, body []byte) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&buf, "Host: %s\r\n", hostHeader)
	buf.WriteString("Connection: close\r\n")
	if len(body) > 0 {
		fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, headers[k])
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

// dialAddr returns the host:port to dial and whether TLS applies, defaulting
// the port from the URL scheme when u.Host doesn't already specify one.
func dialAddr(u *url.URL) (addr string, useTLS bool) {
	useTLS = u.Scheme == "https"
	host := u.Host
	if !strings.Contains(host, ":") {
		if useTLS {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	return host, useTLS
}

func dialRace(ctx context.Context, addr string, useTLS, insecure bool) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if !useTLS {
		return conn, nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: insecure}) //nolint:gosec // opt-in via --insecure, for lab targets only
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}
