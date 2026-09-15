package egressproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

func newTestProxy(t *testing.T, sc *scope.Scope) *Proxy {
	t.Helper()
	hc := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, MaxRedirects: 5})
	p := New(sc, hc)
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// clientThroughProxy returns an http.Client configured to route every
// request through p — the standard net/http way to exercise a forward
// proxy's CONNECT (for https) and absolute-form (for http) paths alike.
func clientThroughProxy(p *Proxy) *http.Client {
	proxyURL := &url.URL{Scheme: "http", Host: p.Addr()}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
}

func TestForward_AllowedHTTPTarget_Succeeds(t *testing.T) {
	target := newUpstreamServer(t, "hello")
	targetHost := mustHost(t, target)

	sc, err := scope.New([]string{targetHost})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	p := newTestProxy(t, sc)
	client := clientThroughProxy(p)

	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello" {
		t.Fatalf("got status=%d body=%q", resp.StatusCode, body)
	}
}

func TestForward_OutOfScopeHTTPTarget_Denied(t *testing.T) {
	target := newUpstreamServer(t, "hello")

	sc, err := scope.New([]string{"only-this-host-is-allowed.test"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	p := newTestProxy(t, sc)
	client := clientThroughProxy(p)

	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got status=%d, want 403", resp.StatusCode)
	}
}

func TestConnect_AllowedTarget_TunnelsSuccessfully(t *testing.T) {
	// A plain TCP echo-ish listener stands in for a TLS target — CONNECT
	// only opens a byte-level tunnel, it never inspects what flows through
	// it, so a raw TCP listener is enough to prove the tunnel itself works.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 5)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write(buf)
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	sc, err := scope.New([]string{host})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	p := newTestProxy(t, sc)

	proxyConn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = proxyConn.Close() }()

	target := net.JoinHostPort(host, port)
	req, _ := http.NewRequest(http.MethodConnect, "http://"+target, nil)
	if err := req.Write(proxyConn); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := proxyConn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); got[:12] != "HTTP/1.1 200" {
		t.Fatalf("got CONNECT response %q, want 200", got)
	}

	if _, err := proxyConn.Write([]byte("ping!")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	echoBuf := make([]byte, 5)
	if _, err := io.ReadFull(proxyConn, echoBuf); err != nil {
		t.Fatalf("read tunnel echo: %v", err)
	}
	if string(echoBuf) != "ping!" {
		t.Fatalf("got echo %q, want %q", echoBuf, "ping!")
	}
}

func TestConnect_OutOfScopeTarget_Denied(t *testing.T) {
	sc, err := scope.New([]string{"only-this-host-is-allowed.test"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	p := newTestProxy(t, sc)

	proxyConn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = proxyConn.Close() }()

	req, _ := http.NewRequest(http.MethodConnect, "http://evil.example.com:443", nil)
	if err := req.Write(proxyConn); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := proxyConn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	got := string(buf[:n])
	if got[:12] != "HTTP/1.1 403" {
		t.Fatalf("got CONNECT response %q, want 403", got)
	}
}

func TestCheckAllowed_DNSRebinding_ResolvedPrivateIPDenied(t *testing.T) {
	// example.test passes the plain scope.Allowed(hostname) check, but its
	// resolved address is a private one no scope entry explicitly covers —
	// the rebinding case Allowed's hostname-string match alone can't catch.
	sc, err := scope.New([]string{"example.test"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	hc := httpclient.New(httpclient.Config{Timeout: time.Second})
	p := New(sc, hc)
	p.lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		if host == "example.test" {
			return []net.IP{net.ParseIP("10.0.0.5")}, nil
		}
		return nil, nil
	}

	allowed, reason := p.checkAllowed(context.Background(), "example.test:443")
	if allowed {
		t.Fatalf("got allowed=true, want denied (reason empty); reason=%q", reason)
	}
}

func TestCheckAllowed_ExplicitCIDRCoversPrivateIP(t *testing.T) {
	// A lab target explicitly scoped by CIDR (docs/20-setup-testing-
	// targets.md's normal workflow) must still work even though its address
	// is private — the rebinding defense only rejects a private address
	// scope doesn't already cover.
	sc, err := scope.New([]string{"lab.test", "10.0.0.0/24"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	hc := httpclient.New(httpclient.Config{Timeout: time.Second})
	p := New(sc, hc)
	p.lookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.5")}, nil
	}

	allowed, reason := p.checkAllowed(context.Background(), "lab.test:443")
	if !allowed {
		t.Fatalf("got denied (reason=%q), want allowed — CIDR explicitly covers this address", reason)
	}
}

func newUpstreamServer(t *testing.T, body string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String() + "/"
}

func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		return u.Host
	}
	return host
}
