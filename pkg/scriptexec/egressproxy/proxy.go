// Package egressproxy is scriptexec's network chokepoint (docs/93-
// implementation-plan-agent-orchestrator.md M1): the sandbox container
// (pkg/scriptexec's sandbox.go) is given no network route except to this
// proxy, so every outbound connection a script makes — a plain HTTP
// request, or a CONNECT tunnel for HTTPS — passes through the same
// pkg/scanner/scope.Scope a scan itself is authorized under before it's
// forwarded anywhere.
//
// Scope.Allowed alone checks a hostname string, which is not enough on its
// own: an in-scope hostname could resolve to a loopback/link-local/private
// address (DNS rebinding), reaching something never intended to be
// reachable at all. This proxy additionally resolves the hostname and
// rejects any resolved address that looks like a non-routable/private
// address unless that literal address is itself covered by an explicit
// scope entry (e.g. a CIDR block for an on-prem lab target).
package egressproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// hopByHopHeaders are stripped from both the forwarded request and the
// returned response — RFC 7230 §6.1's per-connection headers, meaningless
// (and occasionally harmful, e.g. a stray Connection: close) once relayed
// through a second hop.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade",
}

// defaultDialTimeout bounds a CONNECT tunnel's initial dial to the real
// target — independent of the sandbox's own overall script timeout, so a
// single unreachable host can't stall the proxy indefinitely.
const defaultDialTimeout = 10 * time.Second

// Proxy is an allowlisting HTTP(S) forward proxy. Zero value is not usable;
// construct with New.
type Proxy struct {
	scope  *scope.Scope
	client *httpclient.Client

	// lookupIP resolves host to its IPs for the DNS-rebinding check.
	// Defaults to resolveIP; overridable in tests to simulate a hostname
	// resolving to an address it shouldn't.
	lookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// dial opens the real TCP connection for a CONNECT tunnel. Defaults to
	// net.Dialer.DialContext; overridable in tests.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	listener net.Listener
	server   *http.Server
}

// New builds a Proxy that allows only targets sc.Allowed accepts, forwarding
// plain-HTTP traffic through client (so it inherits the scan's own
// rate-limit/retry middleware rather than an unbounded side channel) and
// tunneling HTTPS traffic via a direct dial after the same scope check.
// Neither argument may be nil.
func New(sc *scope.Scope, client *httpclient.Client) *Proxy {
	return &Proxy{
		scope:    sc,
		client:   client,
		lookupIP: resolveIP,
		dial:     (&net.Dialer{Timeout: defaultDialTimeout}).DialContext,
	}
}

// Start listens on addr (e.g. "0.0.0.0:0" to let the OS pick a free port —
// the normal case when this runs inside its own sandbox-network container)
// and begins serving in a background goroutine. Call Addr after Start to
// learn the actual bound address.
func (p *Proxy) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("egressproxy: listen on %s: %w", addr, err)
	}
	p.listener = ln
	p.server = &http.Server{Handler: p}
	go func() { _ = p.server.Serve(ln) }()
	return nil
}

// Addr returns the actual bound address ("host:port") after a successful Start.
func (p *Proxy) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// Close shuts the proxy down, closing its listener and any in-flight connections.
func (p *Proxy) Close() error {
	if p.server == nil {
		return nil
	}
	return p.server.Close()
}

// ServeHTTP dispatches a CONNECT (HTTPS tunnel) request to handleConnect and
// every other method (a plain, absolute-form HTTP proxy request) to
// handleForward.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleForward(w, r)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	allowed, reason := p.checkAllowed(r.Context(), r.Host)
	if !allowed {
		http.Error(w, "egress denied: "+reason, http.StatusForbidden)
		return
	}

	destConn, err := p.dial(r.Context(), "tcp", r.Host)
	if err != nil {
		http.Error(w, "egress proxy: dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = destConn.Close() }()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "egress proxy: hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(destConn, clientConn)
		close(done)
	}()
	_, _ = io.Copy(clientConn, destConn)
	<-done
}

func (p *Proxy) handleForward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() {
		http.Error(w, "egress proxy: requires an absolute-form request URI", http.StatusBadRequest)
		return
	}
	allowed, reason := p.checkAllowed(r.Context(), r.URL.Host)
	if !allowed {
		http.Error(w, "egress denied: "+reason, http.StatusForbidden)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}

	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, "egress proxy: forwarding failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// checkAllowed is the proxy's one policy decision, shared by both the
// CONNECT and plain-forward paths: hostport's host must both name an
// in-scope target (scope.Scope.Allowed) and resolve to no address that
// looks non-routable/private unless that literal address is itself
// explicitly in scope — closing the DNS-rebinding gap Allowed's
// hostname-string match alone doesn't cover.
func (p *Proxy) checkAllowed(ctx context.Context, hostport string) (bool, string) {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if host == "" {
		return false, "empty host"
	}
	if !p.scope.Allowed(asScopeTarget(host)) {
		return false, fmt.Sprintf("host %q is not in the authorized scope", host)
	}

	ips, err := p.lookupIP(ctx, host)
	if err != nil || len(ips) == 0 {
		return false, fmt.Sprintf("could not resolve %q: %v", host, err)
	}
	for _, ip := range ips {
		if isSpecialUseIP(ip) && !p.scope.Allowed(asScopeTarget(ip.String())) {
			return false, fmt.Sprintf("host %q resolves to %s, a non-routable/private address not explicitly covered by scope (possible DNS rebinding)", host, ip)
		}
	}
	return true, ""
}

// asScopeTarget turns a bare host or IP into the URL-shaped string
// scope.Scope.Allowed expects (it parses via url.Parse and reads Hostname())
// — bracketing an IPv6 literal so url.Parse doesn't mistake its colons for a
// port separator.
func asScopeTarget(host string) string {
	if strings.Contains(host, ":") {
		return "https://[" + host + "]"
	}
	return "https://" + host
}

// isSpecialUseIP reports whether ip is loopback, link-local, private
// (RFC1918/RFC4193), or unspecified — the address classes a DNS response
// for an otherwise-in-scope hostname should never legitimately resolve to.
func isSpecialUseIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified()
}

// resolveIP is lookupIP's real implementation: a literal IP address parses
// directly (net.LookupIP would also handle this, but parsing first avoids an
// unnecessary resolver round trip and — more importantly — makes a literal
// IP target's own class checked the same way a resolved hostname's is).
func resolveIP(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}
