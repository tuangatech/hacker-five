// Package netservice implements first-party checks for unauthenticated
// exposure of common non-HTTP network services (FTP, MySQL, Redis from
// Phase 8 Step 1's original design — see docs/17-implementation-plan-ph8.md's
// Design section — plus PostgreSQL and MongoDB added for docs/follow-up.md's
// LT-142). Each check is a single, bounded, read-only handshake that
// stops at "did it let me in" — never enumerating data, never a real
// password guess against a real account, never anything beyond the one
// empty/anonymous-credential attempt every check below documents. Directly
// closes docs/follow-up.md's LT-23: staging.andertone.com (owned, in
// scope) exposes FTP (21) and MySQL (3306) straight to the internet with
// nothing able to check either.
//
// Dispatched by registry.resolvePortFacts promoting a "netservice"-covered
// open port (see its netserviceCheckedPorts) to a real dispatchable leaf
// whose Target is "tcp://host:port" — see pkg/scanner.Engine's "netservice"
// runDetector case.
package netservice

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/template/tcpproto"
)

// Detector runs the built-in unauthenticated-network-service checks.
type Detector struct {
	timeout time.Duration
}

// Option configures a Detector at construction time — same functional-
// options shape ssrf.Detector/authbypass.Detector already use.
type Option func(*Detector)

// WithTimeout overrides the dial/write/read deadline every check uses. A
// zero/negative d is a no-op, leaving tcpproto's own DefaultTimeout as the
// effective value (New's default).
func WithTimeout(d time.Duration) Option {
	return func(det *Detector) {
		if d > 0 {
			det.timeout = d
		}
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

// portChecks maps a port number to the check that owns it — kept as data
// (rather than a switch inside Run) so the "which ports does this detector
// actually cover" question has one obvious place to answer, matching
// registry.netserviceCheckedPorts on the decision-engine side (that map
// controls whether a leaf gets dispatched here at all; this one decides
// what runs once it is).
var portChecks = map[int]func(d *Detector, ctx context.Context, addr, target string) ([]detectors.Finding, error){
	21:    (*Detector).checkFTPAnonymous,
	3306:  (*Detector).checkMySQLEmptyPassword,
	5432:  (*Detector).checkPostgresTrustAuth,
	6379:  (*Detector).checkRedisUnauth,
	27017: (*Detector).checkMongoUnauthListDatabases,
}

// Run checks target — a "tcp://host:port" leaf (registry.resolvePortFacts'
// shape) — for unauthenticated access, dispatching on the port number.
// Returns (nil, nil) for a port this detector doesn't cover yet (defensive
// only: registry.netserviceCheckedPorts already gates which ports ever
// reach here) rather than an error — an unrecognized port is not this
// call's fault.
func (d *Detector) Run(ctx context.Context, target string) ([]detectors.Finding, error) {
	addr, port, err := parseTarget(target)
	if err != nil {
		return nil, fmt.Errorf("netservice: %w", err)
	}
	check, ok := portChecks[port]
	if !ok {
		return nil, nil
	}
	return check(d, ctx, addr, target)
}

// parseTarget splits a "tcp://host:port" leaf into the "host:port" dial
// address tcpproto.Dial expects and the port number this Detector
// dispatches on.
func parseTarget(target string) (addr string, port int, err error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", 0, fmt.Errorf("parsing target %q: %w", target, err)
	}
	if u.Scheme != "tcp" {
		return "", 0, fmt.Errorf("target %q: expected a tcp:// leaf, got scheme %q", target, u.Scheme)
	}
	_, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", 0, fmt.Errorf("target %q: no port: %w", target, err)
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("target %q: invalid port %q", target, portStr)
	}
	return u.Host, port, nil
}

// sanitizeID mirrors ssrf.sanitizeID's convention for turning an address
// into a safe Finding.ID suffix.
func sanitizeID(s string) string {
	return strings.NewReplacer(":", "-", ".", "-").Replace(s)
}

func timeoutOrDefault(d time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return tcpproto.DefaultTimeout
}
