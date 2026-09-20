// Package scope enforces an explicit allow-list of authorized targets before
// a scan dispatches any request — closing a gap flagged Critical in
// docs/follow-up.md §1 ("No technical scope-enforcement mechanism"), open
// since Phase 1. See docs/11-implementation-plan-ph2.md Step 0 for the
// design tradeoff: enforcement only applies when a --scope file is actually
// given, so every existing documented lab-target workflow (README, doc20)
// keeps working unmodified with no flag at all.
package scope

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// Scope is a parsed --scope file: a set of domain (exact or "*."-prefixed
// suffix) and CIDR entries a target's host must match against.
type Scope struct {
	domains []domainEntry
	cidrs   []*net.IPNet
}

// domainEntry is one parsed domain-line: pattern is the exact or
// "*."-prefixed suffix (already lowercased), port is an optional exact port
// this entry is pinned to. An empty port means "any port on this host" — the
// original, and still default, behavior; a non-empty port narrows the entry
// to that one port only (docs/follow-up.md LT-167: `Allowed` used to have no
// port dimension at all, so a scope entry meant to authorize one service on
// one port silently also authorized every other service colocated on the
// same hostname's other ports).
type domainEntry struct {
	pattern string
	port    string
}

// Parse reads path — one entry per line, blank lines and "#"-prefixed
// comments ignored (same convention as cmd/hackerfive/scan.go's
// resolveTargets file handling) — then hands the lines to New. File-specific
// concerns (open/read/line-splitting) live only here; entry-parsing lives
// only in New, so the two never drift apart.
func Parse(path string) (*Scope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scope: opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scope: reading %s: %w", path, err)
	}
	return New(lines)
}

// New builds a Scope directly from in-memory entries (one per element,
// blank/"#"-prefixed entries ignored) — the same per-line syntax Parse
// reads from a file, for a caller that already has entries in memory (e.g.
// an MCP tool argument) rather than a path on the server's own filesystem.
func New(entries []string) (*Scope, error) {
	s := &Scope{}
	for _, line := range entries {
		// Cut an inline "# comment" before anything else — a "#" is legal in
		// neither a hostname nor a CIDR, so from the first one on the rest of
		// the line is a comment, not part of the entry. Without this a
		// "host  # note" line was stored whole (lowercased) as one domain
		// that Allowed could never match, silently dropping an in-scope
		// target (docs/follow-up.md LT-80). A full-line "# comment" reduces
		// to "" here and is skipped by the blank test below.
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(line); err == nil {
			s.cidrs = append(s.cidrs, ipNet)
			continue
		}
		s.domains = append(s.domains, parseDomainEntry(line))
	}
	return s, nil
}

// parseDomainEntry splits an optional trailing ":port" off a domain line —
// e.g. "localhost:8888" or "*.example.com:8443" — via net.SplitHostPort,
// which already correctly rejects a bare (unbracketed) IPv6-shaped entry as
// ambiguous rather than misparsing it, leaving it as a whole, port-less
// pattern exactly as before. A line with no colon at all (the overwhelming
// common case) is unaffected: port stays "", meaning "any port".
func parseDomainEntry(line string) domainEntry {
	if host, port, err := net.SplitHostPort(line); err == nil {
		return domainEntry{pattern: strings.ToLower(host), port: port}
	}
	return domainEntry{pattern: strings.ToLower(line)}
}

// HasWildcard reports whether the scope contains any entry broader than a
// single exact hostname — a "*."-prefixed domain suffix, or a CIDR block
// (which can contain subdomains not spelled out in the file). Recon's Wave 1
// subdomain/SAN enumeration only has somewhere in-scope to land when this is
// true; a scope that is nothing but an exact-host allow-list (a bug-bounty
// program's list of named assets) makes that enumeration pure latency, since
// Allowed rejects every discovered name (docs/follow-up.md LT-35).
func (s *Scope) HasWildcard() bool {
	if len(s.cidrs) > 0 {
		return true
	}
	for _, d := range s.domains {
		if strings.HasPrefix(d.pattern, "*.") {
			return true
		}
	}
	return false
}

// Entries reserializes s back into the one-per-line syntax Parse/New accept
// — domain entries as-is, CIDR entries via their canonical net.IPNet
// string. Not necessarily byte-identical to the original file (comments and
// formatting are gone, and a CIDR's host bits are normalized), but Parse(s
// re-fed through New) always reproduces an equivalent Scope. Used when a
// Scope needs to cross a process boundary that doesn't share Go memory
// (pkg/scriptexec's egress-proxy sidecar container, which reads scope
// entries from a mounted file via Parse).
func (s *Scope) Entries() []string {
	out := make([]string, 0, len(s.domains)+len(s.cidrs))
	for _, d := range s.domains {
		if d.port == "" {
			out = append(out, d.pattern)
			continue
		}
		out = append(out, net.JoinHostPort(d.pattern, d.port))
	}
	for _, c := range s.cidrs {
		out = append(out, c.String())
	}
	return out
}

// Allowed reports whether target's host matches an entry in s — a bare
// domain must match exactly, a "*."-prefixed entry matches that domain and
// any subdomain, and a CIDR entry matches only when the host is a literal
// IP address. Default-deny: an unparseable target or a host matching
// nothing is not allowed.
//
// A domain entry pinned to a port (LT-167, docs/follow-up.md — "host:port"
// in the scope file) only matches a target on that exact port; target's own
// port defaults per its scheme (443 for https, 80 otherwise) when omitted,
// so "https://example.com" is correctly compared against an "example.com:443"
// entry. A domain entry with no port (the default, and the only form that
// existed before LT-167) still matches that host on any port at all —
// existing scope files keep working unmodified.
func (s *Scope) Allowed(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range s.cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}

	for _, d := range s.domains {
		if d.port != "" && d.port != port {
			continue
		}
		if strings.HasPrefix(d.pattern, "*.") {
			suffix := d.pattern[1:] // ".example.com"
			if host == d.pattern[2:] || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == d.pattern {
			return true
		}
	}
	return false
}
