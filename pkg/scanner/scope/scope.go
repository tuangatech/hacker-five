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
	domains []string // exact or "*."-prefixed suffix entries, already lowercased
	cidrs   []*net.IPNet
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
		s.domains = append(s.domains, strings.ToLower(line))
	}
	return s, nil
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
		if strings.HasPrefix(d, "*.") {
			return true
		}
	}
	return false
}

// Allowed reports whether target's host matches an entry in s — a bare
// domain must match exactly, a "*."-prefixed entry matches that domain and
// any subdomain, and a CIDR entry matches only when the host is a literal
// IP address. Default-deny: an unparseable target or a host matching
// nothing is not allowed.
func (s *Scope) Allowed(target string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		for _, cidr := range s.cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
	}

	for _, d := range s.domains {
		if strings.HasPrefix(d, "*.") {
			suffix := d[1:] // ".example.com"
			if host == d[2:] || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		if host == d {
			return true
		}
	}
	return false
}
