package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// securityTxtPath/robotsTxtPath are the well-known paths Wave 0 fetches —
// zero-risk (one GET each), and feed pkg/preflight's D2 program-policy
// pre-flight check (docs/91-research-recon-phase.md §3, Wave 0; doc15 Step 3)
// — no reason to fetch either twice later.
const (
	securityTxtPath = "/.well-known/security.txt"
	robotsTxtPath   = "/robots.txt"
	sitemapPath     = "/sitemap.xml"
	// maxPolicyBodyBytes caps how much of security.txt is retained — it's only
	// ever substring-scanned for advisory warnings, never parsed.
	maxPolicyBodyBytes = 16 << 10
	// LT-39 (docs/follow-up.md) bounds: robots.txt and sitemap.xml are free
	// endpoint hints, but an unbounded sitemap could otherwise flood
	// Endpoints. One sitemap body is capped, and so are the number of
	// Disallow/Allow paths, <loc> entries, and sitemap fetches per host.
	maxSitemapBodyBytes    = 512 << 10
	maxRobotsHintEndpoints = 50
	maxSitemapLocs         = 50
	maxSitemapFetches      = 3
)

// runWave0 is the zero-touch wave: fetch security.txt and robots.txt if
// present, via the same rate-limited, circuit-broken httpclient.Client every
// detector uses (this is our own direct HTTP call, unlike Wave 1-3's
// binary-shelled steps, so it genuinely goes through that shared middleware).
func (r *Recon) runWave0(ctx context.Context, agg *aggregator, target string) {
	base := strings.TrimRight(target, "/")

	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+securityTxtPath, nil); err == nil {
		r.applyHeaders(req)
		if resp, err := r.client.Do(req); err == nil {
			func() {
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode < 200 || resp.StatusCode >= 400 {
					return
				}
				agg.addEndpoint(EndpointFact{
					URL:        base + securityTxtPath,
					Method:     http.MethodGet,
					StatusCode: resp.StatusCode,
					Source:     "wave0-security-txt",
					Confidence: ConfidenceHigh,
				})
				body, _ := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBodyBytes))
				agg.securityTxt = string(body)
			}()
		}
	}

	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+robotsTxtPath, nil); err == nil {
		r.applyHeaders(req)
		if resp, err := r.client.Do(req); err == nil {
			var body string
			func() {
				defer func() { _ = resp.Body.Close() }()
				if resp.StatusCode < 200 || resp.StatusCode >= 400 {
					return
				}
				b, _ := io.ReadAll(io.LimitReader(resp.Body, maxPolicyBodyBytes))
				body = string(b)
			}()
			if body != "" {
				agg.robotsDisallowAll = robotsDisallowsAll(body)
				r.harvestRobotsHints(ctx, agg, base, body)
			}
		}
	}
}

// harvestRobotsHints turns robots.txt into endpoint hints (LT-39,
// docs/follow-up.md): each Disallow:/Allow: path prefix becomes a
// ConfidenceLow EndpointFact (Source "robots-txt") — a "Disallow: /admin/"
// is a classic tell — and every Sitemap: URL is fetched, its <loc> entries
// recorded (Source "sitemap-xml"). Hints only: the Disallow/Allow paths
// themselves are never requested, and every recorded URL is same-host and
// scope-checked. Bounded by maxRobotsHintEndpoints / maxSitemapFetches.
func (r *Recon) harvestRobotsHints(ctx context.Context, agg *aggregator, base, body string) {
	seen := map[string]bool{}
	added := 0
	var sitemaps []string
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "disallow", "allow":
			p := robotsHintPath(val)
			if p == "" || seen[p] || added >= maxRobotsHintEndpoints {
				continue
			}
			seen[p] = true
			added++
			agg.addEndpoint(EndpointFact{
				URL: base + p, Method: http.MethodGet,
				Source: "robots-txt", Confidence: ConfidenceLow,
			})
		case "sitemap":
			if val != "" && len(sitemaps) < maxSitemapFetches && !containsStr(sitemaps, val) {
				sitemaps = append(sitemaps, val)
			}
		}
	}
	// Also try the conventional /sitemap.xml even when robots.txt didn't name one.
	if def := base + sitemapPath; len(sitemaps) < maxSitemapFetches && !containsStr(sitemaps, def) {
		sitemaps = append(sitemaps, def)
	}
	for _, sm := range sitemaps {
		r.harvestSitemap(ctx, agg, hostOnly(base), sm)
	}
}

// robotsHintPath validates a Disallow:/Allow: value as a plain path prefix
// worth recording — a leading "/", not the bare "/", and no wildcard/anchor/
// query metacharacters (a pattern like "/*.php$" names no single resource).
func robotsHintPath(v string) string {
	if v == "" || v == "/" || !strings.HasPrefix(v, "/") {
		return ""
	}
	if strings.ContainsAny(v, "*$?#") {
		return ""
	}
	return v
}

// sitemapLoc is one <loc> element. sitemapDoc decodes both a <urlset>
// (regular sitemap) and a <sitemapindex> (index pointing at child sitemaps)
// — xml.Unmarshal matches by child-element tag, so one struct covers both
// root types.
type sitemapLoc struct {
	Loc string `xml:"loc"`
}

type sitemapDoc struct {
	URLs     []sitemapLoc `xml:"url"`
	Sitemaps []sitemapLoc `xml:"sitemap"`
}

// harvestSitemap fetches one sitemap URL and records its <loc> entries as
// ConfidenceLow EndpointFacts — same-host and scope-checked, capped at
// maxSitemapLocs. A child-sitemap <loc> from an index is recorded as a hint
// too but not recursively fetched (bounded zero-touch pass).
func (r *Recon) harvestSitemap(ctx context.Context, agg *aggregator, host, sitemapURL string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return
	}
	r.applyHeaders(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxSitemapBodyBytes))
	var doc sitemapDoc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return
	}
	added := 0
	for _, e := range append(append([]sitemapLoc{}, doc.URLs...), doc.Sitemaps...) {
		if added >= maxSitemapLocs {
			break
		}
		loc := strings.TrimSpace(e.Loc)
		if loc == "" {
			continue
		}
		u, err := url.Parse(loc)
		if err != nil || u.Hostname() != host {
			continue // same-host only
		}
		if r.scope != nil && !r.scope.Allowed(loc) {
			continue
		}
		added++
		agg.addEndpoint(EndpointFact{
			URL: loc, Method: http.MethodGet,
			Source: "sitemap-xml", Confidence: ConfidenceLow,
		})
	}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// robotsDisallowsAll reports whether robots.txt tells every crawler to stay
// out entirely — a "Disallow: /" (with no path after the slash) under a
// "User-agent: *" group. A crawler convention, surfaced only as an advisory
// warning by pkg/preflight, never a block.
func robotsDisallowsAll(body string) bool {
	inStar := false
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch key {
		case "user-agent":
			inStar = val == "*"
		case "disallow":
			if inStar && val == "/" {
				return true
			}
		}
	}
	return false
}

// runWave1 runs passive subdomain/TLS/WHOIS/ASN enumeration and returns
// every candidate host discovered (domain itself plus every subfinder/tlsx
// result) — filterScope is the caller's next step, run before Wave 2 ever
// sees this list.
func (r *Recon) runWave1(ctx context.Context, agg *aggregator, domain string) []string {
	candidates := map[string]bool{domain: true}

	// LT-35 (docs/follow-up.md): subdomain/SAN enumeration only has somewhere
	// to land when the scope is broader than a list of exact hostnames. A
	// bug-bounty program's scope.txt is often 8 named assets and nothing else
	// (Meesho's is) — every subfinder/tlsx result is then guaranteed to fail
	// filterScope, so the two ~network-bound waves are pure latency on every
	// recon/plan/scan for the engagement. The listed host(s) are still
	// resolved, port-scanned and probed by Wave 2; WHOIS/ASN still runs.
	if r.scope != nil && !r.scope.HasWildcard() {
		agg.addWarning("wave1: --scope is an exact-host allow-list (no *. or CIDR entry) — subdomain and TLS-SAN enumeration skipped, every result would be out of scope (LT-35)")
	} else {
		if hosts, err := r.runSubfinder(ctx, domain); err != nil && !isWaveTimeout(err) {
			if isBinaryMissing(err) {
				agg.addWarning("wave1: %v — subdomain enumeration skipped", err)
			} else {
				agg.addWarning("wave1: subfinder: %v", err)
			}
		} else {
			if isWaveTimeout(err) {
				agg.addWarning("wave1: subfinder: %v", err)
			}
			for _, h := range hosts {
				candidates[h] = true
			}
		}

		if sans, err := r.runTLSX(ctx, domain); err != nil && !isWaveTimeout(err) {
			if isBinaryMissing(err) {
				agg.addWarning("wave1: %v — TLS SAN enumeration skipped", err)
			} else {
				agg.addWarning("wave1: tlsx: %v", err)
			}
		} else {
			if isWaveTimeout(err) {
				agg.addWarning("wave1: tlsx: %v", err)
			}
			for _, h := range sans {
				candidates[h] = true
			}
		}
	}

	if isPrivateOrLoopbackHost(domain) {
		agg.addWarning("wave1: %s is a private/loopback address — WHOIS/ASN lookups skipped (no public registry data exists for it)", domain)
	} else {
		r.runWHOISAndASN(ctx, agg, domain)
	}

	out := make([]string, 0, len(candidates))
	for h := range candidates {
		out = append(out, h)
	}
	return out
}

// filterScope cross-checks every Wave 1 candidate against r.scope
// immediately — before Wave 2 fires a single active probe, per doc91's
// corrected ordering (an earlier draft deferred this to Wave 4, after
// active probes had already touched every host). Hosts failing the check
// go to ReconResult.OutOfScope and are excluded from the returned slice; a
// nil r.scope (no --scope given) allows everything, same posture as scan's
// own optional --scope.
func (r *Recon) filterScope(agg *aggregator, hosts []string) []string {
	if r.scope == nil {
		return hosts
	}
	var inScope []string
	for _, h := range hosts {
		if r.scope.Allowed("https://" + h) {
			inScope = append(inScope, h)
			continue
		}
		agg.addOutOfScope(h)
	}
	return inScope
}

func (r *Recon) runSubfinder(ctx context.Context, domain string) ([]string, error) {
	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	out, err := r.run(waveCtx, "", "subfinder", "-d", domain, "-silent", "-json", "-rate-limit", itoa(r.rateLimit))
	if err != nil && !isWaveTimeout(err) {
		return nil, err
	}
	// On a wave timeout err is errWaveTimeout and out holds whatever subfinder
	// streamed before the kill — parse it and pass the error up so the caller
	// warns (LT-38).
	var hosts []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.Host == "" {
			continue
		}
		hosts = append(hosts, rec.Host)
	}
	return hosts, err // nil, or errWaveTimeout with partial hosts (LT-38)
}

func (r *Recon) runTLSX(ctx context.Context, domain string) ([]string, error) {
	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	target := domain + ":443"
	out, err := r.run(waveCtx, "", "tlsx", "-u", target, "-san", "-silent", "-json")
	if err != nil && !isWaveTimeout(err) {
		return nil, err
	}
	var hosts []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			SubjectAN []string `json:"subject_an"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		hosts = append(hosts, rec.SubjectAN...)
	}
	return hosts, err // nil, or errWaveTimeout with partial hosts (LT-38)
}

// isPrivateOrLoopbackHost reports whether domain is a loopback/private/
// link-local IP literal, or the literal "localhost" — the only cases
// runWave1 skips WHOIS/ASN for. Found live via CI, 2026-09-04: recon always
// runs (no opt-out), and runWHOISAndASN used to fire unconditionally,
// including for local lab/test targets like "127.0.0.1" — WHOIS has no
// record for a private address, so lookupWHOIS's real TCP dial to
// whois.iana.org was pure wasted latency (up to whoisDialTimeout per dial,
// twice if IANA names a referral) with no data to show for it, and on a
// network that can't reach or is slow to reach the real internet (a CI
// runner, an air-gapped lab), that latency was misattributed to the test
// suite being flaky rather than to this call.
func isPrivateOrLoopbackHost(domain string) bool {
	if strings.EqualFold(domain, "localhost") {
		return true
	}
	ip := net.ParseIP(domain)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// runWHOISAndASN best-effort attaches WHOIS/ASN facts to domain's HostFact
// — first-party stdlib clients (whois.go), never a hard failure for the
// whole wave if either lookup fails.
func (r *Recon) runWHOISAndASN(ctx context.Context, agg *aggregator, domain string) {
	host := HostFact{Host: domain, Source: "passive-whois-asn", Confidence: ConfidenceMedium}

	if raw, err := lookupWHOIS(ctx, domain); err == nil {
		if summary := summarizeWHOIS(raw); summary != "" {
			host.Notes = append(host.Notes, "whois: "+summary)
		}
	} else {
		agg.addWarning("wave1: whois: %v", err)
	}

	if ip, err := firstIPv4(ctx, domain); err == nil {
		if asn, prefix, country, err := lookupASN(ctx, ip); err == nil {
			host.Notes = append(host.Notes, fmt.Sprintf("asn: %s | %s | %s (resolved via %s)", asn, prefix, country, ip))
			// LT-61 (docs/follow-up.md): if that AS is a known CDN/edge
			// network, this host is a CDN POP and not the origin — record it
			// so runNaabu skips a pointless edge port scan and the plan/report
			// doesn't read as origin coverage.
			if cdn := cdnForASNField(asn); cdn != "" {
				host.Notes = append(host.Notes, fmt.Sprintf("cdn-edge: ASN %s (%s) is a CDN/edge network — %s resolves to a CDN POP, not the origin; port scan and edge headers reflect the CDN (LT-61)", asn, cdn, domain))
				agg.markCDNEdge(domain, cdn)
			}
		} else {
			agg.addWarning("wave1: asn: %v", err)
		}
	} else {
		agg.addWarning("wave1: resolving %s for asn lookup: %v", domain, err)
	}

	if len(host.Notes) > 0 {
		agg.addHost(host)
	}
}

// summarizeWHOIS extracts a short, human-readable line from a raw WHOIS
// response — just the registrar/organization field if present, since the
// full raw text is verbose and mostly boilerplate; sanity-checking who
// actually owns a discovered host is the point (doc91 §3, Wave 1), not
// reproducing the whole record.
func summarizeWHOIS(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		for _, prefix := range []string{"registrant organization:", "registrar:", "org:", "organisation:"} {
			if strings.HasPrefix(lower, prefix) {
				return strings.TrimSpace(line)
			}
		}
	}
	return ""
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
