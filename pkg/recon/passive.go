package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// securityTxtPath is the well-known path Wave 0 fetches — zero-risk (one
// GET), and doubles as future input to a program-policy pre-flight check
// (docs/91-research-recon-phase.md §3, Wave 0) — no reason to fetch it
// twice later.
const securityTxtPath = "/.well-known/security.txt"

// runWave0 is the zero-touch wave: fetch security.txt if present, via the
// same rate-limited, circuit-broken httpclient.Client every detector uses
// (this is our own direct HTTP call, unlike Wave 1-3's binary-shelled
// steps, so it genuinely goes through that shared middleware).
func (r *Recon) runWave0(ctx context.Context, agg *aggregator, target string) {
	reqURL := strings.TrimRight(target, "/") + securityTxtPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		agg.addEndpoint(EndpointFact{
			URL:        reqURL,
			Method:     http.MethodGet,
			StatusCode: resp.StatusCode,
			Source:     "wave0-security-txt",
			Confidence: ConfidenceHigh,
		})
	}
}

// runWave1 runs passive subdomain/TLS/WHOIS/ASN enumeration and returns
// every candidate host discovered (domain itself plus every subfinder/tlsx
// result) — filterScope is the caller's next step, run before Wave 2 ever
// sees this list.
func (r *Recon) runWave1(ctx context.Context, agg *aggregator, domain string) []string {
	candidates := map[string]bool{domain: true}

	if hosts, err := r.runSubfinder(ctx, domain); err != nil {
		if isBinaryMissing(err) {
			agg.addWarning("wave1: %v — subdomain enumeration skipped", err)
		} else {
			agg.addWarning("wave1: subfinder: %v", err)
		}
	} else {
		for _, h := range hosts {
			candidates[h] = true
		}
	}

	if sans, err := r.runTLSX(ctx, domain); err != nil {
		if isBinaryMissing(err) {
			agg.addWarning("wave1: %v — TLS SAN enumeration skipped", err)
		} else {
			agg.addWarning("wave1: tlsx: %v", err)
		}
	} else {
		for _, h := range sans {
			candidates[h] = true
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
	if err != nil {
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
			Host string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.Host == "" {
			continue
		}
		hosts = append(hosts, rec.Host)
	}
	return hosts, nil
}

func (r *Recon) runTLSX(ctx context.Context, domain string) ([]string, error) {
	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	target := domain + ":443"
	out, err := r.run(waveCtx, "", "tlsx", "-u", target, "-san", "-silent", "-json")
	if err != nil {
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
	return hosts, nil
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
