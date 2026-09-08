package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/fingerprint"
)

// cdnHeaderTokens maps a CDN/edge brand (lower-cased, as httpx -tech-detect
// names it) to header signatures that corroborate the host itself sits
// behind that CDN. httpx's Wappalyzer-style catalog also flags a CDN from a
// cookie name or an inline script referencing its dashboard, both of which
// a plain origin that merely *links* CDN-hosted assets can carry — the
// LT-84 case (docs/follow-up.md): sandbox-royal.securegateway.com served
// `Server: nginx` with no cf-* headers yet was fingerprinted "Cloudflare",
// mis-framing the origin as CDN-fronted and seeding an unresolved leaf. A
// CDN brand with no header backing (and non-empty captured headers to
// judge against) is dropped rather than attributed. A "name:value" token
// matches a header whose value contains value; a bare token matches header
// presence.
var cdnHeaderTokens = map[string][]string{
	"cloudflare":        {"cf-ray", "cf-cache-status", "server:cloudflare"},
	"amazon cloudfront": {"x-amz-cf-id", "x-amz-cf-pop", "via:cloudfront", "server:cloudfront"},
	"cloudfront":        {"x-amz-cf-id", "x-amz-cf-pop", "via:cloudfront", "server:cloudfront"},
	"akamai":            {"x-akamai-transformed", "x-akamai-request-id", "akamai-grn", "server:akamaighost"},
	"fastly":            {"x-served-by", "x-fastly-request-id", "fastly-restarts", "via:varnish"},
}

// headersCorroborateCDN reports whether headers carry any of tokens (see
// cdnHeaderTokens). Header names are matched case-insensitively.
func headersCorroborateCDN(headers map[string]string, tokens []string) bool {
	lower := make(map[string]string, len(headers))
	for k, v := range headers {
		lower[strings.ToLower(k)] = strings.ToLower(v)
	}
	for _, tok := range tokens {
		if name, val, ok := strings.Cut(tok, ":"); ok {
			if hv, present := lower[name]; present && strings.Contains(hv, val) {
				return true
			}
			continue
		}
		if _, present := lower[tok]; present {
			return true
		}
	}
	return false
}

// dropCDNTechWithoutHeader reports whether an httpx -tech-detect CDN brand
// should be discarded because the host's own response headers show no such
// edge (LT-84b). Non-CDN techs and the case where httpx captured no headers
// at all (nothing to judge against) are always kept.
func (r *Recon) dropCDNTechWithoutHeader(agg *aggregator, tech, host string, headers map[string]string) bool {
	tokens, isCDN := cdnHeaderTokens[strings.ToLower(strings.TrimSpace(tech))]
	if !isCDN || len(headers) == 0 || headersCorroborateCDN(headers, tokens) {
		return false
	}
	agg.addWarning("wave2: %s: tech-detect reported %q but the host's own response headers carry no matching edge signature — not attributed (LT-84b)", host, tech)
	return true
}

// runWave2 is the standard first live-touch step (docs/91-research-recon-
// phase.md §3): resolve, port-scan, and HTTP-probe every in-scope host from
// Wave 1 — never a host Wave 1's scope filter already excluded. targetHost
// is the original target's own host:port (from the target URL Run was
// given) — always added to httpx's own input, even when it differs from
// the bare domain subfinder/tlsx queried, since a non-default port (common
// for lab/staging targets) can't otherwise be rediscovered from a passive
// domain-only enumeration. Returns the live base URLs httpx actually
// confirmed, for Wave 3's crawl to use.
func (r *Recon) runWave2(ctx context.Context, agg *aggregator, targetHost string, inScopeHosts []string) []string {
	if len(inScopeHosts) == 0 {
		return nil
	}

	resolved := r.runDNSX(ctx, agg, inScopeHosts)
	if len(resolved) == 0 {
		resolved = inScopeHosts // dnsx unavailable/found nothing new to filter on — fall back to Wave 1's own list
	}

	// naabu reports results keyed by IP, not hostname — joined against
	// httpx's own resolved "host_ip" field below, not the input hostname.
	portsByIP := r.runNaabu(ctx, agg, resolved)
	httpxTargets := resolved
	if targetHost != "" && !contains(httpxTargets, targetHost) {
		httpxTargets = append([]string{targetHost}, httpxTargets...)
	}
	liveURLs, hostFacts := r.runHTTPX(ctx, agg, httpxTargets)

	for _, hf := range hostFacts {
		if ps, ok := portsByIP[hf.hostIP]; ok {
			hf.Ports = ps
		}
		agg.addHost(hf.HostFact)

		// R7: deterministic tech-signature matching on top of httpx's own
		// -tech-detect list, using the same headers/body/favicon httpx
		// already captured plus the just-merged port list — see
		// pkg/fingerprint's own doc comment for why this doesn't replace
		// httpx's own list, it enriches it.
		ports := make([]int, 0, len(hf.Ports))
		for _, p := range hf.Ports {
			ports = append(ports, p.Port)
		}
		for _, m := range fingerprint.Detect(fingerprint.Signal{Headers: hf.headers, Body: hf.body, FaviconHash: hf.favicon, Ports: ports}) {
			confidence := ConfidenceHigh
			switch m.Source {
			case fingerprint.SourceBody:
				confidence = ConfidenceMedium
			case fingerprint.SourcePort:
				confidence = ConfidenceLow
			}
			agg.addTech(TechFact{Name: m.Product, Host: hf.Host, Source: m.Source, Confidence: confidence})
		}
	}
	return liveURLs
}

func (r *Recon) runDNSX(ctx context.Context, agg *aggregator, hosts []string) []string {
	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	out, err := r.run(waveCtx, strings.Join(hosts, "\n"), "dnsx", "-silent", "-json", "-a", "-resp", "-rl", itoa(r.rateLimit))
	if err != nil && !isWaveTimeout(err) {
		if isBinaryMissing(err) {
			agg.addWarning("wave2: %v — dns resolution skipped, using wave1's host list unfiltered", err)
		} else {
			agg.addWarning("wave2: dnsx: %v", err)
		}
		return nil
	}
	if isWaveTimeout(err) {
		agg.addWarning("wave2: dnsx: %v", err) // partial resolution below (LT-38)
	}
	var resolved []string
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
		resolved = append(resolved, rec.Host)
	}
	return resolved
}

// runNaabu returns discovered ports keyed by IP — naabu's own JSON output
// identifies a result by "ip", not the original input hostname (confirmed
// against the real binary's output, not assumed).
func (r *Recon) runNaabu(ctx context.Context, agg *aggregator, hosts []string) map[string][]PortFact {
	// LT-61 (docs/follow-up.md): a host that resolves into a known CDN/edge
	// AS has no origin service ports to find — a scan of it maps the CDN's
	// POPs, not the target. Drop those from the scan (a fresh slice, so the
	// caller's list is untouched) and say so explicitly, so the plan/report
	// never implies origin port coverage.
	scanHosts := hosts[:0:0]
	for _, h := range hosts {
		if cdn, ok := agg.cdnEdgeFor(h); ok {
			agg.addWarning("wave2: %s: resolves into %s's CDN/edge network — port scan skipped; a CDN edge exposes only its own 80/443, never the target's origin services (LT-61)", h, cdn)
			continue
		}
		scanHosts = append(scanHosts, h)
	}
	if len(scanHosts) == 0 {
		return nil
	}
	hosts = scanHosts

	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	out, err := r.run(waveCtx, strings.Join(hosts, "\n"), "naabu", "-silent", "-json", "-top-ports", "100", "-rate", itoa(r.rateLimit))
	if err != nil && !isWaveTimeout(err) {
		if isBinaryMissing(err) {
			agg.addWarning("wave2: %v — port scan skipped", err)
		} else {
			agg.addWarning("wave2: naabu: %v", err)
		}
		return nil
	}
	if isWaveTimeout(err) {
		// naabu scans top-100 ports for every in-scope host at the global
		// rate limit — past ~6 hosts it's routinely cut off here. The partial
		// port map below is still real, just incomplete (LT-38).
		agg.addWarning("wave2: naabu: %v (port scan may not have reached every host)", err)
	}
	byIP := make(map[string][]PortFact)
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.IP == "" || rec.Port == 0 {
			continue
		}
		proto := rec.Protocol
		if proto == "" {
			proto = "tcp"
		}
		if !hasPort(byIP[rec.IP], rec.Port, proto) {
			byIP[rec.IP] = append(byIP[rec.IP], PortFact{Port: rec.Port, Protocol: proto, Source: "naabu"})
		}
	}
	return byIP
}

// hasPort reports whether ports already contains port/proto — naabu can
// report the same open port more than once across its own internal retries.
func hasPort(ports []PortFact, port int, proto string) bool {
	for _, p := range ports {
		if p.Port == port && p.Protocol == proto {
			return true
		}
	}
	return false
}

// hostWithIP pairs an httpx-derived HostFact with the IP httpx itself
// resolved it to ("host_ip" in its JSON output) — the join key runWave2
// uses to attach runNaabu's by-IP port results, since naabu and httpx
// identify a result differently (IP vs. input hostname). headers/body/
// favicon carry httpx's own captured response signals through to runWave2,
// where pkg/fingerprint's matching runs once the port list is also known.
type hostWithIP struct {
	HostFact
	hostIP  string
	headers map[string]string
	body    string
	favicon string
}

func (r *Recon) runHTTPX(ctx context.Context, agg *aggregator, hosts []string) ([]string, []hostWithIP) {
	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	httpxArgs := []string{
		"-silent", "-json", "-status-code", "-title", "-web-server", "-tech-detect", "-follow-redirects",
		"-include-chain", "-location", // LT-64: the redirect chain + final URL, so a cross-host redirect isn't recorded as the target's own 200
		"-favicon", "-irr", // R7: response headers/body + favicon hash, for pkg/fingerprint's signature matching
		"-cl", "-ct", // LT-30b: content-length + content-type into the JSON, so an EndpointFact carries response shape a soft-404/catch-all check can use
		"-rl", itoa(r.rateLimit), "-threads", itoa(r.concurrency),
	}
	httpxArgs = append(httpxArgs, r.headerArgs()...) // LT-36: program-mandated identifying header on every probe
	out, err := r.run(waveCtx, strings.Join(hosts, "\n"), "httpx", httpxArgs...)
	if err != nil && !isWaveTimeout(err) {
		if isBinaryMissing(err) {
			agg.addWarning("wave2: %v — http probing skipped", err)
		} else {
			agg.addWarning("wave2: httpx: %v", err)
		}
		return nil, nil
	}
	if isWaveTimeout(err) {
		agg.addWarning("wave2: httpx: %v (not every host may have been probed)", err) // partial results parsed below (LT-38)
	}

	var urls []string
	var hostFacts []hostWithIP
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // -irr includes full response bodies, can exceed bufio's 64KiB default
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			URL              string            `json:"url"`
			Host             string            `json:"host"`
			HostIP           string            `json:"host_ip"`
			StatusCode       int               `json:"status_code"`
			ContentLength    int               `json:"content_length"`
			ContentType      string            `json:"content_type"`
			Title            string            `json:"title"`
			Tech             []string          `json:"tech"`
			Header           map[string]string `json:"header"`
			Body             string            `json:"body"`
			Favicon          string            `json:"favicon"`
			FinalURL         string            `json:"final_url"`
			ChainStatusCodes []int             `json:"chain_status_codes"`
			Chain            []httpxChainHop   `json:"chain"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.URL == "" {
			continue
		}
		urls = append(urls, rec.URL)
		host := rec.Host
		if host == "" {
			host = hostOnly(rec.URL)
		}

		// LT-64/LT-65 (docs/follow-up.md): httpx followed a redirect that
		// landed on a *different* host. Its status/title/body/tech all
		// describe that other host — attribute none of it here. Keep a
		// record of the probed host with the first-hop 3xx status and the
		// chain, so downstream sees "redirected away", not a phantom 200.
		crossHost, chain, firstHopStatus := analyzeRedirect(rec.FinalURL, host, rec.Chain, rec.ChainStatusCodes, rec.StatusCode)
		if crossHost {
			if r.scope != nil && !r.scope.Allowed(rec.FinalURL) {
				agg.addWarning("wave2: %s: redirects OUT OF SCOPE to %s — its response, tech and shape are not attributed to the target (LT-64)", host, rec.FinalURL)
			} else {
				agg.addWarning("wave2: %s: redirects across hosts to %s — response shape and tech are attributed there, not to %s (LT-64/LT-65)", host, rec.FinalURL, host)
			}
		}

		hf := hostWithIP{
			HostFact: HostFact{Host: host, Source: "httpx", Confidence: ConfidenceHigh},
			hostIP:   rec.HostIP,
		}
		ef := EndpointFact{URL: rec.URL, Method: "GET", Source: "httpx", Confidence: ConfidenceHigh}
		if crossHost {
			ef.StatusCode = firstHopStatus
			ef.RedirectChain = chain
			ef.FinalURL = rec.FinalURL
		} else {
			ef.StatusCode = rec.StatusCode
			ef.BodyLen = rec.ContentLength
			ef.ContentType = rec.ContentType
			ef.Title = rec.Title
			hf.headers = rec.Header
			hf.body = rec.Body
			hf.favicon = rec.Favicon
		}
		hostFacts = append(hostFacts, hf)
		agg.addEndpoint(ef)
		if !crossHost {
			for _, tech := range rec.Tech {
				if r.dropCDNTechWithoutHeader(agg, tech, host, rec.Header) {
					continue
				}
				agg.addTech(TechFact{Name: tech, Host: host, Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
			}
		}
	}
	return urls, hostFacts
}

// httpxChainHop is one entry of httpx's `-include-chain` array: the URL it
// requested and the status that hop returned.
type httpxChainHop struct {
	RequestURL string `json:"request-url"`
	StatusCode int    `json:"status_code"`
}

// analyzeRedirect decides whether httpx's followed redirect crossed to a
// different host and, if so, returns a "<status> <url>" line per hop plus
// the first hop's status (the 3xx). finalURL is httpx's `final_url`; it is
// only set when a redirect was actually followed. A same-host redirect
// (http→https, "/"→"/en/") is not cross-host and is treated as a normal
// response. Falls back to synthesising a two-line chain from
// chainStatusCodes when the full `chain` array is absent.
func analyzeRedirect(finalURL, probedHost string, chain []httpxChainHop, chainStatusCodes []int, finalStatus int) (crossHost bool, chainLines []string, firstHopStatus int) {
	firstHopStatus = finalStatus
	if finalURL == "" {
		return false, nil, firstHopStatus
	}
	finalHost := hostOnly(finalURL)
	if finalHost == "" || NormalizeHost(finalHost) == NormalizeHost(probedHost) {
		return false, nil, firstHopStatus
	}
	switch {
	case len(chain) > 0:
		for _, hop := range chain {
			chainLines = append(chainLines, fmt.Sprintf("%d %s", hop.StatusCode, hop.RequestURL))
		}
		if chain[0].StatusCode != 0 {
			firstHopStatus = chain[0].StatusCode
		}
	case len(chainStatusCodes) > 0:
		firstHopStatus = chainStatusCodes[0]
		chainLines = []string{
			fmt.Sprintf("%d (redirect)", chainStatusCodes[0]),
			fmt.Sprintf("%d %s", finalStatus, finalURL),
		}
	default:
		chainLines = []string{fmt.Sprintf("%d %s", finalStatus, finalURL)}
	}
	return true, chainLines, firstHopStatus
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func hostOnly(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return rawURL
}
