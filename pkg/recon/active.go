package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/fingerprint"
)

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
	if err != nil {
		if isBinaryMissing(err) {
			agg.addWarning("wave2: %v — dns resolution skipped, using wave1's host list unfiltered", err)
		} else {
			agg.addWarning("wave2: dnsx: %v", err)
		}
		return nil
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
	waveCtx, cancel := context.WithTimeout(ctx, waveTimeout)
	defer cancel()
	out, err := r.run(waveCtx, strings.Join(hosts, "\n"), "naabu", "-silent", "-json", "-top-ports", "100", "-rate", itoa(r.rateLimit))
	if err != nil {
		if isBinaryMissing(err) {
			agg.addWarning("wave2: %v — port scan skipped", err)
		} else {
			agg.addWarning("wave2: naabu: %v", err)
		}
		return nil
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
	out, err := r.run(waveCtx, strings.Join(hosts, "\n"), "httpx",
		"-silent", "-json", "-status-code", "-title", "-web-server", "-tech-detect", "-follow-redirects",
		"-favicon", "-irr", // R7: response headers/body + favicon hash, for pkg/fingerprint's signature matching
		"-rl", itoa(r.rateLimit), "-threads", itoa(r.concurrency))
	if err != nil {
		if isBinaryMissing(err) {
			agg.addWarning("wave2: %v — http probing skipped", err)
		} else {
			agg.addWarning("wave2: httpx: %v", err)
		}
		return nil, nil
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
			URL        string            `json:"url"`
			Host       string            `json:"host"`
			HostIP     string            `json:"host_ip"`
			StatusCode int               `json:"status_code"`
			Tech       []string          `json:"tech"`
			Header     map[string]string `json:"header"`
			Body       string            `json:"body"`
			Favicon    string            `json:"favicon"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.URL == "" {
			continue
		}
		urls = append(urls, rec.URL)
		host := rec.Host
		if host == "" {
			host = hostOnly(rec.URL)
		}
		hostFacts = append(hostFacts, hostWithIP{
			HostFact: HostFact{Host: host, Source: "httpx", Confidence: ConfidenceHigh},
			hostIP:   rec.HostIP,
			headers:  rec.Header,
			body:     rec.Body,
			favicon:  rec.Favicon,
		})
		agg.addEndpoint(EndpointFact{URL: rec.URL, Method: "GET", StatusCode: rec.StatusCode, Source: "httpx", Confidence: ConfidenceHigh})
		for _, tech := range rec.Tech {
			agg.addTech(TechFact{Name: tech, Host: host, Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
		}
	}
	return urls, hostFacts
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
