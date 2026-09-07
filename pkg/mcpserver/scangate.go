package mcpserver

import (
	"net/url"
	"strings"
	"sync"
)

// D1 — per-session aggregate scan-concurrency ceiling (doc16 Phase 7 Step
// 4). A coordinator can fire many `scan` tool calls in parallel; each on
// its own looks reasonable (defaultConcurrency cross-target × the engine's
// per-target template fan-out), but their sum against one host is what
// actually lands on the target. A stdio MCP server is one client per
// process (A5), so a package-level gate is session-scoped by construction.
//
// The gate does two things per host a scan call touches:
//   - hard backpressure: at most maxConcurrentScansPerHost `scan` calls run
//     against one host at once; a further call blocks in enter until one
//     releases (the shared rate limiter is still the real throttle — this
//     just bounds how much concurrency can pile onto a single host).
//   - budget split: an admitted call's per-target template fan-out is
//     aggregateTemplateConcurrencyPerHost / (calls now active on its
//     most-contended host), floored at minTemplateConcurrency — so two
//     concurrent calls get ~half each rather than the full default each.
//
// It is a ceiling, not a precise partition: the first-admitted call keeps
// the budget it computed at entry even as later calls arrive. Re-capping a
// call already inside the engine isn't possible, and defense-in-depth on
// top of the rate limiter doesn't need that precision.
const (
	aggregateTemplateConcurrencyPerHost = 10 // matches scanner engine's defaultTemplateConcurrency
	maxConcurrentScansPerHost           = 3
	minTemplateConcurrency              = 2
)

type scanConcurrencyGate struct {
	mu     sync.Mutex
	cond   *sync.Cond
	active map[string]int // host -> in-flight scan calls
}

func newScanConcurrencyGate() *scanConcurrencyGate {
	g := &scanConcurrencyGate{active: map[string]int{}}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// sessionScanGate is the process-wide (== session-wide) instance runScan
// consults. Reset between tests via newScanConcurrencyGate.
var sessionScanGate = newScanConcurrencyGate()

// enter registers a scan call against every distinct host in targets,
// blocking while any of those hosts is already at maxConcurrentScansPerHost.
// It returns the per-target template concurrency the caller should apply
// (scanner.Config.TemplateConcurrency) and a release func to call exactly
// once when the scan finishes. A call with no parseable host still gets a
// budget and a no-op release, so an unusual target can never wedge it.
func (g *scanConcurrencyGate) enter(targets []string) (templateConcurrency int, release func()) {
	hosts := distinctScanHosts(targets)
	if len(hosts) == 0 {
		return aggregateTemplateConcurrencyPerHost, func() {}
	}

	g.mu.Lock()
	for {
		clear := true
		for _, h := range hosts {
			if g.active[h] >= maxConcurrentScansPerHost {
				clear = false
				break
			}
		}
		if clear {
			break
		}
		g.cond.Wait()
	}
	maxActive := 1
	for _, h := range hosts {
		g.active[h]++
		if g.active[h] > maxActive {
			maxActive = g.active[h]
		}
	}
	g.mu.Unlock()

	budget := aggregateTemplateConcurrencyPerHost / maxActive
	if budget < minTemplateConcurrency {
		budget = minTemplateConcurrency
	}

	var once sync.Once
	return budget, func() {
		once.Do(func() {
			g.mu.Lock()
			for _, h := range hosts {
				if g.active[h] > 0 {
					g.active[h]--
				}
				if g.active[h] == 0 {
					delete(g.active, h)
				}
			}
			g.cond.Broadcast()
			g.mu.Unlock()
		})
	}
}

// distinctScanHosts returns the lower-cased host[:port] of every target,
// deduped, order-stable. A target that doesn't parse as a URL with a host
// is folded to its raw trimmed string so it still contends with an
// identical raw target.
func distinctScanHosts(targets []string) []string {
	seen := make(map[string]bool, len(targets))
	var out []string
	for _, t := range targets {
		h := ""
		if u, err := url.Parse(strings.TrimSpace(t)); err == nil && u.Host != "" {
			h = strings.ToLower(u.Host)
		} else {
			h = strings.ToLower(strings.TrimSpace(t))
		}
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}
