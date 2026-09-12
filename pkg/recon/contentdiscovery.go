package recon

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// embeddedContentDiscoveryWordlist is the default --content-discovery
// wordlist (Phase 8 Step 5 remainder, docs/17-implementation-plan-ph8.md —
// not LT-63, which names a separate, still-open Step 5 item: a CT-log-based
// companion mobile-app-API sibling discovery pass, docs/follow-up.md).
//
// Provenance/licence: verbatim, unmodified copy of SecLists'
// Discovery/Web-Content/common.txt (github.com/danielmiessler/SecLists,
// commit current as of 2026-09-12), 4,751 entries — the exact "seclists
// common.txt-scale" list doc17 Step 5 specified. SecLists is MIT-licensed
// (see wordlists/LICENSE-seclists.txt, bundled here per the MIT notice
// requirement); this repo's own MIT LICENSE is unaffected — HackerFive's
// code is not derived from SecLists, it embeds one of its data files.
// Deliberately kept byte-for-byte unmodified (no header comment added to
// the file itself): unlike wordlists/params.txt, this list is fed straight
// to httpx's own `-path` flag, which has no documented `#`-comment-strip
// convention — an injected header line here would fire as a literal,
// bogus probe request instead of being skipped.
//
//go:embed wordlists/common.txt
var embeddedContentDiscoveryWordlist string

// contentDiscoveryStatusFilter is httpx's own -mc argument for the sweep
// below — status codes that mean *something is actually there* (a real
// resource, a redirect, or an access-control wall guarding one). Everything
// else (404, and httpx's own default noise) is discarded by httpx itself
// before it ever reaches this process, keeping a several-thousand-entry
// wordlist's overwhelming 404 volume out of the parsed output entirely.
const contentDiscoveryStatusFilter = "200,201,204,301,302,307,308,401,403"

// discoverContentPaths is Phase 8 Step 5's opt-in bounded content-discovery
// pass (docs/17-implementation-plan-ph8.md): probes a curated wordlist
// of common *unlinked* paths (admin panels, backup files, `/.git/`-style
// dir indexes, config endpoints) against every Wave 3 seed — the surface a
// link-following crawl can't reach by definition, and distinct from
// probeCommonPaths' fixed app-shape list and misconfig's exposed-path
// checks (bad exposure, not discovery). A no-op unless --content-discovery
// is set; --recon-depth full only, structurally, the same way headless
// crawl/param-mining rely on runWave3 itself only running at DepthFull
// rather than adding a second depth check here.
//
// Runs through httpx's own `-path <file>` input rather than a second
// traffic-generating tool, so request volume rides the same --rate-limit
// every other httpx/katana invocation in this pipeline already honors —
// the specific reconciliation docs/14-implementation-plan-ph5.md named as
// ffuf's blocker. Bounded by r.waveTimeout like every other httpx/katana
// call here; a wordlist too large to finish in that window is a partial
// sweep (LT-38), not a hang.
//
// Called after probeCommonPaths (runWave3's ordering) so this can see —
// and skip — any host probeCommonPaths already classified as a uniform
// wall (D6) this run: a wordlist sweep against a WAF/catch-all host would
// otherwise report a "hit" for every single entry.
func (r *Recon) discoverContentPaths(ctx context.Context, agg *aggregator, seeds []string) {
	if !r.contentDiscovery {
		return
	}
	wordlistPath, cleanup, provenance, err := r.contentDiscoveryWordlistFile()
	if err != nil {
		agg.addWarning("wave3: content-discovery: %v — skipped", err)
		return
	}
	defer cleanup()

	waveCtx, cancel := context.WithTimeout(ctx, r.waveTimeout)
	defer cancel()
	httpxArgs := []string{
		"-silent", "-json", "-status-code", "-cl", "-ct",
		"-path", wordlistPath,
		"-mc", contentDiscoveryStatusFilter,
		"-rl", itoa(r.rateLimit), "-threads", itoa(r.concurrency),
	}
	httpxArgs = append(httpxArgs, r.headerArgs()...) // LT-36: program-mandated identifying header on every probe
	out, err := r.run(waveCtx, strings.Join(seeds, "\n"), "httpx", httpxArgs...)
	if err != nil && !isWaveTimeout(err) {
		if isBinaryMissing(err) {
			agg.addWarning("wave3: %v — content discovery skipped", err)
		} else {
			agg.addWarning("wave3: content-discovery: httpx: %v", err)
		}
		return
	}
	if isWaveTimeout(err) {
		agg.addWarning("wave3: content-discovery: httpx: %v (wordlist sweep did not run to completion)", err)
	}

	seedHosts := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedHosts[hostOnly(s)] = true
	}

	hits := 0
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var rec struct {
			URL           string `json:"url"`
			StatusCode    int    `json:"status_code"`
			ContentLength int    `json:"content_length"`
			ContentType   string `json:"content_type"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.URL == "" {
			continue
		}
		host := hostOnly(rec.URL)
		if !seedHosts[host] {
			continue // defensive: httpx's -path fan-out is per-input-host only
		}
		if _, walled := agg.uniformResponses[NormalizeHost(host)]; walled {
			continue // D6: a wordlist "hit" against a WAF/catch-all host is noise, not a finding
		}
		agg.addEndpoint(EndpointFact{
			URL: rec.URL, Method: http.MethodGet, StatusCode: rec.StatusCode,
			BodyLen: rec.ContentLength, ContentType: rec.ContentType,
			Source: "wave3-content-discovery", Confidence: ConfidenceMedium,
		})
		hits++
	}
	if hits > 0 {
		agg.addWarning("wave3: content-discovery found %d unlinked path(s) via a wordlist sweep [%s]", hits, provenance)
	}
}

// contentDiscoveryWordlistFile resolves the real path this run's
// discoverContentPaths hands to httpx's `-path` flag: --content-discovery-
// wordlist verbatim when set (the operator's own file, their choice/risk —
// no size cap, unlike param-mining's capped override), or the embedded
// default written out to a temp file (httpx's -path needs a real path on
// disk; the embedded string has none). cleanup removes the temp file when
// the embedded default was used; a no-op otherwise.
func (r *Recon) contentDiscoveryWordlistFile() (path string, cleanup func(), provenance string, err error) {
	if r.contentDiscoveryWordlist != "" {
		if _, statErr := os.Stat(r.contentDiscoveryWordlist); statErr != nil {
			return "", nil, "", fmt.Errorf("--content-discovery-wordlist: %w", statErr)
		}
		return r.contentDiscoveryWordlist, func() {}, "wordlist " + filepath.Base(r.contentDiscoveryWordlist), nil
	}
	tmp, err := os.CreateTemp("", "hackerfive-content-discovery-*.txt")
	if err != nil {
		return "", nil, "", fmt.Errorf("writing embedded content-discovery wordlist: %w", err)
	}
	if _, err := tmp.WriteString(embeddedContentDiscoveryWordlist); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", nil, "", fmt.Errorf("writing embedded content-discovery wordlist: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", nil, "", fmt.Errorf("writing embedded content-discovery wordlist: %w", err)
	}
	name := tmp.Name()
	return name, func() { _ = os.Remove(name) }, "built-in SecLists common.txt (4,751 entries)", nil
}
