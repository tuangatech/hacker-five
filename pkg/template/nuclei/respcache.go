package nuclei

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
)

// D5 (docs/16-implementation-plan-ph7.md Step 4, docs/follow-up.md LT-54 +
// LT-55): a scoped scan fires one loop over templates per target, and
// across the ~2,200-template misconfig floor the same handful of paths
// (`/`, `/.env`, `/.git/config`, `/robots.txt`, common CVE probes) get
// fetched many times over. Round-trip latency, not CPU, is that scan's
// wall-clock (LT-18(b): `user 2.6s` for a 2m+ run). This file removes two
// classes of redundant round trip without ever widening concurrency — the
// shared httpclient rate limiter stays the only throughput cap:
//
//   - respCache: an Executor-scoped, mutex-guarded, count-bounded response
//     cache keyed on (method, full URL, rendered-header fingerprint, body).
//     Consulted by tryPath before e.client.Do. Hard carve-outs that always
//     hit the network — see respCacheableKey: req.usesInteractsh, req.
//     usesTiming (any duration/duration_N reference), req.pathCorrelated, a
//     multi-value payloads: iteration (idSuffix), a raw: block (tryRaw
//     never consults the cache at all), and any method other than GET/HEAD
//     (a POST/PUT probe may be non-idempotent even when this tool only
//     enumerates). Only tryPath — the single-request, independent-per-path
//     code path — ever reads or writes it.
//
//   - knownDeadSkip: a set of URL paths a scan --recon-file result already
//     saw return 404 (scanner.Config.KnownDeadPaths via WithKnownDeadPaths).
//     A lone matcher-only path: request whose one path renders to a known-
//     dead path makes no request at all — gated to a scan carrying no
//     --header credential, i.e. running under the same unauthenticated
//     posture recon did (an unauthenticated 404 is not a guaranteed
//     authenticated-scan 404).

const (
	// respCacheMaxEntries bounds the per-Executor cache. The hot set a
	// full-corpus scan actually repeats is a few dozen common paths; this
	// leaves generous headroom while capping memory to (roughly) this many
	// response bodies.
	respCacheMaxEntries = 512
	// respCacheMaxBody skips caching a response body larger than this — a
	// large body is rarely one of the repeated common-path probes and
	// caching it would blow the memory bound respCacheMaxEntries assumes.
	respCacheMaxBody = 1 << 19 // 512 KiB
)

// respCacheEntry is one cached response — just enough for tryPath's
// matcher/extractor/evidence pipeline, which reads StatusCode, Header, and
// the already-drained body, never resp.Body itself.
type respCacheEntry struct {
	status int
	header http.Header
	body   []byte
}

// response rebuilds a *http.Response tryPath can use in place of a live
// one. Body is http.NoBody: tryPath has already read the real bytes into
// its respBody local by the time it would touch resp.Body, and http.NoBody
// is a valid no-op io.ReadCloser so an accidental Close never panics.
func (e respCacheEntry) response() *http.Response {
	return &http.Response{StatusCode: e.status, Header: e.header.Clone(), Body: http.NoBody}
}

// respCache is a bounded FIFO-evicted response cache, safe for the
// concurrent template workers scanner.Engine.runTemplates fans out against
// one target (they share a single Executor).
type respCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]respCacheEntry
	order   []string
}

func newRespCache() *respCache {
	return &respCache{max: respCacheMaxEntries, entries: make(map[string]respCacheEntry)}
}

func (c *respCache) get(key string) (respCacheEntry, bool) {
	if c == nil || key == "" {
		return respCacheEntry{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	return e, ok
}

func (c *respCache) put(key string, resp *http.Response, body []byte) {
	if c == nil || key == "" || resp == nil || len(body) > respCacheMaxBody {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; exists {
		return
	}
	if len(c.order) >= c.max {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
	c.entries[key] = respCacheEntry{
		status: resp.StatusCode,
		header: resp.Header.Clone(),
		body:   append([]byte(nil), body...),
	}
	c.order = append(c.order, key)
}

// respCacheableKey returns the cache key for req and whether this request
// may be served from / stored in the cache at all. The carve-outs here are
// the whole correctness surface of D5's part (1) — see this file's header.
func (e *Executor) respCacheableKey(req *http.Request, body string, r HTTPRequest, idSuffix bool) (string, bool) {
	if e.respCache == nil || idSuffix || r.usesInteractsh || r.usesTiming || r.pathCorrelated {
		return "", false
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if method != http.MethodGet && method != http.MethodHead {
		return "", false
	}

	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteByte('\n')
	sb.WriteString(req.URL.String())
	sb.WriteByte('\n')
	if req.Host != "" {
		sb.WriteString("host:")
		sb.WriteString(req.Host)
		sb.WriteByte('\n')
	}
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := append([]string(nil), req.Header[k]...)
		sort.Strings(vs)
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(strings.Join(vs, ","))
		sb.WriteByte('\n')
	}
	sb.WriteString("body:")
	sb.WriteString(body)

	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:]), true
}

// knownDeadSkip reports whether this exact request can be skipped entirely
// because a --recon-file already recorded its path as a 404 and skipping
// it can only re-confirm that. Deliberately narrow: a single-request,
// single-path, matcher-only template with no extractors, no payloads
// iteration, no interactsh/correlation, and a GET/HEAD method — anything
// else may need its request fired for a reason beyond its own matcher
// (chained extractor output, a correlated later probe). Gated to a scan
// with no --header credential so an authenticated scan, whose 404 surface
// differs from recon's unauthenticated pass, still fires every request.
func (e *Executor) knownDeadSkip(tmpl *Template, reqIdx int, req HTTPRequest, idSuffix bool, fullURL string) bool {
	if len(e.knownDead) == 0 || len(e.extraHeaders) > 0 {
		return false
	}
	if len(tmpl.HTTP) != 1 || reqIdx != 0 || idSuffix {
		return false
	}
	if len(req.Path) != 1 || len(req.Matchers) == 0 || len(req.Extractors) > 0 {
		return false
	}
	if req.usesInteractsh || req.pathCorrelated {
		return false
	}
	switch methodOrDefault(req.Method) {
	case http.MethodGet, http.MethodHead:
	default:
		return false
	}
	u, err := neturl.Parse(fullURL)
	if err != nil {
		return false
	}
	return e.knownDead[normalizeDeadPath(u.Path)]
}

// normalizeDeadPath canonicalizes a URL path for knownDead membership:
// leading slash, no trailing slash except root. Must match
// recon.ReconResult.DeadPaths' own normalization so the sets line up.
func normalizeDeadPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	for len(p) > 1 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}
