package recon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Response-shape capture (docs/94-llm-finding-capability-strategy.md, Phase 0).
//
// Recon knows an endpoint's URL, method, status and size, but not what it
// returns — so nothing downstream, deterministic or model, can tell "this
// endpoint returns objects owned by the caller" from "this endpoint returns a
// static list". A response *shape* is the JSON structure with every value
// replaced by its type name: {"items":[{"id":"int","owner_id":"int"}]}. It is
// enough to see resources, id-like fields and ownership references, and by
// construction it carries no response data (doc91 §4: never raw bodies in an
// agent's context).

const (
	// maxShapeProbes bounds the pass's GETs, the same "hints, not a crawl"
	// ceiling as LT-76's status pass (maxUnprobedEndpointProbes).
	maxShapeProbes = 25

	// maxShapeBodyBytes bounds how much of one response is parsed. A body cut
	// off by the limit fails JSON parsing and simply yields no shape.
	maxShapeBodyBytes = 256 << 10

	shapeProbeTimeout = 10 * time.Second

	maxShapeDepth = 4   // nesting levels rendered; deeper collapses to {…} / […]
	maxShapeKeys  = 40  // keys rendered per object
	maxShapeChars = 600 // rendered length; longer is cut and marked
	shapeArrayMix = 3   // array elements merged so a sparse first element does not hide fields
	dynamicKeyLen = 40  // an object key longer than this is treated as data, not schema
	shapeDynKey   = "<key>"
)

// jsonShape returns body's structure with values replaced by type names, and
// false when body is not a JSON object or array (a bare scalar has no schema
// worth recording, and non-JSON is not this pass's business).
//
// Object keys are part of the schema, so they are kept — except a key that
// looks like data rather than a field name (an email, a UUID, a number, a long
// token: what a map keyed by user or record produces). Those collapse to one
// "<key>" entry so a value never leaks through a key.
func jsonShape(body []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", false
	}
	switch v.(type) {
	case map[string]any, []any:
	default:
		return "", false
	}
	s := shapeOf(v, 0)
	if r := []rune(s); len(r) > maxShapeChars {
		s = string(r[:maxShapeChars]) + "…"
	}
	return s, true
}

func shapeOf(v any, depth int) string {
	switch x := v.(type) {
	case nil:
		return `"null"`
	case bool:
		return `"bool"`
	case json.Number:
		if strings.ContainsAny(x.String(), ".eE") {
			return `"number"`
		}
		return `"int"`
	case string:
		return `"string"`
	case []any:
		if len(x) == 0 {
			return `[]`
		}
		if depth >= maxShapeDepth {
			return `[…]`
		}
		return "[" + arrayElemShape(x, depth+1) + "]"
	case map[string]any:
		if depth >= maxShapeDepth {
			return `{…}`
		}
		return renderShapeFields(objectFields(x, depth+1))
	}
	return `"?"`
}

// arrayElemShape renders one shape for a whole array. Up to shapeArrayMix
// object elements are merged field-by-field (a field absent or null in the
// first element but present in a later one still shows); any other array is
// described by its first element.
func arrayElemShape(items []any, depth int) string {
	var merged map[string]string
	n := 0
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if depth > maxShapeDepth {
			return `{…}`
		}
		if merged == nil {
			merged = map[string]string{}
		}
		for k, sh := range objectFields(m, depth) {
			if cur, seen := merged[k]; !seen || cur == `"null"` {
				merged[k] = sh
			}
		}
		if n++; n >= shapeArrayMix {
			break
		}
	}
	if merged != nil {
		return renderShapeFields(merged)
	}
	return shapeOf(items[0], depth)
}

// objectFields maps each (non-dynamic) key of m to its rendered shape. All
// dynamic keys share one "<key>" entry, shaped from the first of them in sorted
// order so the result is deterministic.
func objectFields(m map[string]any, depth int) map[string]string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		name := k
		if dynamicKey(k) {
			name = shapeDynKey
			if _, done := out[name]; done {
				continue
			}
		}
		if len(out) >= maxShapeKeys {
			out["…"] = `"…"`
			break
		}
		out[name] = shapeOf(m[k], depth)
	}
	return out
}

func renderShapeFields(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quoteShapeKey(k))
		b.WriteByte(':')
		b.WriteString(fields[k])
	}
	b.WriteByte('}')
	return b.String()
}

// quoteShapeKey JSON-quotes a key without json.Marshal's HTML escaping, which
// would turn the "<key>" marker into "<key>" in text a model reads.
func quoteShapeKey(k string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(k); err != nil {
		return `"?"`
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// dynamicKey reports whether k looks like a value used as a key rather than a
// schema field name.
func dynamicKey(k string) bool {
	if k == "" || len(k) > dynamicKeyLen || strings.ContainsAny(k, "@ /") {
		return true
	}
	if _, err := strconv.ParseInt(k, 10, 64); err == nil {
		return true
	}
	if len(k) == 36 && strings.Count(k, "-") == 4 { // UUID
		return true
	}
	if len(k) >= 20 && isHex(k) { // hash / token / object id
		return true
	}
	return false
}

func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// Shape-candidate tiers, best first. The pass is capped, so what it spends its
// requests on matters: an endpoint known to be JSON should not queue behind
// crawl hits that might be HTML pages.
const (
	shapeTierKnownJSON    = iota // an API spec documents it, or it was observed answering JSON
	shapeTierLikelyAPI           // observed 2xx, content type unknown, path looks like an API route
	shapeTierUnknown             // observed 2xx, content type unknown, path says nothing
	shapeTierNotCandidate = -1
)

// shapeTier reports whether ep is worth one GET for its response shape and how
// early: a parameter-free GET that an API spec documents, or that was observed
// answering 2xx. A templated path ("{id}") has no concrete URL to fetch, and
// recon never invents an id.
//
// A katana crawl fact has a status but no content type, so "content type
// unknown" must stay eligible — the body decides: a response only yields a
// shape if it parses as JSON. An observed non-JSON content type is excluded.
func shapeTier(ep *EndpointFact) int {
	if ep.ResponseShape != "" {
		return shapeTierNotCandidate
	}
	if ep.Method != "" && !strings.EqualFold(ep.Method, http.MethodGet) {
		return shapeTierNotCandidate
	}
	p := endpointPath(ep.URL)
	if p == "" || IsStaticAssetPath(p) || !IsPlausibleURLPath(p) {
		return shapeTierNotCandidate
	}
	if strings.ContainsAny(ep.URL, "{}") || strings.Contains(strings.ToLower(ep.URL), "%7b") {
		return shapeTierNotCandidate
	}
	if ep.Source == "api-spec" {
		return shapeTierKnownJSON
	}
	if ep.StatusCode < 200 || ep.StatusCode >= 300 {
		return shapeTierNotCandidate
	}
	ct := strings.ToLower(ep.ContentType)
	switch {
	case strings.Contains(ct, "json"):
		return shapeTierKnownJSON
	case ct != "":
		return shapeTierNotCandidate // observed as something else (html, image, ...)
	}
	lp := strings.ToLower(p)
	if strings.HasSuffix(lp, ".json") || strings.Contains(lp, "/api") || strings.Contains(lp, "/v1/") || strings.Contains(lp, "/v2/") || strings.Contains(lp, "/graphql") {
		return shapeTierLikelyAPI
	}
	return shapeTierUnknown
}

// probeResponseShapes issues one bounded GET each against the most interesting
// shape candidates and records the JSON structure of a 2xx JSON answer on
// EndpointFact.ResponseShape. GET-only, in-scope, no redirect following, capped
// at maxShapeProbes, and sent with the operator's configured headers — an
// authenticated run therefore sees authenticated shapes, which is the point: a
// 401 error body says nothing about the resource.
func (r *Recon) probeResponseShapes(ctx context.Context, agg *aggregator, seeds []string) {
	seedHosts := make(map[string]bool, len(seeds))
	for _, s := range seeds {
		seedHosts[NormalizeHost(hostOnly(s))] = true
	}

	type candidate struct {
		url        string
		tier, rank int
	}
	var candidates []candidate
	seen := map[string]int{} // url -> index in candidates, so a better-tiered duplicate fact wins
	for i := range agg.endpoints {
		ep := &agg.endpoints[i]
		tier := shapeTier(ep)
		if tier == shapeTierNotCandidate {
			continue
		}
		host := hostOnly(ep.URL)
		if !seedHosts[NormalizeHost(host)] && (r.scope == nil || !r.scope.Allowed("https://"+host)) {
			continue
		}
		if at, dup := seen[ep.URL]; dup {
			if tier < candidates[at].tier {
				candidates[at].tier = tier
			}
			continue
		}
		seen[ep.URL] = len(candidates)
		candidates = append(candidates, candidate{url: ep.URL, tier: tier, rank: pathInterestRank(endpointPath(ep.URL))})
	}
	if len(candidates) == 0 {
		return
	}
	sort.SliceStable(candidates, func(a, b int) bool {
		if candidates[a].tier != candidates[b].tier {
			return candidates[a].tier < candidates[b].tier
		}
		return candidates[a].rank < candidates[b].rank
	})
	if len(candidates) > maxShapeProbes {
		candidates = candidates[:maxShapeProbes]
	}

	base := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // matches recon.ClientConfig / endpointprobe — internal-cert hosts must not fail closed
		ForceAttemptHTTP2: true,
	}
	// credentialed: this probe builds its own client, so the credential the shared
	// client carries (LT-187) has to be added here too; without it an authenticated
	// recon would read the anonymous 401 body of every route it can now see.
	probe := &http.Client{
		Timeout:       shapeProbeTimeout,
		Transport:     r.credentialed(base),
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer base.CloseIdleConnections()

	shapes := map[string]string{}
	seedSources := map[string]string{} // list URL -> one object id in it; memory only (EndpointFact.SeedID)
	for _, c := range candidates {
		host := hostOnly(c.url)
		if r.hostErrors.ShouldSkip(host) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
		if err != nil {
			continue
		}
		r.applyHeaders(req)
		req.Header.Set("Accept", "application/json")
		resp, err := probe.Do(req)
		if err != nil {
			if !isRequestTimeout(err) {
				r.hostErrors.RecordError(host)
			}
			continue
		}
		r.hostErrors.RecordSuccess(host)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxShapeBodyBytes))
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		if shape, ok := jsonShape(body); ok {
			shapes[c.url] = shape
		}
		if id := harvestUUIDSeed(body); id != "" {
			seedSources[c.url] = id
		}
	}
	if n := attachHarvestedSeeds(agg, seedSources); n > 0 {
		agg.addWarning("wave3: %d templated route(s) were given an object id read from a list response, so an idor leaf can test them (the id is held in memory only and is never recorded)", n)
	}
	if len(shapes) == 0 {
		return
	}
	for i := range agg.endpoints {
		ep := &agg.endpoints[i]
		if s, ok := shapes[ep.URL]; ok && (ep.Method == "" || strings.EqualFold(ep.Method, http.MethodGet)) {
			ep.ResponseShape = s
		}
	}
	agg.addWarning("wave3: captured a response shape (JSON structure, no values) for %d of %d endpoint(s) probed", len(shapes), len(candidates))
}
