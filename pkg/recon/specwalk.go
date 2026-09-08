package recon

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// maxSpecBodyBytes bounds how much of a discovered OpenAPI/Swagger document
// walkOpenAPISpec reads and parses — a real spec is tens to a few hundred
// KiB; 3 MiB is generous headroom without letting a broken or hostile
// endpoint stream unboundedly into memory.
const maxSpecBodyBytes = 3 << 20

// maxSpecEndpoints caps how many EndpointFacts one spec walk contributes —
// the same "hints, not an exhaustive map" ceiling LT-39 puts on sitemap
// ingestion. A spec with more paths than this still yields its first
// maxSpecEndpoints (sorted, so the selection is stable) plus a warning.
const maxSpecEndpoints = 200

// openAPIMethods are the HTTP-method keys a path-item object can carry —
// every other key ("parameters", "summary", "description", "$ref",
// "servers") is not an operation.
var openAPIMethods = map[string]bool{
	http.MethodGet: true, http.MethodPut: true, http.MethodPost: true,
	http.MethodDelete: true, http.MethodOptions: true, http.MethodHead: true,
	http.MethodPatch: true, http.MethodTrace: true,
}

// specParam is the subset of an OpenAPI parameter object walkOpenAPISpec
// reads: its name and where it goes ("query", "path", "header", "cookie").
type specParam struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

// walkOpenAPISpec parses a fetched OpenAPI 2.0 / 3.x document into
// EndpointFacts — the richest single source of an API's real route and
// parameter surface there is (LT-40, docs/follow-up.md). The caller
// presence-gates it: probeCommonPaths only calls it once the response is a
// genuine structured spec body, not an SPA shell (LT-30). Pure — given the
// spec's URL and body it returns the facts, issues no requests, records
// nothing itself.
//
// Path templating is preserved verbatim ("/users/{id}"): a "{param}"
// segment is by construction an identifier position, and
// SuggestIDOREndpointCandidates treats it as one (isSpecPathParam), so the
// spec's documented object routes become idor candidates without the walker
// fabricating a concrete id. Documented query parameters are appended
// keyless ("?q=&url=") — enough for SuggestSSRFParamsFromRecon's name-based
// match; their values are not invented. Only OpenAPI JSON is handled this
// pass; a YAML spec is still recorded as an APISpecFact upstream but not
// walked (tracked in follow-up.md).
func walkOpenAPISpec(specURL string, body []byte) (facts []EndpointFact, truncated bool) {
	if len(body) == 0 {
		return nil, false
	}
	var doc struct {
		Swagger  string `json:"swagger"` // "2.0" for OpenAPI 2
		OpenAPI  string `json:"openapi"` // "3.x.x" for OpenAPI 3
		BasePath string `json:"basePath"`
		Servers  []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	if doc.Swagger == "" && doc.OpenAPI == "" {
		return nil, false // has "paths" but no version key — not an OpenAPI/Swagger document
	}
	if len(doc.Paths) == 0 {
		return nil, false
	}

	base, err := url.Parse(specURL)
	if err != nil || base.Host == "" {
		return nil, false
	}

	// The route prefix: OpenAPI 2's basePath, else the path component of the
	// first OpenAPI 3 server URL. Only the path is taken — a server on a
	// different host is a separate surface this pass doesn't chase.
	prefix := strings.TrimRight(strings.TrimSpace(doc.BasePath), "/")
	if prefix == "" {
		for _, s := range doc.Servers {
			su, err := url.Parse(strings.TrimSpace(s.URL))
			if err != nil {
				continue
			}
			if p := strings.TrimRight(su.Path, "/"); p != "" {
				prefix = p
				break
			}
		}
	}

	rawPaths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		rawPaths = append(rawPaths, p)
	}
	sort.Strings(rawPaths)

	seen := map[string]bool{}
	for _, p := range rawPaths {
		if !strings.HasPrefix(p, "/") {
			continue // a relative or server-templated path — skip
		}
		method, queryKeys := walkPathItem(doc.Paths[p])
		full := prefix + p
		if !strings.HasPrefix(full, "/") {
			full = "/" + full
		}
		full = base.Scheme + "://" + base.Host + full
		if len(queryKeys) > 0 {
			sort.Strings(queryKeys)
			parts := make([]string, len(queryKeys))
			for i, k := range queryKeys {
				parts[i] = url.QueryEscape(k) + "="
			}
			full += "?" + strings.Join(parts, "&")
		}
		if seen[full] {
			continue
		}
		seen[full] = true
		if len(facts) >= maxSpecEndpoints {
			truncated = true
			break
		}
		facts = append(facts, EndpointFact{
			URL:        full,
			Method:     method,
			Source:     "api-spec",
			Confidence: ConfidenceLow,
		})
	}
	return facts, truncated
}

// walkPathItem pulls the representative method and the set of documented
// query-parameter names out of one path-item object. The method is GET when
// the path documents one, else the first documented operation
// alphabetically (deterministic); it falls back to GET for a path-item that
// is all $ref/parameters and no operation.
func walkPathItem(raw json.RawMessage) (method string, queryKeys []string) {
	var item map[string]json.RawMessage
	if err := json.Unmarshal(raw, &item); err != nil {
		return http.MethodGet, nil
	}

	qk := map[string]bool{}
	collect := func(rawParams json.RawMessage) {
		var params []specParam
		if json.Unmarshal(rawParams, &params) != nil {
			return
		}
		for _, prm := range params {
			if strings.EqualFold(prm.In, "query") && prm.Name != "" {
				qk[prm.Name] = true
			}
		}
	}
	if pl, ok := item["parameters"]; ok {
		collect(pl) // path-level parameters, shared by every operation
	}

	var methods []string
	for k, v := range item {
		up := strings.ToUpper(k)
		if !openAPIMethods[up] {
			continue
		}
		methods = append(methods, up)
		var op struct {
			Parameters json.RawMessage `json:"parameters"`
		}
		if json.Unmarshal(v, &op) == nil && len(op.Parameters) > 0 {
			collect(op.Parameters)
		}
	}
	sort.Strings(methods)

	method = http.MethodGet
	if len(methods) > 0 {
		method = methods[0]
		for _, m := range methods {
			if m == http.MethodGet {
				method = http.MethodGet
				break
			}
		}
	}
	for k := range qk {
		queryKeys = append(queryKeys, k)
	}
	return method, queryKeys
}
