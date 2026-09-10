package recon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
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

// specBodyToJSON returns body as JSON bytes: unchanged when it already is
// JSON (an object/array head), else the result of a YAML decode re-marshalled
// to JSON (LT-40(b), docs/follow-up.md — springdoc and many hand-written
// specs are served as YAML). yaml.v3 decodes a mapping into
// map[string]interface{}, which json.Marshal then handles directly; a body
// that is neither valid JSON nor valid YAML, or a YAML scalar/sequence that
// can't represent a spec object, yields ok=false and the caller treats the
// document as unwalkable (still recorded as a presence-only APISpecFact
// upstream).
func specBodyToJSON(body []byte) (jsonBody []byte, ok bool) {
	if head := bytes.TrimLeft(body, " \t\r\n"); len(head) > 0 && (head[0] == '{' || head[0] == '[') {
		return body, true
	}
	var doc any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	if _, isMap := doc.(map[string]any); !isMap {
		return nil, false // a spec document is a mapping at the top level
	}
	j, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return j, true
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
// match; their values are not invented. Both JSON and YAML spec bodies are
// handled (LT-40(b), docs/follow-up.md): a YAML document is normalised to
// JSON once up front (specBodyToJSON) and walked by the identical code
// path — the caller's structured-Content-Type gate already only lets a
// genuine spec body reach here.
func walkOpenAPISpec(specURL string, body []byte) (facts []EndpointFact, truncated bool) {
	if len(body) == 0 {
		return nil, false
	}
	jsonBody, ok := specBodyToJSON(body)
	if !ok {
		return nil, false
	}
	var doc struct {
		Swagger  string `json:"swagger"` // "2.0" for OpenAPI 2
		OpenAPI  string `json:"openapi"` // "3.x.x" for OpenAPI 3
		BasePath string `json:"basePath"`
		Servers  []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Security []map[string]json.RawMessage `json:"security"` // document-level default auth requirement (LT-90)
		Paths    map[string]json.RawMessage   `json:"paths"`
	}
	if err := json.Unmarshal(jsonBody, &doc); err != nil {
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

	docRequiresAuth := securityListRequiresAuth(doc.Security)

	seen := map[string]bool{}
	for _, p := range rawPaths {
		if !strings.HasPrefix(p, "/") {
			continue // a relative or server-templated path — skip
		}
		method, queryKeys, bodyParamKeys, authRequired := walkPathItem(doc.Paths[p], docRequiresAuth)
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
			URL:           full,
			Method:        method,
			Source:        "api-spec",
			Confidence:    ConfidenceLow,
			AuthRequired:  authRequired,
			BodyParamKeys: bodyParamKeys,
		})
	}
	return facts, truncated
}

// walkPathItem pulls the representative method, the set of documented
// query-parameter names, the representative operation's requestBody JSON
// schema property names (LT-96), and whether the representative operation
// requires authentication (LT-90) out of one path-item object. The method is
// GET when the path documents one, else the first documented operation
// alphabetically (deterministic); it falls back to GET for a path-item that
// is all $ref/parameters and no operation. docRequiresAuth is the
// document-level default, used unless the operation declares its own
// `security`.
func walkPathItem(raw json.RawMessage, docRequiresAuth bool) (method string, queryKeys, bodyParamKeys []string, authRequired bool) {
	var item map[string]json.RawMessage
	if err := json.Unmarshal(raw, &item); err != nil {
		return http.MethodGet, nil, nil, docRequiresAuth
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

	ops := map[string]json.RawMessage{}
	bodyKeysByOp := map[string][]string{}
	var methods []string
	for k, v := range item {
		up := strings.ToUpper(k)
		if !openAPIMethods[up] {
			continue
		}
		methods = append(methods, up)
		ops[up] = v
		var op struct {
			Parameters  json.RawMessage `json:"parameters"`
			RequestBody json.RawMessage `json:"requestBody"`
		}
		if json.Unmarshal(v, &op) == nil {
			if len(op.Parameters) > 0 {
				collect(op.Parameters)
			}
			if len(op.RequestBody) > 0 {
				bodyKeysByOp[up] = requestBodyPropertyNames(op.RequestBody)
			}
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

	// LT-90: an operation-level `security` overrides the document default;
	// an explicit `security: []` is a deliberate opt-out and also overrides.
	authRequired = docRequiresAuth
	if declared, requires := operationSecurity(ops[method]); declared {
		authRequired = requires
	}

	for k := range qk {
		queryKeys = append(queryKeys, k)
	}
	sort.Strings(queryKeys)
	bodyParamKeys = bodyKeysByOp[method]
	sort.Strings(bodyParamKeys)
	return method, queryKeys, bodyParamKeys, authRequired
}

// requestBodyPropertyNames reads an OpenAPI 3 `requestBody` object's
// top-level JSON schema property names — `content["application/json"].
// schema.properties` only (LT-96, docs/follow-up.md); no nested-object
// recursion and no other media type in v1, matching this walker's existing
// "names only, no values invented" scope for query parameters.
func requestBodyPropertyNames(raw json.RawMessage) []string {
	var rb struct {
		Content map[string]struct {
			Schema struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schema"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &rb) != nil {
		return nil
	}
	media, ok := rb.Content["application/json"]
	if !ok {
		return nil
	}
	var names []string
	for name := range media.Schema.Properties {
		names = append(names, name)
	}
	return names
}

// operationSecurity reports whether an operation object declares a `security`
// key at all, and if so whether it mandates auth. `security: []` counts as
// declared-but-not-required (an explicit opt-out from the doc default).
func operationSecurity(rawOp json.RawMessage) (declared, requires bool) {
	if len(rawOp) == 0 {
		return false, false
	}
	var op struct {
		Security *[]map[string]json.RawMessage `json:"security"`
	}
	if json.Unmarshal(rawOp, &op) != nil || op.Security == nil {
		return false, false
	}
	return true, securityListRequiresAuth(*op.Security)
}

// securityListRequiresAuth reports whether an OpenAPI `security` requirement
// list actually mandates auth: at least one entry naming at least one
// scheme. An empty list, or a list of only empty objects, does not.
func securityListRequiresAuth(list []map[string]json.RawMessage) bool {
	for _, entry := range list {
		if len(entry) > 0 {
			return true
		}
	}
	return false
}
