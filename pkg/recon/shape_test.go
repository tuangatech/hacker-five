package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONShape_TypesNotValues(t *testing.T) {
	body := `{"id": 7, "email": "jane@example.com", "score": 1.5, "active": true, "note": null,
		"token": "s3cr3t-value", "items": [{"sku": "A1", "qty": 2}, {"sku": "B2", "qty": 3, "gift": true}]}`
	got, ok := jsonShape([]byte(body))
	require.True(t, ok)
	assert.Equal(t,
		`{"active":"bool","email":"string","id":"int","items":[{"gift":"bool","qty":"int","sku":"string"}],"note":"null","score":"number","token":"string"}`,
		got)
	for _, leak := range []string{"jane@example.com", "s3cr3t-value", "A1", "B2"} {
		assert.NotContains(t, got, leak, "a shape must never carry a response value")
	}
}

// A map keyed by user id / email / uuid would put data in the keys; those must
// collapse so a value cannot leak through the schema.
func TestJSONShape_DataLikeKeysCollapse(t *testing.T) {
	body := `{"jane@example.com": {"role": "admin"}, "42": {"role": "user"},
		"3f2b8c1e-1111-4222-8333-444455556666": {"role": "user"}, "plain": {"role": "x"}}`
	got, ok := jsonShape([]byte(body))
	require.True(t, ok)
	assert.Equal(t, `{"<key>":{"role":"string"},"plain":{"role":"string"}}`, got)
	assert.NotContains(t, got, "jane@example.com")
	assert.NotContains(t, got, "42")
	assert.NotContains(t, got, "3f2b8c1e")
}

func TestJSONShape_RejectsNonObjectsAndBadJSON(t *testing.T) {
	for _, body := range []string{``, `not json`, `"just a string"`, `42`, `true`, `<html></html>`, `{"cut": [1, 2`} {
		_, ok := jsonShape([]byte(body))
		assert.False(t, ok, "body %q has no recordable shape", body)
	}
	got, ok := jsonShape([]byte(`[]`))
	require.True(t, ok)
	assert.Equal(t, `[]`, got)
}

func TestJSONShape_BoundedDepthAndLength(t *testing.T) {
	deep := `{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}`
	got, ok := jsonShape([]byte(deep))
	require.True(t, ok)
	assert.Contains(t, got, `{…}`, "nesting past maxShapeDepth collapses")
	assert.NotContains(t, got, `"f"`)

	var b strings.Builder
	b.WriteString(`{`)
	for i := 0; i < 200; i++ {
		if i > 0 {
			b.WriteString(`,`)
		}
		fmt.Fprintf(&b, `"field_%03d": "v"`, i)
	}
	b.WriteString(`}`)
	long, ok := jsonShape([]byte(b.String()))
	require.True(t, ok)
	assert.LessOrEqual(t, len([]rune(long)), maxShapeChars+1, "rendered shape is length-capped")
}

func TestJSONShape_IsDeterministic(t *testing.T) {
	body := `{"z":1,"a":2,"m":{"y":1,"b":2},"list":[{"k":1},{"j":2}]}`
	first, _ := jsonShape([]byte(body))
	for i := 0; i < 20; i++ {
		again, _ := jsonShape([]byte(body))
		require.Equal(t, first, again)
	}
}

func TestShapeCandidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		ep   EndpointFact
		want bool
	}{
		{"observed 2xx json GET", EndpointFact{URL: "http://x.test/api/items", Method: "GET", StatusCode: 200, ContentType: "application/json; charset=utf-8"}, true},
		{"observed with no method recorded", EndpointFact{URL: "http://x.test/api/items", StatusCode: 200, ContentType: "application/json"}, true},
		{"spec route with no observed status", EndpointFact{URL: "http://x.test/api/items", Method: "GET", Source: "api-spec"}, true},
		{"templated spec route has no concrete URL", EndpointFact{URL: "http://x.test/api/items/{id}", Method: "GET", Source: "api-spec"}, false},
		{"POST is never probed", EndpointFact{URL: "http://x.test/api/items", Method: "POST", Source: "api-spec"}, false},
		{"html page", EndpointFact{URL: "http://x.test/home", StatusCode: 200, ContentType: "text/html"}, false},
		{"401 is not a resource", EndpointFact{URL: "http://x.test/api/items", StatusCode: 401, ContentType: "application/json"}, false},
		{"static asset", EndpointFact{URL: "http://x.test/app.js", Method: "GET", Source: "api-spec"}, false},
		{"already shaped", EndpointFact{URL: "http://x.test/api/items", StatusCode: 200, ContentType: "application/json", ResponseShape: `{}`}, false},
	} {
		assert.Equal(t, tc.want, shapeCandidate(&tc.ep), tc.name)
	}
}

// TestProbeResponseShapes drives the whole pass against a real server: shapes
// land on the right facts, only GETs are sent, an error body and a templated
// route are skipped, the operator's headers are sent, and no value is recorded.
func TestProbeResponseShapes(t *testing.T) {
	var posts atomic.Int64
	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			posts.Add(1)
		}
		if r.Header.Get("Authorization") == "Bearer tok" {
			sawAuth.Store(true)
		}
		switch r.URL.Path {
		case "/api/orders":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orders":[{"id":1,"owner_id":9,"total":10.5,"card":"4111111111111111"}]}`))
		case "/api/private":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"missing token"}`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html></html>`))
		}
	}))
	defer srv.Close()

	agg := &aggregator{target: srv.URL}
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/api/orders", Method: "GET", Source: "api-spec"})
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/api/orders", Method: "GET", StatusCode: 200, ContentType: "application/json", Source: "katana-crawl"})
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/api/private", Method: "GET", Source: "api-spec"})
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/api/orders/{id}", Method: "GET", Source: "api-spec"})
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/home", StatusCode: 200, ContentType: "text/html"})

	r := New(newTestClient(), WithHeaders(map[string]string{"Authorization": "Bearer tok"}))
	r.probeResponseShapes(context.Background(), agg, []string{srv.URL})

	byKey := map[string]EndpointFact{}
	for _, ep := range agg.endpoints {
		byKey[ep.URL+"|"+ep.Source] = ep
	}
	const want = `{"orders":[{"card":"string","id":"int","owner_id":"int","total":"number"}]}`
	assert.Equal(t, want, byKey[srv.URL+"/api/orders|api-spec"].ResponseShape)
	assert.Equal(t, want, byKey[srv.URL+"/api/orders|katana-crawl"].ResponseShape, "every fact for the same GET URL gets the shape")
	assert.Empty(t, byKey[srv.URL+"/api/private|api-spec"].ResponseShape, "a 401 body is not the resource's shape")
	assert.Empty(t, byKey[srv.URL+"/api/orders/{id}|api-spec"].ResponseShape, "a templated route has no concrete URL to fetch")
	assert.Empty(t, byKey[srv.URL+"/home|"].ResponseShape, "html is not JSON")

	assert.Zero(t, posts.Load(), "the pass is GET-only")
	assert.True(t, sawAuth.Load(), "the operator's configured headers must be sent so an authenticated run sees authenticated shapes")
	for _, ep := range agg.endpoints {
		assert.NotContains(t, ep.ResponseShape, "4111", "no response value may reach the fact")
	}
	assert.Contains(t, strings.Join(agg.warnings, " | "), "captured a response shape")
}

func TestProbeResponseShapes_HonoursTheCap(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	agg := &aggregator{target: srv.URL}
	for i := 0; i < 3*maxShapeProbes; i++ {
		agg.addEndpoint(EndpointFact{URL: fmt.Sprintf("%s/api/r%d", srv.URL, i), Method: "GET", Source: "api-spec"})
	}
	New(newTestClient()).probeResponseShapes(context.Background(), agg, []string{srv.URL})
	assert.LessOrEqual(t, int(hits.Load()), maxShapeProbes)
}

func TestProbeResponseShapes_OutOfScopeHostIsNeverProbed(t *testing.T) {
	var hits atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer other.Close()

	agg := &aggregator{target: "http://seed.invalid"}
	agg.addEndpoint(EndpointFact{URL: other.URL + "/api/x", Method: "GET", Source: "api-spec"})
	// seeds do not include the other server's host, and no scope is configured.
	New(newTestClient()).probeResponseShapes(context.Background(), agg, []string{"http://seed.invalid"})
	assert.Zero(t, hits.Load(), "a host outside the seeds and scope must not be requested")
}
