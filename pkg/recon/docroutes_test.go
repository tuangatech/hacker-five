package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The anchor format is copied from vAPI's served Redoc page (2026-09-21).
const redocAnchors = `<li><a href="#tag/API1/paths/~1vapi~1api1~1user/post">Create</a></li>` +
	`<li><a href="#tag/API1/paths/~1vapi~1api1~1user~1{api1_id}/get">Read</a></li>` +
	`<li><a href="#tag/API1/paths/~1vapi~1api1~1user~1{api1_id}/put">Update</a></li>` +
	`<li><a href="#tag/API9/paths/~1vapi~1api9~1v2~1user~1login/post">Login</a></li>` +
	`<li><a href="#tag/API1/paths/~1vapi~1api1~1user~1{api1_id}/get">duplicate</a></li>` +
	`<li><a href="#tag/API1">not a route anchor</a></li>` +
	`<li><a href="#operation/getUser">an operation id carries no path</a></li>`

func TestExtractDocAnchorRoutes(t *testing.T) {
	got := extractDocAnchorRoutes(redocAnchors)
	assert.Equal(t, []docRoute{
		{"POST", "/vapi/api1/user"},
		{"GET", "/vapi/api1/user/{api1_id}"},
		{"PUT", "/vapi/api1/user/{api1_id}"},
		{"POST", "/vapi/api9/v2/user/login"},
	}, got, "methods and ~1-escaped paths are decoded, placeholders kept, duplicates and non-route anchors dropped")
	assert.Empty(t, extractDocAnchorRoutes(`<a href="/docs">no anchors here</a>`))
}

func TestSameHostMentions(t *testing.T) {
	body := `Browse http://localhost/vapi/ for Documentation. Also http://localhost:8000/guide and ` +
		`http://LOCALHOST/Help, but not http://localhost:9999/other/, http://elsewhere.example/docs/, ` +
		`or http://localhost/ (root), http://localhost/logo.png (asset), http://localhost/vapi/ again.`
	assert.Equal(t, []string{"/Help", "/guide", "/vapi/"}, sameHostMentions(body, "localhost", "8000"),
		"same hostname with no port or the seed's own port; another host or port is another origin; sorted, deduplicated")
}

// LT-189: a page that only mentions its documentation URL in prose leads recon to the
// documentation page, whose route anchors become endpoints, without ever following an
// origin it merely mentions.
func TestRun_DocumentationPageRoutesAreDiscovered(t *testing.T) {
	var mu sync.Mutex
	got := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<p>Browse http://127.0.0.1/vapi/ for Documentation. See http://127.0.0.1:1/never/ and http://other.example/never/</p>`))
		case "/vapi/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(redocAnchors))
		case "/vapi/api1/user", "/vapi/api9/v2/user/login":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, fake := recordingRun(t, nil)
	res, err := New(newTestClient(), withRun(fake)).Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	byKey := map[string]EndpointFact{}
	for _, ep := range res.Endpoints {
		if ep.Source == "docs-anchor" {
			byKey[ep.Method+" "+strings.TrimPrefix(ep.URL, srv.URL)] = ep
		}
	}
	require.Len(t, byKey, 4)
	assert.Contains(t, byKey, "GET /vapi/api1/user/{api1_id}")
	assert.Contains(t, byKey, "POST /vapi/api9/v2/user/login")
	assert.Contains(t, strings.Join(res.Warnings, "\n"), "read 4 API route(s) from the route anchors of 1 documentation page(s)")

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, got["/never/"], "a mentioned URL on another origin is never requested")
	for path := range got {
		assert.NotContains(t, path, "{", "a templated route is never requested with its placeholder: %s", path)
	}

	// The documented, parameterless routes get a live status (the anonymous 403 is the
	// signal that they need authentication), and feed authbypass; the templated one has
	// no concrete URL to ask about, and feeds idor.
	assert.Equal(t, http.StatusForbidden, endpointStatus(res, srv.URL+"/vapi/api1/user"))
	protected, _, _ := SuggestAuthBypassPathsFromRecon(res)
	assert.Contains(t, protected, "/vapi/api1/user")
	assert.Contains(t, SuggestIDOREndpointCandidates(res), "/vapi/api1/user/{{id}}")
}

func endpointStatus(res *ReconResult, u string) int {
	for _, ep := range res.Endpoints {
		if ep.URL == u && ep.StatusCode != 0 {
			return ep.StatusCode
		}
	}
	return 0
}
