package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// paramMineServer models a handler whose behaviour per path is what LT-100's
// diff oracle has to tell apart. Every response starts from a fixed filler so
// a length shift is measurable.
func paramMineServer(t *testing.T, hits *int64) *httptest.Server {
	t.Helper()
	const filler = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt64(hits, 1)
		}
		q := r.URL.Query()
		body := filler
		switch r.URL.Path {
		case "/honest":
			// Honours ?debug= : reflects its value and returns a longer body.
			if v := q.Get("debug"); v != "" {
				body = filler + filler + " debugvalue=" + v
			}
		case "/ssrfish":
			if v := q.Get("url"); v != "" {
				body = filler + filler + " fetched=" + v
			}
		case "/idish":
			if v := q.Get("uid"); v != "" {
				body = filler + filler + " row=" + v
			}
		case "/lengthonly":
			// Any extra param shifts the length but nothing is reflected.
			if len(q) > 0 {
				body = filler + filler + filler
			}
		case "/reflectall":
			// Echoes every value it is given — a classic reflect-all sink.
			var b strings.Builder
			b.WriteString(filler)
			for _, vs := range q {
				for _, v := range vs {
					b.WriteString(" " + v)
				}
			}
			body = b.String()
		case "/ignore":
			// Constant regardless of input.
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func minedParams(t *testing.T, r *Recon, srv *httptest.Server, paths ...string) []EndpointFact {
	t.Helper()
	agg := &aggregator{target: srv.URL}
	for _, p := range paths {
		agg.endpoints = append(agg.endpoints, EndpointFact{URL: srv.URL + p, Method: http.MethodGet, StatusCode: 200, Source: "katana-crawl"})
	}
	before := len(agg.endpoints)
	r.runParamMining(context.Background(), agg, []string{srv.URL})
	return agg.endpoints[before:]
}

func newParamMineRecon(t *testing.T, opts ...Option) *Recon {
	t.Helper()
	base := []Option{WithParamMining(true)}
	return New(newTestClient(), append(base, opts...)...)
}

// TestParamMining_CorroboratedParamEmitted: a param the app reflects *and*
// that shifts the body length is emitted exactly once, as a
// wave3-param-mining EndpointFact carrying the discovered key.
func TestParamMining_CorroboratedParamEmitted(t *testing.T) {
	srv := paramMineServer(t, nil)
	got := minedParams(t, newParamMineRecon(t), srv, "/honest")

	var keys []string
	for _, ep := range got {
		assert.Equal(t, "wave3-param-mining", ep.Source)
		u := ep.URL
		assert.True(t, strings.HasPrefix(u, srv.URL+"/honest?"), "fact URL keeps the mined endpoint path: %s", u)
		keys = append(keys, u[strings.Index(u, "?")+1:])
	}
	assert.Equal(t, []string{"debug="}, keys, "exactly the honoured param, once, value-less")
}

// TestParamMining_NoSignalYieldsNothing: an endpoint that ignores unknown
// params, and one that only shifts length without reflecting, both emit
// nothing (a lone weak signal is not enough).
func TestParamMining_NoSignalYieldsNothing(t *testing.T) {
	srv := paramMineServer(t, nil)

	assert.Empty(t, minedParams(t, newParamMineRecon(t), srv, "/ignore"),
		"an endpoint that ignores every param yields no discovery")
	assert.Empty(t, minedParams(t, newParamMineRecon(t), srv, "/lengthonly"),
		"a length shift with no reflection is a single weak signal — dropped")
}

// TestParamMining_ReflectAllSinkSuppressed: an endpoint that echoes every
// value it is handed is recognised as a reflect-all sink and contributes no
// discoveries, with a warning.
func TestParamMining_ReflectAllSinkSuppressed(t *testing.T) {
	srv := paramMineServer(t, nil)
	agg := &aggregator{target: srv.URL}
	agg.endpoints = append(agg.endpoints, EndpointFact{URL: srv.URL + "/reflectall", Method: http.MethodGet, StatusCode: 200, Source: "katana-crawl"})
	newParamMineRecon(t).runParamMining(context.Background(), agg, []string{srv.URL})

	for _, ep := range agg.endpoints {
		assert.NotEqual(t, "wave3-param-mining", ep.Source, "a reflect-all sink must not produce discoveries")
	}
	var sawWarning bool
	for _, w := range agg.warnings {
		if strings.Contains(w, "reflect-all") {
			sawWarning = true
		}
	}
	assert.True(t, sawWarning, "the reflect-all sink must leave a visible warning")
}

// TestParamMining_RequestCapHonoured: the pass stops once the per-host cap is
// spent, even with more endpoints and a full wordlist left to probe.
func TestParamMining_RequestCapHonoured(t *testing.T) {
	var hits int64
	srv := paramMineServer(t, &hits)
	r := newParamMineRecon(t, WithParamMiningRequestCap(8))
	minedParams(t, r, srv, "/honest", "/ssrfish", "/idish", "/ignore")

	assert.LessOrEqual(t, atomic.LoadInt64(&hits), int64(8), "the pass must not exceed --param-mining-request-cap")
	assert.Positive(t, atomic.LoadInt64(&hits), "the pass must actually issue requests")
}

// TestParamMining_FeedsSSRFAndIDORSuggesters: a discovered url-ish param
// reaches SuggestSSRFParamsFromRecon; a discovered id-ish param reaches
// SuggestIDOREndpointCandidates as an {{id}} template.
func TestParamMining_FeedsSSRFAndIDORSuggesters(t *testing.T) {
	srv := paramMineServer(t, nil)
	agg := &aggregator{target: srv.URL}
	for _, p := range []string{"/ssrfish", "/idish"} {
		agg.endpoints = append(agg.endpoints, EndpointFact{URL: srv.URL + p, Method: http.MethodGet, StatusCode: 200, Source: "katana-crawl"})
	}
	newParamMineRecon(t).runParamMining(context.Background(), agg, []string{srv.URL})

	result := &ReconResult{Endpoints: agg.endpoints}

	ssrf := SuggestSSRFParamsFromRecon(result)
	assert.Contains(t, ssrf, "url", "a mined url= param must reach the SSRF param suggester")

	idor := SuggestIDOREndpointCandidates(result)
	var sawUID bool
	for _, c := range idor {
		if c == "/idish?uid={{id}}" {
			sawUID = true
		}
	}
	assert.True(t, sawUID, "a mined uid= param must reach the IDOR candidate suggester as /idish?uid={{id}}; got %v", idor)
}

// TestParamMining_OffByDefault: without WithParamMining the pass is a no-op.
func TestParamMining_OffByDefault(t *testing.T) {
	srv := paramMineServer(t, nil)
	agg := &aggregator{target: srv.URL}
	agg.endpoints = append(agg.endpoints, EndpointFact{URL: srv.URL + "/honest", Method: http.MethodGet, StatusCode: 200, Source: "katana-crawl"})
	New(newTestClient()).runParamMining(context.Background(), agg, []string{srv.URL})

	assert.Len(t, agg.endpoints, 1, "param mining must do nothing unless --param-mining is set")
	assert.Empty(t, agg.warnings)
}

// TestParamCandidateNames_WordlistOverride: --param-mining-wordlist replaces
// the built-in list; malformed lines and comments are dropped.
func TestParamCandidateNames_WordlistOverride(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/w.txt"
	require.NoError(t, os.WriteFile(path, []byte("# a comment\nfoo\nbar\n\nnot a name\nfoo\nbaz2\n"), 0o644))

	r := New(newTestClient(), WithParamMiningWordlist(path))
	names, provenance, err := r.paramCandidateNames()
	require.NoError(t, err)
	assert.Equal(t, []string{"foo", "bar", "baz2"}, names, "comments, blanks, dupes and malformed lines dropped")
	assert.Contains(t, provenance, "w.txt")
}
