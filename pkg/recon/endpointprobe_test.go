package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPathInterestRank(t *testing.T) {
	assert.Less(t, pathInterestRank("/oauth/authorize"), pathInterestRank("/blog/post"))
	assert.Less(t, pathInterestRank("/accounts/bounce"), pathInterestRank("/help"))
	assert.Equal(t, len(interestingPathHints), pathInterestRank("/totally/plain"))
}

// TestProbeUnprobedEndpoints guards LT-76 (Phase 8 Step 5): the bounded,
// name-ranked pass gives a live status to the most interesting robots/
// sitemap paths that had none, skips static assets, honours the cap, and
// leaves already-probed / crawl-sourced facts alone.
func TestProbeUnprobedEndpoints(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch {
		case strings.Contains(r.URL.Path, "bounce"):
			http.Redirect(w, r, "/account", http.StatusFound)
		case strings.Contains(r.URL.Path, "oauth"):
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	agg := &aggregator{target: srv.URL}
	// Interesting, unprobed, from sitemap/robots — should be probed.
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/oauth/authorize", Source: "sitemap-xml", Confidence: ConfidenceLow})
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/accounts/bounce", Source: "robots-txt", Confidence: ConfidenceLow})
	// Static asset — must be skipped even though it's unprobed.
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/assets/app.js", Source: "sitemap-xml", Confidence: ConfidenceLow})
	// Already has a status — must be left alone.
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/known", Source: "sitemap-xml", StatusCode: 200, Confidence: ConfidenceLow})
	// From the crawl, not robots/sitemap — not in scope for this pass.
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/crawled/oauth", Source: "katana-crawl", Confidence: ConfidenceMedium})
	// A pile of low-interest unprobed paths to exercise the cap.
	for i := 0; i < 40; i++ {
		agg.addEndpoint(EndpointFact{URL: fmt.Sprintf("%s/page/%d", srv.URL, i), Source: "sitemap-xml", Confidence: ConfidenceLow})
	}

	r := New(newTestClient())
	r.probeUnprobedEndpoints(context.Background(), agg, []string{srv.URL})

	byURL := map[string]EndpointFact{}
	for _, ep := range agg.endpoints {
		byURL[ep.URL] = ep
	}
	assert.Equal(t, http.StatusUnauthorized, byURL[srv.URL+"/oauth/authorize"].StatusCode, "the OAuth path must be probed and its 401 recorded")
	assert.Equal(t, ConfidenceMedium, byURL[srv.URL+"/oauth/authorize"].Confidence)
	assert.Equal(t, http.StatusFound, byURL[srv.URL+"/accounts/bounce"].StatusCode, "the first-hop 302 must be kept, not the followed 200")
	assert.NotEmpty(t, byURL[srv.URL+"/accounts/bounce"].FinalURL)
	assert.Zero(t, byURL[srv.URL+"/assets/app.js"].StatusCode, "a static asset must not be probed")
	assert.Zero(t, byURL[srv.URL+"/crawled/oauth"].StatusCode, "a katana-crawl fact is out of scope for the LT-76 pass")
	assert.LessOrEqual(t, hits, maxUnprobedEndpointProbes, "the probe count must respect the cap")

	joined := strings.Join(agg.warnings, " | ")
	assert.Contains(t, joined, "LT-76")
}

// TestProbeUnprobedEndpoints_OutOfScopeHostSkipped: without a --scope, only
// seed hosts are probed; a non-seed host in agg is left alone.
func TestProbeUnprobedEndpoints_OutOfScopeHostSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()

	agg := &aggregator{target: srv.URL}
	agg.addEndpoint(EndpointFact{URL: "https://other-host.example/oauth/authorize", Source: "sitemap-xml", Confidence: ConfidenceLow})

	r := New(newTestClient())
	r.probeUnprobedEndpoints(context.Background(), agg, []string{srv.URL})

	require.Len(t, agg.endpoints, 1)
	assert.Zero(t, agg.endpoints[0].StatusCode, "a non-seed host with no --scope allowance must not be probed")
}

// TestProbeTemplatedRouteAuthBoundary guards LT-191: a {param}-shaped
// js-static/js-static-joined route (never requested by anything, since
// probeUnprobedEndpoints itself skips any URL containing "{") gets one
// bounded, anonymous, concrete-substituted probe; a 401/403 response
// becomes a new EndpointFact carrying that status — the signal
// SuggestAuthBypassPathsFromRecon already looks for — while the original
// {param} fact (idor's own candidate) is left untouched.
func TestProbeTemplatedRouteAuthBoundary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/rest/basket/"):
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasPrefix(r.URL.Path, "/rest/public/"):
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	agg := &aggregator{target: srv.URL}
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/rest/basket/{param}", Source: "js-static", Confidence: ConfidenceLow})
	// A public {param} route — must be probed too, but yields no new fact.
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/rest/public/{param}", Source: "js-static", Confidence: ConfidenceLow})
	// Wrong source — idor's own leaf, out of scope for this pass.
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/rest/other/{param}", Source: "katana-crawl", Confidence: ConfidenceMedium})
	// Already has a status — left alone regardless of source.
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/rest/known/{param}", Source: "js-static", StatusCode: 200, Confidence: ConfidenceLow})

	r := New(newTestClient())
	r.probeTemplatedRouteAuthBoundary(context.Background(), agg, []string{srv.URL})

	var newFacts []EndpointFact
	for _, ep := range agg.endpoints {
		if ep.Source == "js-static-authcheck" {
			newFacts = append(newFacts, ep)
		}
	}
	require.Len(t, newFacts, 1, "only the genuinely gated route should produce a new fact")
	assert.Equal(t, srv.URL+"/rest/basket/1", newFacts[0].URL)
	assert.Equal(t, http.StatusUnauthorized, newFacts[0].StatusCode)

	// The original {param} fact must be untouched — idor's own candidate
	// list reads directly from it.
	for _, ep := range agg.endpoints {
		if ep.URL == srv.URL+"/rest/basket/{param}" {
			assert.Zero(t, ep.StatusCode, "the original template fact must not be mutated")
		}
	}

	joined := strings.Join(agg.warnings, " | ")
	assert.Contains(t, joined, "LT-191")
}

// TestProbeTemplatedRouteAuthBoundary_MultiParamPathSkipped: a route with
// more than one {...} segment is ambiguous to substitute a single concrete
// value into, so it's left alone rather than guessed at.
func TestProbeTemplatedRouteAuthBoundary_MultiParamPathSkipped(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	agg := &aggregator{target: srv.URL}
	agg.addEndpoint(EndpointFact{URL: srv.URL + "/a/{x}/b/{y}", Source: "js-static", Confidence: ConfidenceLow})

	r := New(newTestClient())
	r.probeTemplatedRouteAuthBoundary(context.Background(), agg, []string{srv.URL})

	assert.False(t, hit, "a multi-param route must never be probed")
	assert.Len(t, agg.endpoints, 1, "no new fact should be added")
}
