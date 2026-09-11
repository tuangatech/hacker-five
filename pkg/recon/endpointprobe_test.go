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
