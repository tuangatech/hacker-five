package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRobotsDisallowsAll(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"blanket disallow", "User-agent: *\nDisallow: /\n", true},
		{"blanket disallow with comment and blank lines", "# robots\n\nUser-agent: *\n\nDisallow: /\n", true},
		{"specific path only", "User-agent: *\nDisallow: /admin/\n", false},
		{"disallow-all but for a named bot only", "User-agent: BadBot\nDisallow: /\n", false},
		{"allow all (empty disallow)", "User-agent: *\nDisallow:\n", false},
		{"no robots directives", "Sitemap: https://x.example/sitemap.xml\n", false},
		{"star group then reset to named bot", "User-agent: *\nAllow: /\n\nUser-agent: Bot\nDisallow: /\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := robotsDisallowsAll(tc.body); got != tc.want {
				t.Fatalf("robotsDisallowsAll(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

func TestRobotsHintPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/admin/", "/admin/"},
		{"/api/internal", "/api/internal"},
		{"/", ""},          // bare slash names nothing
		{"", ""},           // empty Disallow = allow-all
		{"/*.php$", ""},    // a pattern, not a resource
		{"/search?q=", ""}, // query metachar
		{"relative", ""},   // must be rooted
	}
	for _, c := range cases {
		if got := robotsHintPath(c.in); got != c.want {
			t.Errorf("robotsHintPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRunWave0_HarvestsRobotsAndSitemapHints guards LT-39 (docs/follow-up.md):
// Wave 0 turns robots.txt Disallow/Allow paths and sitemap.xml <loc> entries
// into ConfidenceLow EndpointFacts, never requesting the Disallow/Allow paths
// themselves.
func TestRunWave0_HarvestsRobotsAndSitemapHints(t *testing.T) {
	var mu struct {
		hitAdmin bool
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin/\nAllow: /public/\nDisallow: /*.json$\nSitemap: " + baseOf(r) + "/sitemap.xml\n"))
		case "/sitemap.xml":
			_, _ = w.Write([]byte(`<?xml version="1.0"?><urlset><url><loc>` + baseOf(r) + `/products/1</loc></url><url><loc>https://off-host.example/x</loc></url></urlset>`))
		case "/admin/":
			mu.hitAdmin = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	_, fake := recordingRun(t, nil)
	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthPassive)
	require.NoError(t, err)

	var robotsHint, sitemapHint bool
	for _, ep := range result.Endpoints {
		switch ep.Source {
		case "robots-txt":
			robotsHint = true
			assert.Equal(t, ConfidenceLow, ep.Confidence)
			assert.NotContains(t, ep.URL, ".json", "a wildcard/anchor pattern must not be recorded as a path")
		case "sitemap-xml":
			sitemapHint = true
			assert.NotContains(t, ep.URL, "off-host.example", "an off-host <loc> must be dropped")
		}
	}
	assert.True(t, robotsHint, "a Disallow: path must become a robots-txt EndpointFact")
	assert.True(t, sitemapHint, "a same-host <loc> must become a sitemap-xml EndpointFact")
	assert.False(t, mu.hitAdmin, "Wave 0 must never actually request a Disallow: path")
}

func baseOf(r *http.Request) string {
	return "http://" + r.Host
}
