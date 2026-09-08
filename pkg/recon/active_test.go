package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeRedirect(t *testing.T) {
	t.Run("no final_url is not a redirect", func(t *testing.T) {
		cross, chain, status := analyzeRedirect("", "a.example", nil, nil, 200)
		assert.False(t, cross)
		assert.Nil(t, chain)
		assert.Equal(t, 200, status)
	})
	t.Run("same-host final_url is not cross-host", func(t *testing.T) {
		cross, _, status := analyzeRedirect("https://a.example/en/", "a.example", nil, []int{301, 200}, 200)
		assert.False(t, cross)
		assert.Equal(t, 200, status)
	})
	t.Run("www. vs bare is not cross-host", func(t *testing.T) {
		cross, _, _ := analyzeRedirect("https://www.a.example/", "a.example", nil, []int{301, 200}, 200)
		assert.False(t, cross)
	})
	t.Run("cross-host with full chain keeps the first-hop status", func(t *testing.T) {
		chain := []httpxChainHop{
			{RequestURL: "https://linkpop.example", StatusCode: 301},
			{RequestURL: "https://www.shopify.example/", StatusCode: 200},
		}
		cross, lines, status := analyzeRedirect("https://www.shopify.example/", "linkpop.example", chain, []int{301, 200}, 200)
		assert.True(t, cross)
		assert.Equal(t, 301, status)
		require.Len(t, lines, 2)
		assert.Equal(t, "301 https://linkpop.example", lines[0])
	})
	t.Run("cross-host with only chain_status_codes synthesises a chain", func(t *testing.T) {
		cross, lines, status := analyzeRedirect("https://www.shopify.example/", "linkpop.example", nil, []int{302, 200}, 200)
		assert.True(t, cross)
		assert.Equal(t, 302, status)
		require.Len(t, lines, 2)
	})
}

func TestHeadersCorroborateCDN(t *testing.T) {
	cf := cdnHeaderTokens["cloudflare"]
	assert.True(t, headersCorroborateCDN(map[string]string{"CF-Ray": "abc123-LHR"}, cf))
	assert.True(t, headersCorroborateCDN(map[string]string{"Server": "cloudflare"}, cf))
	assert.False(t, headersCorroborateCDN(map[string]string{"Server": "nginx"}, cf))
	assert.False(t, headersCorroborateCDN(nil, cf))
}

// TestRunHTTPX_CrossHostRedirect_NotAttributed guards LT-64/LT-65: a root
// that redirects to a different host must not lend that host's 200, title
// or tech to the recon target — the linkpop.com → www.shopify.com case.
func TestRunHTTPX_CrossHostRedirect_NotAttributed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	host := hostOnly(srv.URL)

	fake := func(_ context.Context, _ string, name string, _ ...string) ([]byte, error) {
		if name == "httpx" {
			return []byte(`{"url":"` + srv.URL + `","host":"` + host + `","host_ip":"` + host + `",` +
				`"status_code":200,"title":"Shopify: The All-in-One Commerce Platform","tech":["Shopify","Ruby on Rails"],` +
				`"final_url":"https://www.shopify.example/","chain_status_codes":[301,200]}`), nil
		}
		return nil, nil
	}

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthActive)
	require.NoError(t, err)

	var ep *EndpointFact
	for i := range result.Endpoints {
		if result.Endpoints[i].Source == "httpx" {
			ep = &result.Endpoints[i]
		}
	}
	require.NotNil(t, ep)
	assert.Equal(t, 301, ep.StatusCode, "status must be the first-hop 3xx, not the destination's 200")
	assert.Equal(t, "https://www.shopify.example/", ep.FinalURL)
	assert.NotEmpty(t, ep.RedirectChain)
	assert.Empty(t, ep.Title, "the destination's title must not be attributed to the target")

	for _, tf := range result.TechStack {
		assert.NotContains(t, strings.ToLower(tf.Name), "shopify", "a tech fact from the redirect destination must not seed the target's plan")
		assert.NotContains(t, strings.ToLower(tf.Name), "rails")
	}
	assert.Contains(t, strings.Join(result.Warnings, " | "), "redirects across hosts")
}

// TestRunHTTPX_SpuriousCDNTechWithoutHeader guards LT-84b: an httpx
// -tech-detect CDN brand with no corroborating edge header on the host's
// own response is dropped; one that IS backed by a header is kept.
func TestRunHTTPX_SpuriousCDNTechWithoutHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	host := hostOnly(srv.URL)

	run := func(techJSON, headerJSON string) *ReconResult {
		fake := func(_ context.Context, _ string, name string, _ ...string) ([]byte, error) {
			if name == "httpx" {
				return []byte(`{"url":"` + srv.URL + `","host":"` + host + `","host_ip":"` + host + `","status_code":200,` +
					`"tech":` + techJSON + `,"header":` + headerJSON + `}`), nil
			}
			return nil, nil
		}
		r := New(newTestClient(), withRun(fake))
		res, err := r.Run(context.Background(), srv.URL, DepthActive)
		require.NoError(t, err)
		return res
	}

	hasTech := func(res *ReconResult, name string) bool {
		for _, tf := range res.TechStack {
			if strings.EqualFold(tf.Name, name) {
				return true
			}
		}
		return false
	}

	spurious := run(`["Cloudflare","Nginx"]`, `{"server":"nginx"}`)
	assert.False(t, hasTech(spurious, "Cloudflare"), "Cloudflare with no cf-* header must be dropped (LT-84b)")
	assert.True(t, hasTech(spurious, "Nginx"), "a non-CDN tech is unaffected")
	assert.Contains(t, strings.Join(spurious.Warnings, " | "), "LT-84b")

	backed := run(`["Cloudflare"]`, `{"server":"cloudflare","cf-ray":"abc-LHR"}`)
	assert.True(t, hasTech(backed, "Cloudflare"), "Cloudflare backed by a real edge header is kept")
}
