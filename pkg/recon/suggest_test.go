package recon

import "testing"

func TestSuggestIDOREndpointCandidates(t *testing.T) {
	cases := []struct {
		name string
		urls []string
		want []string
	}{
		{
			name: "single numeric-ID candidate — path-only, scheme+host stripped",
			urls: []string{"https://example.com/workshop/api/mechanic/mechanic_report?report_id=482"},
			want: []string{"/workshop/api/mechanic/mechanic_report?report_id={{id}}"},
		},
		{
			name: "single UUID candidate in the path",
			urls: []string{"https://example.com/orders/1b4e28ba-2fa1-11d2-883f-0016d3cca427"},
			want: []string{"/orders/{{id}}"},
		},
		{
			name: "multiple distinct candidates, no auto-pick",
			urls: []string{
				"https://example.com/orders/123",
				"https://example.com/invoices?invoice_id=456",
			},
			want: []string{
				"/orders/{{id}}",
				"/invoices?invoice_id={{id}}",
			},
		},
		{
			name: "duplicate templates across endpoints collapse to one",
			urls: []string{
				"https://example.com/orders/123",
				"https://example.com/orders/456",
			},
			want: []string{"/orders/{{id}}"},
		},
		{
			name: "zero candidates",
			urls: []string{"https://example.com/about", "https://example.com/contact-us"},
			want: nil,
		},
		{
			name: "same real ID-shaped path with different cosmetic query strings collapses to one — found live against a real CDN image URL",
			urls: []string{
				"https://thetavernhouse.com/pluto-images/funnel/images/eee6af0e-5695-48a1-8b52-06042ed956d9?w=96",
				"https://thetavernhouse.com/pluto-images/funnel/images/eee6af0e-5695-48a1-8b52-06042ed956d9?h=48&dpr=3&fit=cover",
				"https://thetavernhouse.com/pluto-images/funnel/images/eee6af0e-5695-48a1-8b52-06042ed956d9?w=32",
			},
			want: []string{"/pluto-images/funnel/images/{{id}}"},
		},
		{
			name: "numeric-valued but non-ID-named query keys are not candidates — the resize-param false positive found live",
			urls: []string{"https://example.com/thumb?w=96&h=48&dpr=3"},
			want: nil,
		},
		{
			name: "static-asset paths under an ID-shaped cache-slot segment are not candidates — found live against a real WordPress minify-cache plugin (2026-09-04)",
			urls: []string{
				"https://example.com/wp-content/cache/min/1/wp-content/plugins/easy-affiliate-links/dist/public.js",
				"https://example.com/wp-content/cache/min/1/analytics.js",
			},
			want: nil,
		},
		{
			name: "an ID-shaped segment inside a JavaScript string-concat fragment is still rejected (LT-85)",
			urls: []string{
				"https://example.com/library/video/42/'+D.prop(",
				"https://example.com/library/ideabox/7'+e.query.results.item[n].link+'",
			},
			want: nil,
		},
		{
			name: "numeric query param varying across crawled URLs is an ID candidate even when the key name isn't ID-shaped (LT-83)",
			urls: []string{
				"https://example.com/index.php?article=3",
				"https://example.com/index.php?article=8",
				"https://example.com/index.php?topic=1",
				"https://example.com/index.php?topic=2",
			},
			want: []string{
				"/index.php?article={{id}}",
				"/index.php?topic={{id}}",
			},
		},
		{
			name: "a lone numeric query value (single observation) is not enough for an LT-83 candidate",
			urls: []string{"https://example.com/index.php?article=8"},
			want: nil,
		},
		{
			name: "pagination/cosmetic numeric query keys are excluded from LT-83 even when they vary",
			urls: []string{
				"https://example.com/list?page=2",
				"https://example.com/list?page=3",
				"https://example.com/thumb?w=96",
				"https://example.com/thumb?w=32",
			},
			want: nil,
		},
		{
			name: "an OpenAPI-templated path param is an ID candidate without a concrete id (LT-40)",
			urls: []string{"https://example.com/api/accounts/{accountId}"},
			want: []string{"/api/accounts/{{id}}"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ReconResult{}
			for _, u := range tc.urls {
				result.Endpoints = append(result.Endpoints, EndpointFact{URL: u})
			}
			got := SuggestIDOREndpointCandidates(result)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestSuggestIDOREndpointCandidates_NilResult(t *testing.T) {
	if got := SuggestIDOREndpointCandidates(nil); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestSuggestSSRFParamsFromRecon(t *testing.T) {
	cases := []struct {
		name string
		urls []string
		want []string
	}{
		{
			name: "keyword hit",
			urls: []string{"https://example.com/fetch?url=https://internal.example/health"},
			want: []string{"url"},
		},
		{
			name: "keyword hit, case-insensitive",
			urls: []string{"https://example.com/avatar?Redirect=https://cdn.example/img.png"},
			want: []string{"Redirect"},
		},
		{
			name: "keyword miss",
			urls: []string{"https://example.com/search?q=widgets&page=2"},
			want: nil,
		},
		{
			name: "duplicate key across endpoints collapses to one",
			urls: []string{
				"https://example.com/a?webhook=https://a.example",
				"https://example.com/b?webhook=https://b.example",
			},
			want: []string{"webhook"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ReconResult{}
			for _, u := range tc.urls {
				result.Endpoints = append(result.Endpoints, EndpointFact{URL: u})
			}
			got := SuggestSSRFParamsFromRecon(result)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestSuggestSSRFParamsFromRecon_NilResult(t *testing.T) {
	if got := SuggestSSRFParamsFromRecon(nil); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestSuggestAuthBypassPathsFromRecon(t *testing.T) {
	result := &ReconResult{Endpoints: []EndpointFact{
		{URL: "https://example.com/admin/settings", StatusCode: 403},
		{URL: "https://example.com/api/private", StatusCode: 401},
		{URL: "https://example.com/login", Source: "wave1"},
		{URL: "https://example.com/auth/signin", Source: "wave3-auth-boundary-heuristic"},
		{URL: "https://example.com/logout"},
		{URL: "https://example.com/about"}, // matches nothing
		// Found live, 2026-09-03: a static JS bundle and a degenerate "/\"
		// path can both carry a real 401/403 from a katana crawl (bot
		// protection, not real per-resource access control) — neither
		// should ever be treated as a meaningful authbypass candidate.
		{URL: "https://example.com/_next/static/chunks/660-d4913fd145d4d716.js", StatusCode: 401},
		{URL: `https://example.com/\`, StatusCode: 403},
	}}

	protected, login, logout := SuggestAuthBypassPathsFromRecon(result)

	wantProtected := []string{"/admin/settings", "/api/private"}
	wantLogin := []string{"/login", "/auth/signin"}
	wantLogout := []string{"/logout"}

	assertStringSlice(t, "protected", protected, wantProtected)
	assertStringSlice(t, "login", login, wantLogin)
	assertStringSlice(t, "logout", logout, wantLogout)
}

// TestSuggestAuthBypassPathsFromRecon_SpecDeclaredAuth covers LT-90: a
// parameterless api-spec route the OpenAPI doc marks auth-required becomes a
// protected-path candidate; a {param} route does not (no id to invent), and
// a spec route the doc leaves open does not.
func TestSuggestAuthBypassPathsFromRecon_SpecDeclaredAuth(t *testing.T) {
	result := &ReconResult{Endpoints: []EndpointFact{
		{URL: "https://api.example.com/identity/api/v2/user/dashboard", Source: "api-spec", AuthRequired: true},
		{URL: "https://api.example.com/identity/api/v2/vehicle/{vehicleId}/location", Source: "api-spec", AuthRequired: true},
		{URL: "https://api.example.com/identity/api/auth/login", Source: "api-spec", AuthRequired: false},
		{URL: "https://api.example.com/community/api/v2/community/home", Source: "api-spec", AuthRequired: true},
	}}

	protected, _, _ := SuggestAuthBypassPathsFromRecon(result)

	assertStringSlice(t, "protected", protected, []string{
		"/community/api/v2/community/home",
		"/identity/api/v2/user/dashboard",
	})
}

func TestSuggestAuthBypassPathsFromRecon_NilResult(t *testing.T) {
	protected, login, logout := SuggestAuthBypassPathsFromRecon(nil)
	if protected != nil || login != nil || logout != nil {
		t.Fatalf("got (%v, %v, %v), want (nil, nil, nil)", protected, login, logout)
	}
}

func assertStringSlice(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", label, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", label, got, want)
		}
	}
}
