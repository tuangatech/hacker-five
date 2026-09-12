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
		{
			name: "a *.js.php asset wrapper with an ID-shaped segment and no query is not an IDOR candidate (LT-117)",
			urls: []string{"https://example.com/includes/42/lib_head.js.php"},
			want: nil,
		},
		{
			name: "a dependency-tree file with an ID-shaped segment and no query is not an IDOR candidate (LT-117)",
			urls: []string{"https://example.com/node_modules/select2/42/index.min"},
			want: nil,
		},
		{
			name: "a *.js.php path that still carries a real id query param IS a candidate — the LT-117 guard is inert-GET-no-query only",
			urls: []string{"https://example.com/includes/lib_head.js.php?id=5"},
			want: []string{"/includes/lib_head.js.php?id={{id}}"},
		},
		{
			name: "a spec-documented but valueless ID-shaped query param IS a candidate — the walker's own keyless encoding (LT-95)",
			urls: []string{"https://example.com/workshop/api/mechanic/mechanic_report?report_id="},
			want: []string{"/workshop/api/mechanic/mechanic_report?report_id={{id}}"},
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

// TestSuggestIDORSeedIDs covers LT-95 (docs/follow-up.md): a UUID-shaped
// candidate's real, concrete observed value is surfaced as a seed keyed by
// its {{id}}-templated string; an int-shaped or spec-templated ("{id}")
// candidate has no seed, since SequentialIntStrategy already brute-forces
// the int case and a bare spec placeholder carries no real value.
func TestSuggestIDORSeedIDs(t *testing.T) {
	result := &ReconResult{Endpoints: []EndpointFact{
		{URL: "https://example.com/vehicle/1b4e28ba-2fa1-11d2-883f-0016d3cca427/location"},
		{URL: "https://example.com/orders/123"},
		{URL: "https://example.com/api/accounts/{accountId}"},
	}}

	seeds := SuggestIDORSeedIDs(result)
	if got := seeds["/vehicle/{{id}}/location"]; got != "1b4e28ba-2fa1-11d2-883f-0016d3cca427" {
		t.Fatalf("got seed %q, want the observed UUID", got)
	}
	if _, ok := seeds["/orders/{{id}}"]; ok {
		t.Fatalf("an int-shaped candidate must not get a seed")
	}
	if _, ok := seeds["/api/accounts/{{id}}"]; ok {
		t.Fatalf("a bare spec-templated {accountId} candidate must not get a seed")
	}
}

func TestSuggestIDORSeedIDs_NilResult(t *testing.T) {
	if got := SuggestIDORSeedIDs(nil); got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

// TestSuggestSQLiTargets covers doc18 Step 4's two signals: an ID-named
// query key with an ID-shaped value (single observation), and LT-83's
// unnamed-numeric-key signal (>= 2 distinct observed values on the same
// path).
func TestSuggestSQLiTargets(t *testing.T) {
	cases := []struct {
		name       string
		urls       []string
		wantPath   string
		wantParams []string
	}{
		{
			name:       "ID-named key, single observation is enough",
			urls:       []string{"https://example.com/product?product_id=482&ref=email"},
			wantPath:   "/product?product_id=482&ref=email",
			wantParams: []string{"product_id"},
		},
		{
			name: "unnamed numeric key needs >= 2 distinct values",
			urls: []string{
				"https://example.com/article?article=3",
				"https://example.com/article?article=7",
			},
			wantPath:   "/article?article=3",
			wantParams: []string{"article"},
		},
		{
			name:       "unnamed numeric key, single observation is NOT enough",
			urls:       []string{"https://example.com/article?article=3"},
			wantPath:   "",
			wantParams: nil,
		},
		{
			name:       "pagination-shaped key excluded even with an ID-shaped name check bypassed",
			urls:       []string{"https://example.com/list?page=1", "https://example.com/list?page=2"},
			wantPath:   "",
			wantParams: nil,
		},
		{
			name:       "static asset path excluded",
			urls:       []string{"https://example.com/app.js?id=1"},
			wantPath:   "",
			wantParams: nil,
		},
		{
			name:       "ID-named key, non-ID-shaped value excluded",
			urls:       []string{"https://example.com/search?user_id=not-an-id"},
			wantPath:   "",
			wantParams: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ReconResult{}
			for _, u := range tc.urls {
				result.Endpoints = append(result.Endpoints, EndpointFact{URL: u})
			}
			got := SuggestSQLiTargets(result)
			if tc.wantPath == "" {
				if len(got) != 0 {
					t.Fatalf("got %+v, want no targets", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %+v, want exactly 1 target", got)
			}
			if got[0].Path != tc.wantPath {
				t.Fatalf("got Path %q, want %q", got[0].Path, tc.wantPath)
			}
			if len(got[0].Params) != len(tc.wantParams) {
				t.Fatalf("got params %v, want %v", got[0].Params, tc.wantParams)
			}
			for i := range got[0].Params {
				if got[0].Params[i] != tc.wantParams[i] {
					t.Fatalf("got params %v, want %v", got[0].Params, tc.wantParams)
				}
			}
		})
	}
}

// TestSuggestSQLiTargets_GroupsMultipleParamsOnSamePath confirms two
// distinct candidate params on the same path fold into one Target rather
// than two.
func TestSuggestSQLiTargets_GroupsMultipleParamsOnSamePath(t *testing.T) {
	result := &ReconResult{Endpoints: []EndpointFact{
		{URL: "https://example.com/order?order_id=100&user_id=5"},
	}}
	got := SuggestSQLiTargets(result)
	if len(got) != 1 {
		t.Fatalf("got %+v, want exactly 1 target", got)
	}
	if got[0].Path != "/order?order_id=100&user_id=5" {
		t.Fatalf("got Path %q, want /order?order_id=100&user_id=5", got[0].Path)
	}
	want := []string{"order_id", "user_id"}
	if len(got[0].Params) != len(want) {
		t.Fatalf("got params %v, want %v", got[0].Params, want)
	}
	for i := range want {
		if got[0].Params[i] != want[i] {
			t.Fatalf("got params %v, want %v", got[0].Params, want)
		}
	}
}

func TestSuggestSQLiTargets_NilResult(t *testing.T) {
	if got := SuggestSQLiTargets(nil); got != nil {
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

// TestSuggestSSRFBodyParamsFromRecon covers LT-96: unlike
// SuggestSSRFParamsFromRecon's exact-key match, this matches by substring —
// a real body field name is typically compound ("mechanic_api",
// "repair_url") rather than a bare "url"/"redirect".
func TestSuggestSSRFBodyParamsFromRecon(t *testing.T) {
	cases := []struct {
		name     string
		bodyKeys [][]string
		want     []string
	}{
		{
			name:     "compound keyword hit",
			bodyKeys: [][]string{{"repair_url", "vehicle_id"}},
			want:     []string{"repair_url"},
		},
		{
			name:     "compound keyword hit, case-insensitive",
			bodyKeys: [][]string{{"Repair_Url"}},
			want:     []string{"Repair_Url"},
		},
		{
			name:     "keyword miss",
			bodyKeys: [][]string{{"quantity", "notes"}},
			want:     nil,
		},
		{
			name:     "duplicate key across endpoints collapses to one",
			bodyKeys: [][]string{{"webhook_endpoint"}, {"webhook_endpoint"}},
			want:     []string{"webhook_endpoint"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ReconResult{}
			for _, keys := range tc.bodyKeys {
				result.Endpoints = append(result.Endpoints, EndpointFact{URL: "https://example.com/x", BodyParamKeys: keys})
			}
			got := SuggestSSRFBodyParamsFromRecon(result)
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

func TestSuggestSSRFBodyParamsFromRecon_NilResult(t *testing.T) {
	if got := SuggestSSRFBodyParamsFromRecon(nil); got != nil {
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
		// LT-117: a *.js.php asset wrapper and a node_modules tree file
		// carrying a katana-crawl 401/403 are the same class of noise —
		// derivedAssetPath must keep them out of the protected set.
		{URL: "https://example.com/htdocs/theme/eldy/style.css.php", StatusCode: 403},
		{URL: "https://example.com/node_modules/jquery/dist/jquery.min", StatusCode: 401},
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
// TestSuggestAuthBypassPathsFromRecon_RedirectToLoginBoundary is LT-125's
// regression: a redirect-to-login path (WordPress /wp-admin/ -> wp-login.php
// is the live-observed shape) must be bucketed as protected even though it
// never itself returned 401/403 — recon only ever saw the redirect. A 3xx
// whose target has nothing login-shaped about it (a plain cross-host
// redirect) and a 3xx with no observed destination at all must not be
// swept in.
func TestSuggestAuthBypassPathsFromRecon_RedirectToLoginBoundary(t *testing.T) {
	result := &ReconResult{Endpoints: []EndpointFact{
		{URL: "https://example.com/wp-admin/", StatusCode: 302, FinalURL: "https://example.com/wp-login.php?redirect_to=%2Fwp-admin%2F"},
		{URL: "https://example.com/account/", StatusCode: 301, RedirectChain: []string{"301 https://example.com/account/", "https://example.com/signin"}},
		{URL: "https://example.com/old-blog", StatusCode: 301, FinalURL: "https://example.com/blog"},
		{URL: "https://example.com/no-destination-observed", StatusCode: 302},
	}}

	protected, _, _ := SuggestAuthBypassPathsFromRecon(result)

	assertStringSlice(t, "protected", protected, []string{"/wp-admin/", "/account/"})
}

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

func TestIsNonRouteAssetPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// plain static-asset extensions — already covered by IsStaticAssetPath
		{"/assets/app.js", true},
		{"/css/site.css", true},
		{"/logo.svg", true},
		// LT-117: server-script wrappers over a static asset
		{"/htdocs/core/js/lib_head.js.php", true},
		{"/theme/eldy/style.css.php", true},
		{"/scripts/bundle.js.aspx", true},
		// LT-117: dependency-manager / build-output subtrees
		{"/wp-content/themes/x/node_modules/select2/select2.full", true},
		{"/bower_components/jquery/jquery", true},
		{"/static/dist/js/app.min", true},
		{"/static/dist/css/app.min", true},
		// real application routes — must NOT be flagged
		{"/", false},
		{"/admin", false},
		{"/api/v2/users", false},
		{"/report.php", false},         // a bare .php route, no inner asset ext
		{"/index.php", false},          // ditto
		{"/download.aspx", false},      // ditto
		{"/dist/report", false},        // "/dist/" alone is not enough — needs /dist/js|css/
		{"/products/dist-belt", false}, // substring "dist" but not the "/dist/js/" segment
	}
	for _, tc := range cases {
		if got := IsNonRouteAssetPath(tc.path); got != tc.want {
			t.Errorf("IsNonRouteAssetPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
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
