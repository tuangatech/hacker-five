package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// --- extractJSEndpoints -----------------------------------------------

func TestExtractJSEndpoints_PlantedRouteFound(t *testing.T) {
	body := `fetch("/api/v2/internal/reports")`
	got := extractJSEndpoints("https://target.example/static/app.js", body)
	assert.Contains(t, got, "https://target.example/api/v2/internal/reports")
}

func TestExtractJSEndpoints_AbsoluteURLFound(t *testing.T) {
	body := `const u = "https://target.example/api/v2/admin/users";`
	got := extractJSEndpoints("https://target.example/static/app.js", body)
	assert.Contains(t, got, "https://target.example/api/v2/admin/users")
}

// TestExtractJSEndpoints_DecoysRejected guards the false-positive side of
// LT-85/IsNonRouteAssetPath reuse: none of these common minified-JS quoted
// strings should ever become an endpoint candidate.
func TestExtractJSEndpoints_DecoysRejected(t *testing.T) {
	decoys := []string{
		`"/"`,                          // bare root, not interesting
		`"//"`,                         // protocol-relative junk
		`"/static/logo.png"`,           // static asset
		`"/node_modules/foo/index.js"`, // dependency tree
		`"/library/ideabox/'+e.query"`, // LT-85 JS-syntax fragment
		`"application/json"`,           // MIME type, not a path
		`'MM/DD/YYYY'`,                 // date-format string, no leading slash
	}
	for _, d := range decoys {
		got := extractJSEndpoints("https://target.example/static/app.js", d)
		assert.Empty(t, got, "decoy %q must not be extracted as an endpoint", d)
	}
}

func TestExtractJSEndpoints_DedupedWithinOneAsset(t *testing.T) {
	body := `a("/api/foo"); b("/api/foo");`
	got := extractJSEndpoints("https://target.example/app.js", body)
	assert.Len(t, got, 1)
}

// --- backtick template literals (LT-190) --------------------------------

// TestExtractJSEndpoints_BacktickTemplateLiteral_JuiceShopShape is the real
// live-observed Juice Shop bundle shape (2026-09-22): its Angular services
// build every REST call as a template literal, a host-variable
// interpolation immediately followed by the real path, with an id segment
// interpolated at the end. Before jsQuotedStringRe captured backtick
// strings at all, none of this was even visible to extraction.
func TestExtractJSEndpoints_BacktickTemplateLiteral_JuiceShopShape(t *testing.T) {
	body := "basketService.get=e=>this.http.get(`${this.hostServer}/rest/basket/${e}`)," +
		"basketService.checkout=(e,i)=>this.http.post(`${this.hostServer}/rest/basket/${e}/checkout`,i)"
	got := extractJSEndpoints("https://target.example/main.js", body)
	assert.Contains(t, got, "https://target.example/rest/basket/{param}")
	assert.Contains(t, got, "https://target.example/rest/basket/{param}/checkout")
}

// TestExtractJSEndpoints_PlainBacktickLiteral_Found covers the other real
// shape in the same bundle: a backtick string with no interpolation at all
// (`/rest/products`) — found exactly like a double-quoted one would be.
func TestExtractJSEndpoints_PlainBacktickLiteral_Found(t *testing.T) {
	body := "const P=`/rest/products`;"
	got := extractJSEndpoints("https://target.example/main.js", body)
	assert.Contains(t, got, "https://target.example/rest/products")
}

// TestExtractJSEndpoints_BacktickEmbeddedInterpolation_Rejected guards the
// false-positive side: an interpolation that only fills *part* of a segment
// can't be normalized with confidence (what "${x}" contains isn't known),
// so the literal is dropped rather than emitted with the raw "${x}" text
// still in it or guessed at.
func TestExtractJSEndpoints_BacktickEmbeddedInterpolation_Rejected(t *testing.T) {
	body := "u(`/rest/product-${id}-detail`)"
	got := extractJSEndpoints("https://target.example/main.js", body)
	assert.Empty(t, got, "an interpolation embedded inside a segment must not be guessed at")
}

func TestNormalizeJSTemplateLiteral(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{name: "no interpolation", in: "/rest/products", want: "/rest/products", wantOK: true},
		{name: "leading host variable stripped", in: "${this.hostServer}/rest/basket/${e}", want: "/rest/basket/{param}", wantOK: true},
		{name: "two trailing placeholders", in: "${this.hostServer}/rest/basket/${e}/coupon/${i}", want: "/rest/basket/{param}/coupon/{param}", wantOK: true},
		{name: "query value interpolated", in: "${this.hostServer}/rest/products/search?q=${e}", want: "/rest/products/search?q={param}", wantOK: true},
		{name: "embedded, not whole-segment", in: "/rest/product-${id}-detail", want: "", wantOK: false},
		{name: "query value embedded, not whole", in: "/rest/products/search?q=x-${e}", want: "", wantOK: false},
		{name: "query pair with no equals", in: "/rest/products/search?${e}", want: "", wantOK: false},
		{name: "nested braces rejected", in: "/rest/${a[`${b}`]}", want: "", wantOK: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := normalizeJSTemplateLiteral(c.in)
			assert.Equal(t, c.wantOK, ok)
			if c.wantOK {
				assert.Equal(t, c.want, got)
			}
		})
	}
}

// TestCollectJSPathJoinParts_BacktickBaseWithPlaceholder: the join-parts
// pipeline (LT-164/LT-186) gets the same backtick+placeholder handling as
// the direct endpoint pipeline, for a bundle that declares its bare
// "api/..." route constants as template literals instead of plain strings.
func TestCollectJSPathJoinParts_BacktickBaseWithPlaceholder(t *testing.T) {
	body := "ig=`workshop/`,sg={A:`api/shop/orders/${orderId}`}"
	_, bases, _ := collectJSPathJoinParts(body)
	assert.Contains(t, bases, "api/shop/orders/{param}")
}

// TestExtractJSEndpoints_QuerySuffixTemplateLiteral is Juice Shop's actual
// live-verified SQLi endpoint's real declared shape: a query value
// interpolated directly into the same template literal as the path, not a
// separately-declared "?key=" constant the way collectJSPathJoinParts'
// isJSQuerySuffixCandidate bucket already handles for crAPI-style bundles.
func TestExtractJSEndpoints_QuerySuffixTemplateLiteral(t *testing.T) {
	body := "search=e=>this.http.get(`${this.hostServer}/rest/products/search?q=${e}`)"
	got := extractJSEndpoints("https://target.example/main.js", body)
	assert.Contains(t, got, "https://target.example/rest/products/search?q={param}")
}

// TestExtractBacktickLiterals_NestedTemplateLiteralDoesNotDesyncLaterOnes is
// the real bug LT-190's first attempt (a flat regex "backtick" alternative
// on jsQuotedStringRe) had, live-verified against Juice Shop's actual
// main.js: a template literal nested inside another one's own "${...}"
// (Angular Material's internal CSS-in-JS calc() logic, three deep in the
// real bundle) desynchronized every backtick pairing after it, silently
// dropping a real, unrelated, non-nested route declared much later in the
// same file. This reproduces the shape at unit-test scale: a nested
// literal, then later, a completely ordinary one — both must be found.
func TestExtractBacktickLiterals_NestedTemplateLiteralDoesNotDesyncLaterOnes(t *testing.T) {
	body := "css=t=>`calc(${t?`-1`:`1`} * (${`${1}px`}))`;" +
		"basketService.get=e=>this.http.get(`${this.hostServer}/rest/basket/${e}`)"
	got := extractJSEndpoints("https://target.example/main.js", body)
	assert.Contains(t, got, "https://target.example/rest/basket/{param}",
		"a route declared after a nested template literal must still be found")
}

// TestExtractBacktickLiterals_EscapedBacktickDoesNotEndTheLiteral: a real
// "\`" inside a template literal (live-verified in Juice Shop's own bundle,
// an angularx-qrcode error message) must not be mistaken for the closing
// delimiter, which would truncate the literal early and, same as an
// unhandled nested literal, desync every pairing after it.
func TestExtractBacktickLiterals_EscapedBacktickDoesNotEndTheLiteral(t *testing.T) {
	body := "throw new Error(`Field \\`qrdata\\` is empty`);" +
		"basketService.get=e=>this.http.get(`${this.hostServer}/rest/basket/${e}`)"
	lits := extractBacktickLiterals(body)
	assert.Contains(t, lits, "Field \\`qrdata\\` is empty")
	got := extractJSEndpoints("https://target.example/main.js", body)
	assert.Contains(t, got, "https://target.example/rest/basket/{param}")
}

// TestExtractBacktickLiterals_UnterminatedLiteralIsSkippedNotHung guards
// against an unclosed backtick (a truncated JS body, LT-164's own body-size
// cap) hanging or panicking rather than just skipping it.
func TestExtractBacktickLiterals_UnterminatedLiteralIsSkippedNotHung(t *testing.T) {
	body := "const x = `/rest/unterminated"
	assert.NotPanics(t, func() { extractBacktickLiterals(body) })
	assert.Empty(t, extractBacktickLiterals(body))
}

// --- extractJSPathJoinParts / collectJSPathJoinParts / verifyJSJoinBases (LT-164, LT-186) -----------------

func TestExtractJSPathJoinParts_PlantedCrAPIShape(t *testing.T) {
	// The real live-observed crAPI bundle shape (2026-09-19): a service
	// prefix, a bare API-path constant, and a keyless query literal, each
	// declared separately.
	body := `og="identity/",ig="workshop/",ag="chatbot/",lg="community/",` +
		`sg={LOGIN:"api/auth/login",GET_SERVICE_REPORT:"api/mechanic/mechanic_report"};` +
		`const e=ig+sg.GET_SERVICE_REPORT+"?report_id="+n;`
	prefixes, bases, suffixes := extractJSPathJoinParts(body)
	assert.Contains(t, prefixes, "identity/")
	assert.Contains(t, prefixes, "workshop/")
	assert.Contains(t, prefixes, "chatbot/")
	assert.Contains(t, prefixes, "community/")
	assert.Contains(t, bases, "api/mechanic/mechanic_report")
	assert.Contains(t, bases, "api/auth/login")
	assert.Contains(t, suffixes, "?report_id=")
}

func TestExtractJSPathJoinParts_DecoysRejected(t *testing.T) {
	body := `"MM/DD/YYYY"; "application/json"; "//"; "/api/foo"; "?"; "id=5"; "foo/bar/'+x"`
	prefixes, bases, suffixes := extractJSPathJoinParts(body)
	assert.Empty(t, prefixes, "MM/DD/YYYY-shaped decoys must not become prefix candidates")
	assert.Empty(t, bases, "a bare relative string without a leading api/ segment must not become a base candidate")
	assert.Empty(t, suffixes, "a bare '?' or a key=value string must not become a query-suffix candidate")
}

func TestNormalizeJSPathPlaceholders(t *testing.T) {
	assert.Equal(t, "api/shop/orders/{orderId}", normalizeJSPathPlaceholders("api/shop/orders/<orderId>"))
	assert.Equal(t, "api/v2/vehicle/{carId}/location", normalizeJSPathPlaceholders("api/v2/vehicle/<carId>/location"))
	assert.Equal(t, "api/a<b>c", normalizeJSPathPlaceholders("api/a<b>c"), "only a whole segment is a placeholder")
	assert.Equal(t, "api/x/<a b>", normalizeJSPathPlaceholders("api/x/<a b>"), "a segment that is not an identifier is left alone")
}

// LT-186: crAPI's bundle declares "api/shop/orders/<orderId>" and
// "api/v2/vehicle/<carId>/location"; the angle brackets used to fail the JS-syntax
// plausibility check and both routes were dropped before the join step.
func TestCollectJSPathJoinParts_PlaceholderRoutesBecomeBases(t *testing.T) {
	body := `ig="workshop/",sg={A:"api/shop/orders",B:"api/shop/orders/<orderId>",C:"api/v2/vehicle/<carId>/location",D:"api/x/a<b>c"}`
	_, bases, _ := collectJSPathJoinParts(body)
	assert.Contains(t, bases, "api/shop/orders/{orderId}")
	assert.Contains(t, bases, "api/v2/vehicle/{carId}/location")
	assert.NotContains(t, bases, "api/x/a<b>c", "a JS fragment that only looks like a placeholder must still be rejected")
	assert.NotContains(t, bases, "api/x/a{b}c")
}

// LT-186: the base list used to be sorted and cut at 15, so on a bundle with more
// routes everything past the 15th name was never considered. collect reports them all.
func TestCollectJSPathJoinParts_IsUncappedAndExtractCaps(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxJSPathBases+20; i++ {
		b.WriteString(`"api/r` + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + `",`)
	}
	_, all, _ := collectJSPathJoinParts(b.String())
	require.Greater(t, len(all), maxJSPathBases)
	_, capped, _ := extractJSPathJoinParts(b.String())
	assert.Len(t, capped, maxJSPathBases)
	kept, cut := capStrings(all, maxJSPathBases)
	assert.Len(t, kept, maxJSPathBases)
	assert.Equal(t, len(all)-maxJSPathBases, cut)
}

func TestPreferSiblingPrefix(t *testing.T) {
	verified := []jsJoinPair{{Prefix: "identity/", Base: "api/v2/user/videos"}, {Prefix: "workshop/", Base: "api/shop/orders"}}
	got := preferSiblingPrefix([]string{"chatbot/", "identity/", "workshop/"}, verified, "api/shop/orders/all")
	assert.Equal(t, []string{"workshop/", "chatbot/", "identity/"}, got, "the prefix that verified the nearest sibling goes first")
	assert.Equal(t, []string{"chatbot/", "identity/", "workshop/"}, preferSiblingPrefix([]string{"chatbot/", "identity/", "workshop/"}, verified, "api/other/thing"), "no sibling, no reordering")
	assert.Equal(t, []string{"a/", "b/"}, preferSiblingPrefix([]string{"a/", "b/"}, verified, "api/health"), "one shared segment (\"api\") is not a family")
	assert.Equal(t, []string{"identity/", "a/", "b/"}, preferSiblingPrefix([]string{"a/", "b/", "identity/"}, verified, "api/v2/community/posts"),
		"two shared segments is the threshold: a wrong first guess costs one probe, never a wrong result, since the canary still has to differ")
}

// joinFixture serves a bundle and a set of real routes, counting every request path.
type joinFixture struct {
	srv  *httptest.Server
	hits map[string]int
}

func newJoinFixture(t *testing.T, real map[string]int, blanket map[string]int) *joinFixture {
	t.Helper()
	f := &joinFixture{hits: map[string]int{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.hits[r.URL.Path]++
		if code, ok := real[r.URL.Path]; ok {
			w.WriteHeader(code)
			return
		}
		for prefix, code := range blanket {
			if strings.HasPrefix(r.URL.Path, prefix) {
				w.WriteHeader(code)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *joinFixture) recon(t *testing.T, jsBody string) *ReconResult {
	t.Helper()
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + f.srv.URL + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)
	result, err := New(newTestClient(), withRun(fake)).Run(context.Background(), f.srv.URL, DepthFull)
	require.NoError(t, err)
	return result
}

func joinedURLs(result *ReconResult) []string {
	var out []string
	for _, ep := range result.Endpoints {
		if ep.Source == "js-static-joined" {
			out = append(out, ep.URL)
		}
	}
	return out
}

// TestRunWave3_JSJoin_TemplatedRouteBorrowsItsSiblingsPrefix is LT-186's core case:
// a parameterised route is emitted under the prefix that verified a sibling in the
// same resource family, is never requested with its placeholder, and becomes an
// idor candidate.
func TestRunWave3_JSJoin_TemplatedRouteBorrowsItsSiblingsPrefix(t *testing.T) {
	f := newJoinFixture(t, map[string]int{
		"/workshop/api/shop/orders":     http.StatusMethodNotAllowed,
		"/workshop/api/shop/orders/all": http.StatusUnauthorized,
	}, nil)
	jsBody := `og="identity/",ig="workshop/",` +
		`sg={BUY:"api/shop/orders",ALL:"api/shop/orders/all",BY_ID:"api/shop/orders/<orderId>"};`
	result := f.recon(t, jsBody)

	assert.ElementsMatch(t, []string{
		f.srv.URL + "/workshop/api/shop/orders",
		f.srv.URL + "/workshop/api/shop/orders/all",
		f.srv.URL + "/workshop/api/shop/orders/{orderId}",
	}, joinedURLs(result))
	for path := range f.hits {
		assert.NotContains(t, path, "orderId", "a placeholder must never be requested as a literal: %s", path)
		assert.NotContains(t, path, "{", "no request may carry a placeholder: %s", path)
	}
	assert.Contains(t, SuggestIDOREndpointCandidates(result), "/workshop/api/shop/orders/{{id}}")
}

// A route that throws on a parameterless request answers 500, where an unknown path answers 404.
func TestRunWave3_JSJoin_ServerErrorOnARealRouteVerifiesIt(t *testing.T) {
	f := newJoinFixture(t, map[string]int{"/workshop/api/mechanic/mechanic_report": http.StatusInternalServerError}, nil)
	result := f.recon(t, `ig="workshop/",sg={R:"api/mechanic/mechanic_report"};const e=ig+sg.R+"?report_id="+n;`)
	assert.Equal(t, []string{f.srv.URL + "/workshop/api/mechanic/mechanic_report?report_id="}, joinedURLs(result))
}

// A gateway error is infrastructure, not evidence the route exists.
func TestRunWave3_JSJoin_GatewayErrorDoesNotVerify(t *testing.T) {
	f := newJoinFixture(t, map[string]int{"/workshop/api/mechanic/mechanic_report": http.StatusBadGateway}, nil)
	result := f.recon(t, `ig="workshop/",sg={R:"api/mechanic/mechanic_report"};`)
	assert.Empty(t, joinedURLs(result))
}

func TestRunWave3_JSJoin_TemplatedRouteWithNoVerifiedSiblingIsNotEmittedAndIsReported(t *testing.T) {
	f := newJoinFixture(t, map[string]int{"/workshop/api/mechanic/mechanic_report": http.StatusUnauthorized}, nil)
	jsBody := `ig="workshop/",sg={R:"api/mechanic/mechanic_report",S:"api/mechanic/service_request/<serviceId>"};`
	result := f.recon(t, jsBody)

	for _, u := range joinedURLs(result) {
		assert.NotContains(t, u, "service_request", "no verified route shares its resource family, so no prefix can be borrowed")
	}
	assert.Contains(t, strings.Join(result.Warnings, "\n"), "1 parameterised API route(s)")
}

// LT-186: 15 was the old cap, and it starved everything alphabetically after the
// 15th name. A 30-route family on one service must now be found in full, and
// cost about one probe per route after the first, not one per prefix.
func TestRunWave3_JSJoin_BeyondTheOldCapAndCheapPerRoute(t *testing.T) {
	real := map[string]int{}
	var consts []string
	for i := 0; i < 30; i++ {
		name := "r" + string(rune('a'+i/26)) + string(rune('a'+i%26))
		real["/workshop/api/svc/"+name] = http.StatusUnauthorized
		consts = append(consts, "K"+name+":\"api/svc/"+name+"\"")
	}
	f := newJoinFixture(t, real, nil)
	jsBody := `a="chatbot/",b="community/",c="identity/",d="workshop/",sg={` + strings.Join(consts, ",") + `};`
	result := f.recon(t, jsBody)

	assert.Len(t, joinedURLs(result), 30, "every route past the old 15-route cap must be verified")
	probes := 0
	for path, n := range f.hits {
		if strings.Contains(path, "/api/svc/") {
			probes += n
		}
	}
	assert.LessOrEqual(t, probes, 30+3, "one probe per route once the family's prefix is known, plus the wrong prefixes tried for the first: got %d (the old cross product was 120)", probes)
}

func TestRunWave3_JSJoin_ReportsCandidatesBeyondTheBaseCap(t *testing.T) {
	var consts []string
	for i := 0; i < maxJSPathBases+5; i++ {
		consts = append(consts, "K"+strings.Repeat("x", i%3)+string(rune('a'+i%26))+string(rune('a'+i/26))+":\"api/many/n"+string(rune('a'+i%26))+string(rune('a'+i/26))+"\"")
	}
	f := newJoinFixture(t, nil, nil)
	result := f.recon(t, `ig="workshop/",sg={`+strings.Join(consts, ",")+`};`)
	assert.Contains(t, strings.Join(result.Warnings, "\n"), "beyond the 80-per-bundle cap", "a cut must be reported, not silent")
}

// --- extractJSSecrets ---------------------------------------------------

func TestExtractJSSecrets_AWSAccessKey(t *testing.T) {
	body := `const key = "AKIAABCDEFGHIJKLMNOP";`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "aws-access-key", got[0].Kind)
	assert.Equal(t, "high", got[0].Severity)
	assert.NotContains(t, got[0].Redacted, "ABCDEFGHIJKLMNOP", "the real secret value must never appear unredacted")
	assert.Equal(t, 1, got[0].Line)
}

func TestExtractJSSecrets_GoogleAPIKey(t *testing.T) {
	// Split across concatenation so no contiguous token-shaped literal sits
	// in the source (GitHub secret scanning flags the shape on sight, even
	// for an obviously-fake fixture value never used against a real API).
	fakeKey := "AIzaSyD-9tSrke72PouQMnMX" + "-a7eZSW0jkFMBWY"
	body := `apiKey: "` + fakeKey + `"`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "google-api-key", got[0].Kind)
}

func TestExtractJSSecrets_SlackToken(t *testing.T) {
	// Split across concatenation so no contiguous token-shaped literal sits
	// in the source (GitHub push protection flags the shape on sight, even
	// for an obviously-fake fixture value).
	fakeToken := "xoxb-1234567890-" + "abcdefghijklmnop"
	body := `token: "` + fakeToken + `"`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "slack-token", got[0].Kind)
}

func TestExtractJSSecrets_GitHubToken(t *testing.T) {
	body := `const t = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";` // 36 chars after ghp_
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "github-token", got[0].Kind)
	assert.Equal(t, "critical", got[0].Severity)
}

func TestExtractJSSecrets_PrivateKeyHeader(t *testing.T) {
	body := "-----BEGIN RSA PRIVATE KEY-----\nMIIC...\n-----END RSA PRIVATE KEY-----"
	got := extractJSSecrets("https://target.example/config.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "private-key", got[0].Kind)
}

func TestExtractJSSecrets_LineNumberTracksNewlines(t *testing.T) {
	body := "line one\nline two\nconst key = \"AKIAABCDEFGHIJKLMNOP\";\n"
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, 3, got[0].Line)
}

func TestExtractJSSecrets_BearerToken_HighEntropyAccepted(t *testing.T) {
	body := `headers: {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.aZ9kLp3mQwErTyUiOpAsDfGh"}`
	got := extractJSSecrets("https://target.example/app.js", body)
	require.Len(t, got, 1)
	assert.Equal(t, "hardcoded-bearer-token", got[0].Kind)
}

// TestExtractJSSecrets_DecoysRejected covers the FP-reduction machinery
// (placeholder-word screen + entropy floor) for the one shape-only pattern —
// the four vendor-prefixed patterns need no such screen (see the patterns'
// own doc comment).
func TestExtractJSSecrets_DecoysRejected(t *testing.T) {
	decoys := []string{
		`Authorization: "Bearer YOUR_TOKEN_HERE_PLEASE_REPLACE"`, // placeholder marker
		`Authorization: "Bearer aaaaaaaaaaaaaaaaaaaaaaaa"`,       // low entropy
		`const example = "just a normal string of some length"`,  // no pattern at all
		`aki_but_not_aws_key_shaped_string_here_1234567890`,      // near-miss, not a real prefix match
	}
	for _, d := range decoys {
		got := extractJSSecrets("https://target.example/app.js", d)
		assert.Empty(t, got, "decoy %q must not be reported as a secret", d)
	}
}

func TestRedactSecret_NeverExposesFullValue(t *testing.T) {
	r := redactSecret("AKIAABCDEFGHIJKLMNOP")
	assert.NotEqual(t, "AKIAABCDEFGHIJKLMNOP", r)
	assert.True(t, strings.HasPrefix(r, "AKIA"))
	assert.True(t, strings.HasSuffix(r, "MNOP"))
}

// --- extractCloudBucketRefs ---------------------------------------------

func TestExtractCloudBucketRefs_S3HostStyle(t *testing.T) {
	refs := extractCloudBucketRefs(`img src="https://my-app-uploads.s3.amazonaws.com/logo.png"`)
	require.Len(t, refs, 1)
	assert.Equal(t, "s3", refs[0].kind)
	assert.Equal(t, "https://my-app-uploads.s3.amazonaws.com/", refs[0].url)
}

func TestExtractCloudBucketRefs_S3PathStyle(t *testing.T) {
	refs := extractCloudBucketRefs(`"https://s3.amazonaws.com/my-app-uploads/logo.png"`)
	require.Len(t, refs, 1)
	assert.Equal(t, "s3", refs[0].kind)
	assert.Equal(t, "https://s3.amazonaws.com/my-app-uploads/", refs[0].url)
}

func TestExtractCloudBucketRefs_GCSHostStyle(t *testing.T) {
	refs := extractCloudBucketRefs(`"https://my-gcs-bucket.storage.googleapis.com/file.pdf"`)
	require.Len(t, refs, 1)
	assert.Equal(t, "gcp", refs[0].kind)
}

func TestExtractCloudBucketRefs_NoBucket_Empty(t *testing.T) {
	refs := extractCloudBucketRefs(`just some ordinary JS with no cloud references at all`)
	assert.Empty(t, refs)
}

func TestExtractCloudBucketRefs_DedupedWithinOneCall(t *testing.T) {
	text := `"https://bucket.s3.amazonaws.com/a" "https://bucket.s3.amazonaws.com/b"`
	refs := extractCloudBucketRefs(text)
	assert.Len(t, refs, 1)
}

// --- end-to-end: runJSStaticAnalysis via a full recon Run ----------------

// TestRunWave3_JSStaticAnalysis_EndpointsSecretsAndCloudFact exercises the
// whole Phase 8 Step 3 pass through a real recon.Run: katana's own JSONL
// output already carries the fetched .js body (no -omit-body flag is
// passed), and this recon run must turn it into an endpoint candidate, a
// redacted secret fact, and an actionable "s3" TechFact — all without any
// extra request beyond the one katana already made.
func TestRunWave3_JSStaticAnalysis_EndpointsSecretsAndCloudFact(t *testing.T) {
	jsBody := `fetch("/api/v2/internal/reports");` +
		`const key = "AKIAABCDEFGHIJKLMNOP";` +
		`const bucket = "https://my-app-uploads.s3.amazonaws.com/asset.png";`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := "https://target.example"
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	require.Len(t, result.Secrets, 1)
	assert.Equal(t, "aws-access-key", result.Secrets[0].Kind)
	assert.NotContains(t, result.Secrets[0].Redacted, "ABCDEFGHIJKLMNOP")

	foundJSStaticEndpoint := false
	foundBucketEndpoint := false
	for _, ep := range result.Endpoints {
		if ep.Source == "js-static" && ep.URL == target+"/api/v2/internal/reports" {
			foundJSStaticEndpoint = true
		}
		if ep.Source == "js-static-cloud" && ep.URL == "https://my-app-uploads.s3.amazonaws.com/" {
			foundBucketEndpoint = true
		}
	}
	assert.True(t, foundJSStaticEndpoint, "expected a js-static EndpointFact from the fetch() call, got: %+v", result.Endpoints)
	assert.True(t, foundBucketEndpoint, "expected a js-static-cloud EndpointFact for the discovered bucket, got: %+v", result.Endpoints)

	foundCloudTech := false
	for _, tf := range result.TechStack {
		if tf.Name == "s3" {
			foundCloudTech = true
			assert.Equal(t, "my-app-uploads.s3.amazonaws.com", tf.Host, "the cloud TechFact must attach to the bucket's own host — the corpus's bucket-exposure templates need to run against the bucket itself")
		}
	}
	assert.True(t, foundCloudTech, "expected an 's3' TechFact from the bucket reference, got: %+v", result.TechStack)

	// The whole result, secrets and all, must still satisfy the frozen schema.
	schema := compileReconSchema(t)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	var asAny any
	require.NoError(t, json.Unmarshal(raw, &asAny))
	assert.NoError(t, schema.Validate(asAny), "ReconResult with secrets must satisfy docs/schema/recon-result.schema.json: %s", raw)
}

// TestRunWave3_JSStaticAnalysis_OutOfScopeBucket_NotDispatched guards the
// scope boundary: a bucket URL mentioned in JS never becomes a scannable
// EndpointFact or a dispatchable TechFact unless it independently clears
// --scope — a page can reference any third party's bucket, so a mention
// alone must never earn a scan or a fact about anything.
func TestRunWave3_JSStaticAnalysis_OutOfScopeBucket_NotDispatched(t *testing.T) {
	jsBody := `const bucket = "https://someones-bucket.s3.amazonaws.com/asset.png";`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := "https://target.example"
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	s, err := scope.New([]string{"target.example"}) // the bucket host is NOT in scope
	require.NoError(t, err)
	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		assert.NotContains(t, ep.URL, "someones-bucket", "an out-of-scope bucket must never become a dispatchable endpoint")
	}
	assert.Contains(t, result.OutOfScope, "someones-bucket.s3.amazonaws.com")

	for _, tf := range result.TechStack {
		assert.NotEqual(t, "s3", tf.Name, "an out-of-scope bucket mention must never produce a dispatchable TechFact")
	}
}

// TestRunWave3_JSStaticAnalysis_OutOfScopeAbsoluteEndpoint_NotDispatched is
// LT-144's regression guard (docs/follow-up.md): extractJSEndpoints's
// absolute-URL branch only checks path *shape*, so a page can carry an
// absolute URL on an unrelated third-party domain (live-observed: an
// "xmlns=\"http://www.w3.org/1999/xhtml\"" namespace declaration, not a
// link) and that host must clear --scope exactly like a cloud-bucket
// reference already does, rather than becoming a real js-static
// EndpointFact that registry.Resolve can turn into a dispatchable leaf
// against a host nobody authorized.
func TestRunWave3_JSStaticAnalysis_OutOfScopeAbsoluteEndpoint_NotDispatched(t *testing.T) {
	jsBody := `const u = "https://evil.example/api/v2/admin/users";`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := "https://target.example"
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	s, err := scope.New([]string{"target.example"}) // evil.example is NOT in scope
	require.NoError(t, err)
	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		assert.NotContains(t, ep.URL, "evil.example", "an out-of-scope absolute endpoint must never become a dispatchable EndpointFact")
	}
	assert.Contains(t, result.OutOfScope, "evil.example")
}

// TestRunWave3_JSStaticAnalysis_JoinedPathCandidate_LiveVerified is LT-164's
// regression guard (docs/follow-up.md): a service-route prefix and a bare
// API-path constant declared separately in a bundle — crAPI's own real
// shape, live-verified 2026-09-19 — must join into a real EndpointFact only
// once the specific combination is live-verified, with every wrong
// prefix+base combination dropped rather than emitted at the same
// confidence.
func TestRunWave3_JSStaticAnalysis_JoinedPathCandidate_LiveVerified(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/workshop/api/mechanic/mechanic_report", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // the one real, correct join
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // every other path, including the wrong-prefix joins
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jsBody := `og="identity/",ig="workshop/",ag="chatbot/",lg="community/",` +
		`sg={GET_SERVICE_REPORT:"api/mechanic/mechanic_report"};` +
		`const e=ig+sg.GET_SERVICE_REPORT+"?report_id="+n;`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := srv.URL
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	foundReal := false
	for _, ep := range result.Endpoints {
		if ep.Source != "js-static-joined" {
			continue
		}
		assert.Contains(t, ep.URL, "/workshop/api/mechanic/mechanic_report", "the only live-verified prefix+base combination is the workshop one, got: %s", ep.URL)
		if ep.URL == target+"/workshop/api/mechanic/mechanic_report?report_id=" {
			foundReal = true
		}
	}
	assert.True(t, foundReal, "expected the verified workshop join + keyless query suffix, got: %+v", result.Endpoints)

	candidates := SuggestIDOREndpointCandidates(result)
	assert.Contains(t, candidates, "/workshop/api/mechanic/mechanic_report?report_id={{id}}", "the joined+verified endpoint must flow into the existing idor candidate pipeline unchanged")
}

// TestRunWave3_JSStaticAnalysis_JoinedPathCandidate_NoneVerified_EmitsNothing
// guards the other side: when no prefix+base combination verifies (every
// probe 404s), no js-static-joined EndpointFact is emitted at all — the
// live-verification step must prune to nothing rather than falling back to
// emitting every unverified guess.
func TestRunWave3_JSStaticAnalysis_JoinedPathCandidate_NoneVerified_EmitsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	jsBody := `ig="workshop/";sg={GET_SERVICE_REPORT:"api/mechanic/mechanic_report"};`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := srv.URL
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	for _, ep := range result.Endpoints {
		assert.NotEqual(t, "js-static-joined", ep.Source, "no combination verified — no js-static-joined endpoint should be emitted, got: %+v", ep)
	}
}

// TestRunWave3_JSStaticAnalysis_JoinedPathCandidate_BlanketAuthPrefixRejected
// is LT-164's canary-diff regression guard, live-verified against crAPI
// itself 2026-09-19: its identity/ service answers 401 for *every* path
// under that prefix — real or not, a Spring Security gateway rejecting
// before route resolution — so a bare jsJoinVerifyStatuses membership check
// alone would accept every identity/+base combination as "verified"
// alongside the one real workshop/ endpoint, reintroducing the exact
// "multiple distinct candidates" ambiguity this whole step exists to
// resolve. fetchJSPrefixCanary's per-prefix diff must reject identity/'s
// look-alikes while still accepting workshop/'s real one.
func TestRunWave3_JSStaticAnalysis_JoinedPathCandidate_BlanketAuthPrefixRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/workshop/api/mechanic/mechanic_report", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // the real route: needs auth, but exists
	})
	mux.HandleFunc("/workshop/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // workshop/'s canary and every other workshop/ path: a real 404
	})
	mux.HandleFunc("/identity/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // identity/'s blanket gate: 401 for literally everything
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jsBody := `og="identity/",ig="workshop/",` +
		`sg={GET_SERVICE_REPORT:"api/mechanic/mechanic_report"};` +
		`const e=ig+sg.GET_SERVICE_REPORT+"?report_id="+n;`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := srv.URL
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	foundWorkshop := false
	for _, ep := range result.Endpoints {
		if ep.Source != "js-static-joined" {
			continue
		}
		assert.NotContains(t, ep.URL, "/identity/", "identity/'s blanket-401 look-alike must be rejected by the canary diff, got: %+v", result.Endpoints)
		if strings.Contains(ep.URL, "/workshop/api/mechanic/mechanic_report") {
			foundWorkshop = true
		}
	}
	assert.True(t, foundWorkshop, "the real workshop/ endpoint must still be verified despite identity/'s look-alike being rejected, got: %+v", result.Endpoints)
}

// --- assignQuerySuffixes (LT-184) ---------------------------------------

const crapiShapedBody = `og="identity/",ig="workshop/",` +
	`sg={LOGIN:"api/auth/login",SIGNUP:"api/auth/signup",GET_SERVICE_REPORT:"api/mechanic/mechanic_report"};` +
	`const e=ig+sg.GET_SERVICE_REPORT+"?report_id="+n;`

func TestAssignQuerySuffixes_TiesSuffixToTheBaseItIsUsedWith(t *testing.T) {
	bases := []string{"api/auth/login", "api/auth/signup", "api/mechanic/mechanic_report"}
	got := assignQuerySuffixes(crapiShapedBody, bases, []string{"?report_id="})
	assert.Equal(t, map[string][]string{"api/mechanic/mechanic_report": {"?report_id="}}, got,
		"the suffix must attach to the one route the bundle joins it to, not be crossed with every base")
}

func TestAssignQuerySuffixes_UntiedSuffixAttachesOnlyWhenOneBaseVerified(t *testing.T) {
	body := `sg={GET_SERVICE_REPORT:"api/mechanic/mechanic_report"};x=fetch(q+"?report_id="+n)`
	one := assignQuerySuffixes(body, []string{"api/mechanic/mechanic_report"}, []string{"?report_id="})
	assert.Equal(t, []string{"?report_id="}, one["api/mechanic/mechanic_report"], "a single verified base leaves nothing to be ambiguous about")

	two := assignQuerySuffixes(body+`,sg2={LOGIN:"api/auth/login"}`, []string{"api/mechanic/mechanic_report", "api/auth/login"}, []string{"?report_id="})
	assert.Empty(t, two, "with several verified bases an untied suffix is dropped, not guessed")
}

func TestAssignQuerySuffixes_MangledShortNamesDoNotTie(t *testing.T) {
	body := `o={a:"api/x/one",b:"api/x/two"};const e=a+"?report_id="+n;`
	got := assignQuerySuffixes(body, []string{"api/x/one", "api/x/two"}, []string{"?report_id="})
	assert.Empty(t, got, "one- and two-letter identifiers recur across a minified bundle and prove nothing")
}

// TestRunWave3_JSStaticAnalysis_QuerySuffixOnlyOnItsOwnRoute is LT-184's
// regression guard, live-observed against crAPI 2026-09-21: several routes
// verified from one bundle, one `?report_id=` literal in it, and the literal
// used to be crossed with every verified route — 12 idor leaves, 11 of them on
// unrelated paths. The suffix must land only on the route the bundle uses it
// with; the other verified routes are still recon facts, emitted bare.
func TestRunWave3_JSStaticAnalysis_QuerySuffixOnlyOnItsOwnRoute(t *testing.T) {
	mux := http.NewServeMux()
	for _, p := range []string{"/workshop/api/mechanic/mechanic_report", "/workshop/api/auth/login", "/workshop/api/auth/signup"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jsBodyJSON, err := json.Marshal(crapiShapedBody)
	require.NoError(t, err)
	target := srv.URL
	responses := map[string]string{
		"katana": `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
			`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`,
	}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	var joined []string
	for _, ep := range result.Endpoints {
		if ep.Source == "js-static-joined" {
			joined = append(joined, ep.URL)
		}
	}
	assert.ElementsMatch(t, []string{
		target + "/workshop/api/mechanic/mechanic_report?report_id=",
		target + "/workshop/api/auth/login",
		target + "/workshop/api/auth/signup",
	}, joined)
	assert.Equal(t, []string{"/workshop/api/mechanic/mechanic_report?report_id={{id}}"}, SuggestIDOREndpointCandidates(result),
		"one query key on one route must yield one idor candidate")
}

// TestRunWave3_JSStaticAnalysis_DuplicateAssetObservation_ProcessedOnce is
// LT-164's asset-dedup regression guard: katana's crawl can (and does,
// live-verified against crAPI) observe the same bundle URL more than once —
// the same asset linked from several pages at different crawl depths. Before
// the dedup fix, each duplicate observation independently re-verified and
// re-emitted the same join candidate as a second, byte-identical
// EndpointFact, which registry.Resolve then turned into a genuine second
// idor leaf for the same URL — the orchestrator re-dispatched (and
// re-scanned) an already-resolved real endpoint multiple times in one run,
// each dispatch burning real wall-clock/LLM-turn budget on a leaf that had
// already produced findings. One asset URL must contribute its join
// candidate exactly once regardless of how many times it was observed.
func TestRunWave3_JSStaticAnalysis_DuplicateAssetObservation_ProcessedOnce(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/workshop/api/mechanic/mechanic_report", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	jsBody := `ig="workshop/";sg={GET_SERVICE_REPORT:"api/mechanic/mechanic_report"};` +
		`const e=ig+sg.GET_SERVICE_REPORT+"?report_id="+n;`
	jsBodyJSON, err := json.Marshal(jsBody)
	require.NoError(t, err)

	target := srv.URL
	// The same asset URL observed twice — e.g. linked from two different
	// crawled pages — exactly the shape live-verified against crAPI.
	line := `{"request":{"endpoint":"` + target + `/static/app.js","method":"GET"},` +
		`"response":{"status_code":200,"headers":{"content-type":"application/javascript"},"body":` + string(jsBodyJSON) + `}}`
	responses := map[string]string{"katana": line + "\n" + line}
	_, fake := recordingRun(t, responses)

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	count := 0
	for _, ep := range result.Endpoints {
		if ep.Source == "js-static-joined" && ep.URL == target+"/workshop/api/mechanic/mechanic_report?report_id=" {
			count++
		}
	}
	assert.Equal(t, 1, count, "a join candidate from a duplicate-observed asset must be emitted exactly once, got %d, endpoints: %+v", count, result.Endpoints)
}
