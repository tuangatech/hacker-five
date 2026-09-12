package recon

import (
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// maxSpecAuthProtectedPaths caps how many spec-declared auth-required routes
// (LT-90) SuggestAuthBypassPathsFromRecon contributes to the protected set —
// each one becomes a tokenless GET in authbypass's checkMissingAuth, and a
// large spec shouldn't turn that into hundreds of requests. Observed
// 401/403 paths are never capped; only the spec-derived tail is.
const maxSpecAuthProtectedPaths = 30

// numericIDPattern/uuidPattern match a full path segment or query value that
// looks like a database ID — anchored so "v2" or "api123abc" never match, the
// same discipline pkg/registry's techRules uses for exact-name lookups rather
// than fuzzy substring matching.
var (
	numericIDPattern = regexp.MustCompile(`^[0-9]+$`)
	uuidPattern      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func isIDShaped(s string) bool {
	return s != "" && (numericIDPattern.MatchString(s) || uuidPattern.MatchString(s))
}

// isSpecPathParam reports whether seg is an OpenAPI/Swagger path-template
// parameter — "{id}", "{userId}", "{user_id}". Such a segment is an
// identifier position by definition (LT-40, docs/follow-up.md), so an
// EndpointFact the spec walker emitted with the templating intact
// ("/users/{id}") yields an {{id}} candidate the same as an observed
// "/users/482" would, without the walker fabricating a concrete id.
func isSpecPathParam(seg string) bool {
	return len(seg) > 2 && strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// smallIntPattern matches a 1-6 digit run — a plausible per-record object
// ID, small enough to exclude epoch timestamps and cache-buster nonces that
// idShapedQueryCandidate's name check (looksLikeIDKey) would already skip
// but numericQueryIDCandidates, which ignores the key name, must not.
var smallIntPattern = regexp.MustCompile(`^[0-9]{1,6}$`)

// nonIDNumericQueryKeys are query-parameter names that conventionally carry
// a small integer that is not an object identifier — pagination, image
// resize, cache-busting. A varying numeric value on one of these is not an
// IDOR/SQLi candidate even though its shape matches (docs/follow-up.md
// LT-83). Same "exclude by curated table" discipline as ssrfParamKeywords.
var nonIDNumericQueryKeys = map[string]bool{
	"page": true, "limit": true, "offset": true, "per_page": true, "perpage": true,
	"page_size": true, "pagesize": true, "start": true, "count": true, "size": true,
	"w": true, "h": true, "width": true, "height": true, "dpr": true, "quality": true,
	"q": true, "fit": true, "v": true, "ver": true, "version": true, "rev": true,
	"t": true, "ts": true, "timestamp": true, "_": true,
}

// numericQueryIDCandidates finds query keys whose observed value is a small
// integer that varies across at least two crawled URLs sharing the same
// path, and returns each as a "/path?key={{id}}" candidate. This is the
// IDOR/SQLi surface of a query-routed CMS (?article=3..13, ?topic=1..2 —
// sandbox-royal.securegateway.com, docs/follow-up.md LT-83) that
// idShapedQueryCandidate misses because it gates on the key *name*
// (looksLikeIDKey) and "article" doesn't look like an identifier. The
// ">= 2 distinct values" requirement is what separates a route parameter
// enumerated by the crawl from a lone constant that could be anything.
func numericQueryIDCandidates(endpoints []EndpointFact) []string {
	type pathKey struct{ path, key string }
	values := map[pathKey]map[string]bool{}
	var order []pathKey
	for _, ep := range endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || u.RawQuery == "" {
			continue
		}
		if IsStaticAssetPath(u.Path) || !IsPlausibleURLPath(u.Path) {
			continue
		}
		for _, pair := range strings.Split(u.RawQuery, "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := kv[0]
			if key == "" || nonIDNumericQueryKeys[strings.ToLower(key)] {
				continue
			}
			val, err := url.QueryUnescape(kv[1])
			if err != nil || !smallIntPattern.MatchString(val) {
				continue
			}
			k := pathKey{u.Path, key}
			if values[k] == nil {
				values[k] = map[string]bool{}
				order = append(order, k)
			}
			values[k][val] = true
		}
	}
	var out []string
	for _, k := range order {
		if len(values[k]) < 2 {
			continue
		}
		out = append(out, k.path+"?"+k.key+"={{id}}")
	}
	return out
}

// jsSyntaxInPath matches a character that never legitimately appears
// unescaped in a URL path but is common in a JavaScript source fragment —
// a quote, a backtick, a paren/bracket, a "+", an angle bracket, a
// backslash, or whitespace. Endpoint extraction that reads crawled .js
// bodies can otherwise surface a string-concatenation snippet like
// "/library/video/'+D.prop(" as an endpoint or "protected path"
// candidate, which then seeds a nonsensical idor/authbypass leaf
// (docs/follow-up.md LT-85, same junk-candidate family as LT-20 / LT-66).
var jsSyntaxInPath = regexp.MustCompile("['\"`()\\[\\]<>\\\\ +]")

// IsPlausibleURLPath reports whether p could be a real, requestable URL
// path: non-empty, rooted at "/", and free of the JavaScript-syntax
// punctuation that marks a fragment scraped out of a .js body rather than
// an observed request. Kept deliberately strict — a candidate this
// rejects is one no scan should ever have dispatched.
func IsPlausibleURLPath(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") {
		return false
	}
	return !jsSyntaxInPath.MatchString(p)
}

// SuggestIDOREndpointCandidates walks result's EndpointFacts looking for a
// path segment or query value shaped like a database ID, and returns each
// distinct {{id}}-templated candidate found — e.g. an observed
// ".../mechanic_report?report_id=482" becomes
// "/mechanic_report?report_id={{id}}". Pure and pkg/webui-agnostic
// (docs/14-implementation-plan-ph5.md Step 7) so it's reusable by
// cmd/hackerfive/plan.go or a future MCP tool, not just the Launch page.
//
// Returned candidates are path-only (scheme+host stripped) — matching
// scanner.Config.EndpointTemplate's own real contract ("endpoint path with
// an {{id}} placeholder", joined onto a target later by
// pkg/scanner/engine.go's runDetector, not a standalone URL). Found live
// against a real external target: an earlier version returned the full
// observed URL, which pkg/webui.fillReconFields would have written straight
// into EndpointTemplate — concatenated with the target a second time by
// runDetector, producing a broken double-domain string. Never reached a real
// scan (that run's own multiple-candidate case skipped instead of
// auto-filling), but a real defect all the same, fixed here before a
// single-candidate run could ever hit it.
//
// Deliberately returns every distinct candidate rather than picking one:
// zero candidates and multiple distinct candidates are both real, different
// situations a caller must handle explicitly (skip-and-explain, in the
// Launch page's case) — this function only ever reports what recon found.
func SuggestIDOREndpointCandidates(result *ReconResult) []string {
	candidates, _ := idorCandidatesAndSeeds(result)
	return candidates
}

// SuggestIDORSeedIDs returns, for every UUID-shaped {{id}} candidate
// SuggestIDOREndpointCandidates would also produce, the concrete UUID value
// recon actually observed on the wire — keyed by the same {{id}}-templated
// string, so a caller already holding a candidate template can look up its
// seed. LT-95 (docs/follow-up.md): idor.SequentialIntStrategy's int-only
// range can never reach a UUID-keyed BOLA (e.g. crAPI's
// vehicle/{vehicleId}/location); idor.RandomUUIDStrategy instead needs one
// real, concrete seed ID to test cross-account access against directly.
// Wave 3's crawl runs with whatever --auth-token/header the operator
// supplied, so a concrete UUID seen in an authenticated crawl is very
// likely that same account's own resource ID — exactly the value idor's
// owner/other baseline semantics need. Never invents a value: only
// surfaces an ID recon actually observed. A template with no UUID-shaped
// observation (e.g. a plain int-keyed route) has no entry.
func SuggestIDORSeedIDs(result *ReconResult) map[string]string {
	_, seeds := idorCandidatesAndSeeds(result)
	return seeds
}

// idorCandidatesAndSeeds is SuggestIDOREndpointCandidates/
// SuggestIDORSeedIDs' shared implementation — one walk over result's
// EndpointFacts feeding both public views, so their filtering (static-asset
// skip, LT-117's asset-wrapper skip, LT-85's plausible-path check) can never
// drift apart.
func idorCandidatesAndSeeds(result *ReconResult) (candidates []string, seedByTemplate map[string]string) {
	if result == nil {
		return nil, nil
	}

	seen := map[string]bool{}
	for _, ep := range result.Endpoints {
		// A static build/CDN asset's ID-shaped path segment is a cache-slot
		// or version number, not a per-record identifier — swapping it just
		// serves a different concatenated JS/CSS bundle, never another
		// user's data. Found live, 2026-09-04: a real WordPress target's
		// minify-cache plugin served bundles from
		// "/wp-content/cache/min/<N>/...", each distinct plugin bundle
		// producing its own {{id}}-templated "candidate" — 4 static .js
		// files, none of them a meaningful IDOR test target, surfaced as
		// "4 candidates found, none auto-selected" instead of the more
		// honest "recon found no candidate."
		p := endpointPath(ep.URL)
		if IsStaticAssetPath(p) {
			continue
		}
		// LT-117: a *.js.php asset wrapper or a dependency-tree file
		// (node_modules/, dist/js/, …) isn't an IDOR target on its own.
		// Unlike the bare .js/.css dropped just above, a server-rendered
		// *.php that merely ends ".js.php" could still carry a real,
		// tamperable id — so only drop the inert case here: a plain GET with
		// no query string. A "?id=…" variant, or any non-GET, still flows
		// through to idShapedCandidate below.
		if derivedAssetPath(p) && !strings.Contains(ep.URL, "?") &&
			(ep.Method == "" || strings.EqualFold(ep.Method, http.MethodGet)) {
			continue
		}
		// A path scraped as a JavaScript string-concat fragment
		// ("/library/video/'+D.prop(") is not a requestable endpoint —
		// drop it before it can become an {{id}} candidate (LT-85).
		if !IsPlausibleURLPath(p) {
			continue
		}
		tmpl, concreteVal, isUUID, ok := idShapedCandidate(ep.URL)
		if !ok || seen[tmpl] {
			continue
		}
		seen[tmpl] = true
		candidates = append(candidates, tmpl)
		if isUUID && concreteVal != "" {
			if seedByTemplate == nil {
				seedByTemplate = map[string]string{}
			}
			seedByTemplate[tmpl] = concreteVal
		}
	}
	// LT-83: a query-routed CMS enumerates its content through a numeric
	// param whose name (e.g. "article") doesn't look ID-shaped — pick those
	// up from the cross-endpoint value spread, after the per-URL pass above.
	for _, tmpl := range numericQueryIDCandidates(result.Endpoints) {
		if seen[tmpl] {
			continue
		}
		seen[tmpl] = true
		candidates = append(candidates, tmpl)
	}
	return candidates, seedByTemplate
}

// idShapedCandidate returns the {{id}}-templated path(+query) for rawURL, if
// any — an ID-shaped path segment first, else an ID-shaped query value whose
// key name itself suggests an identifier. concreteVal/isUUID (LT-95,
// docs/follow-up.md) surface the real value that was templated away and
// whether it was UUID-shaped, so idorCandidatesAndSeeds can offer it as a
// RandomUUIDStrategy seed — a plain int-shaped or spec-templated "{id}"
// match leaves isUUID false, since idor.SequentialIntStrategy already
// brute-forces the int case and a bare "{id}"/"{userId}" spec placeholder
// carries no real value at all.
func idShapedCandidate(rawURL string) (tmpl, concreteVal string, isUUID, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", false, false
	}

	if tmpl, concreteVal, isUUID, ok := idShapedPathCandidate(u); ok {
		return tmpl, concreteVal, isUUID, true
	}
	return idShapedQueryCandidate(u)
}

// idShapedPathCandidate deliberately drops the query string entirely: found
// live against a real target (a CDN image path,
// "/pluto-images/funnel/images/<uuid>?w=96", "...?h=48&dpr=3&fit=cover", ...)
// where the same real ID-shaped path recurred across dozens of otherwise-
// identical EndpointFacts, differing only by cosmetic image-resize query
// params — those params aren't part of what a --endpoint template actually
// needs to enumerate, and keeping them turned one real candidate into dozens
// of spurious "distinct" ones, each looking like a genuine ambiguity.
func idShapedPathCandidate(u *url.URL) (tmpl, concreteVal string, isUUID, ok bool) {
	segments := strings.Split(u.Path, "/")
	for i, seg := range segments {
		if !isIDShaped(seg) && !isSpecPathParam(seg) {
			continue
		}
		newSegments := append([]string(nil), segments...)
		newSegments[i] = "{{id}}"
		return strings.Join(newSegments, "/"), seg, uuidPattern.MatchString(seg), true
	}
	return "", "", false, false
}

// idShapedQueryCandidate requires the query key's own name to look
// ID-shaped (looksLikeIDKey), not just its value — a value-only check would
// treat any small integer as a candidate, including the same real target's
// image-resize params ("w=96", "h=48", "dpr=3") that motivated
// idShapedPathCandidate's fix above; those keys don't look like an
// identifier by name, so they're excluded before the value pattern is even
// checked.
func idShapedQueryCandidate(u *url.URL) (tmpl, concreteVal string, isUUID, ok bool) {
	if u.RawQuery == "" {
		return "", "", false, false
	}
	for _, pair := range strings.Split(u.RawQuery, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, rawVal := kv[0], kv[1]
		if !looksLikeIDKey(key) {
			continue
		}
		// LT-95 (docs/follow-up.md): a spec-documented but valueless query
		// param ("report_id=", the walker's own keyless-param encoding, see
		// specwalk.go) is still an identifier position by definition — the
		// same tolerance isSpecPathParam already gives a valueless *path*
		// "{id}" template, just for a query key instead.
		if rawVal == "" {
			return u.Path + "?" + strings.Replace(u.RawQuery, pair, key+"={{id}}", 1), "", false, true
		}
		val, err := url.QueryUnescape(rawVal)
		if err != nil || !isIDShaped(val) {
			continue
		}
		return u.Path + "?" + strings.Replace(u.RawQuery, pair, key+"={{id}}", 1), val, uuidPattern.MatchString(val), true
	}
	return "", "", false, false
}

// looksLikeIDKey reports whether key's own name suggests an object
// identifier ("id", "report_id", "userId") rather than an unrelated
// parameter that just happens to hold a small integer.
func looksLikeIDKey(key string) bool {
	return strings.Contains(strings.ToLower(key), "id")
}

// redirectFlowPathHints are lower-cased path substrings whose shape is a
// redirect / OAuth / SSO / logout flow — the classic open-redirect and
// OAuth-flow surface (`redirect_uri`, `return_to`, `RelayState` params).
// docs/follow-up.md LT-77: `/accounts/bounce` 302s to `/account`,
// `/oauth/authorize` + `/oauth/continue` are textbook candidates, but the
// decision engine had no rule mapping such a path to a redirect probe.
var redirectFlowPathHints = []string{
	"/oauth/authorize", "/oauth/continue", "/oauth2/authorize", "/connect/authorize",
	"/sso", "/saml", "/openid",
	"/bounce", "/callback", "/logout", "/signout", "/return", "/continue",
}

// IsRedirectFlowPath reports whether p (a URL path) looks like a redirect /
// OAuth / SSO / logout flow endpoint — the LT-77 surface the decision
// engine dispatches the generic open-redirect check against. Requires a
// plausible path first, so a JS fragment never matches.
func IsRedirectFlowPath(p string) bool {
	if !IsPlausibleURLPath(p) || IsStaticAssetPath(p) {
		return false
	}
	lp := strings.ToLower(p)
	for _, hint := range redirectFlowPathHints {
		if strings.HasSuffix(lp, hint) || strings.Contains(lp, hint+"/") || strings.Contains(lp, hint+"?") {
			return true
		}
	}
	return false
}

// redirectsToLoginBoundary reports whether ep is a 3xx whose redirect
// target looks like a login/sign-in page — LT-125's signal, checked against
// FinalURL (set by probeUnprobedEndpoints/analyzeRedirect) or, failing
// that, the last hop recorded in RedirectChain. A path recon never actually
// observed following anywhere (no FinalURL, no chain) can't be judged, so
// it returns false rather than guessing.
func redirectsToLoginBoundary(ep EndpointFact) bool {
	switch ep.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return false
	}
	dest := ep.FinalURL
	if dest == "" && len(ep.RedirectChain) > 0 {
		dest = ep.RedirectChain[len(ep.RedirectChain)-1]
	}
	if dest == "" {
		return false
	}
	lower := strings.ToLower(dest)
	return strings.Contains(lower, "login") || strings.Contains(lower, "signin") || strings.Contains(lower, "sign-in")
}

// SuggestAuthBypassPathsFromRecon buckets result's EndpointFacts into
// protected/login/logout path candidates for authbypass's own three config
// fields — extracted from pkg/webui's original private suggestPathsFromRecon
// (docs/15-implementation-plan-ph6.md Step 2) into this pkg/recon-agnostic
// form, the same way SuggestIDOREndpointCandidates/SuggestSSRFParamsFromRecon
// already are, so a future MCP tool can call it without a pkg/webui
// dependency. protected is the field that gates authbypass entirely when
// empty and none is hand-supplied (mirrors idor's EndpointTemplate miss);
// login/logout are supplementary and never block the detector on their own.
func SuggestAuthBypassPathsFromRecon(result *ReconResult) (protected, login, logout []string) {
	if result == nil {
		return nil, nil, nil
	}

	seenProtected, seenLogin, seenLogout := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var specProtected []string
	seenSpec := map[string]bool{}
	for _, ep := range result.Endpoints {
		path := endpointPath(ep.URL)
		if path == "" || looksLikeStaticAssetOrJunk(path) {
			continue
		}
		lower := strings.ToLower(path)
		switch {
		case ep.StatusCode == http.StatusUnauthorized || ep.StatusCode == http.StatusForbidden:
			if !seenProtected[path] {
				seenProtected[path] = true
				protected = append(protected, path)
			}
		case redirectsToLoginBoundary(ep):
			// LT-125: a redirect to a login page is the dominant
			// access-control shape for session-cookie apps (WordPress
			// /wp-admin/ -> wp-login.php, and most web apps generally) —
			// a 401/403-equivalent "should reject me" signal that the
			// switch above never saw. Must ship together with/after
			// LT-124's authbypass redirect-blindness fix: widening this
			// net without it would turn every correctly-secured
			// redirect-gated page into a guaranteed false "missing auth"
			// finding.
			if !seenProtected[path] {
				seenProtected[path] = true
				protected = append(protected, path)
			}
		case ep.Source == "api-spec" && ep.AuthRequired && !strings.Contains(path, "{"):
			// LT-90: the OpenAPI doc says this route needs auth. A
			// parameterless route is a direct "should reject me" probe for
			// checkMissingAuth; a {param} route has no id to invent, so it's
			// left to the idor path.
			if !seenSpec[path] {
				seenSpec[path] = true
				specProtected = append(specProtected, path)
			}
		case ep.Source == "wave3-auth-boundary-heuristic" || strings.Contains(lower, "login") || strings.Contains(lower, "signin"):
			if !seenLogin[path] {
				seenLogin[path] = true
				login = append(login, path)
			}
		case strings.Contains(lower, "logout") || strings.Contains(lower, "signout"):
			if !seenLogout[path] {
				seenLogout[path] = true
				logout = append(logout, path)
			}
		}
	}
	// LT-90: append the spec-declared auth routes after any observed 401/403
	// ones, sorted for determinism and capped so a large spec can't balloon
	// the tokenless-probe count. A path already recorded from an observed
	// 401/403 is skipped (that status is the stronger signal).
	sort.Strings(specProtected)
	if len(specProtected) > maxSpecAuthProtectedPaths {
		specProtected = specProtected[:maxSpecAuthProtectedPaths]
	}
	for _, p := range specProtected {
		if !seenProtected[p] {
			seenProtected[p] = true
			protected = append(protected, p)
		}
	}
	return protected, login, logout
}

// endpointPath extracts rawURL's path, "" on a malformed URL (skipped by
// SuggestAuthBypassPathsFromRecon's caller).
func endpointPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}

// staticAssetExtensions are front-end build-artifact extensions that are
// never meaningful authbypass candidates, regardless of what HTTP status
// katana happened to observe for them — a bundler chunk isn't a
// "protected resource" in the sense this heuristic looks for, even when a
// bot-protection layer 401/403s crawl requests against it. Found live,
// 2026-09-03: a real target's static JS bundles dominated
// SuggestAuthBypassPathsFromRecon's protected-path output the first time
// runKatana's StatusCode decoding fix (see crawl.go) actually populated
// that bucket at scale.
var staticAssetExtensions = map[string]bool{
	".js": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
}

// IsStaticAssetPath reports whether p (a URL path) ends in a front-end
// build-artifact extension — a bundler/CDN output file, never a meaningful
// application route or API endpoint regardless of what status code it
// returned. Exported for pkg/webui's Endpoints table (recon_view.go),
// which uses this narrower, extension-only check to declutter the display
// without pkg/webui's own suite of unrelated failure modes; kept separate
// from looksLikeStaticAssetOrJunk's own "too degenerate to be a real
// candidate" half below, which would wrongly also flag a bare "/" (the
// homepage root — real signal, not noise) as junk. Uses the "path"
// package, not "path/filepath" — these are URL paths (forward-slash), not
// OS paths.
func IsStaticAssetPath(p string) bool {
	return staticAssetExtensions[strings.ToLower(path.Ext(p))]
}

// dynamicScriptWrapperExts are server-side-script extensions that, when
// they wrap a static-asset name (lib_head.js.php, style.css.php), mark a
// generated/concatenated asset rather than an application route. On
// jQuery/Dolibarr-style stacks katana surfaces a lot of these by
// following minified-JS string literals as if they were links (LT-117). A
// bare "/report.php" with no inner asset extension is NOT matched — that's
// a real endpoint.
var dynamicScriptWrapperExts = map[string]bool{
	".php": true, ".asp": true, ".aspx": true, ".jsp": true, ".jspx": true,
	".cfm": true, ".cgi": true, ".ashx": true, ".pl": true,
}

// dependencyTreeSegments are path fragments that only ever appear inside a
// package-manager download tree or a front-end build-output directory —
// never a hand-authored application route. Matched as substrings of the
// lower-cased path.
var dependencyTreeSegments = []string{
	"/node_modules/", "/bower_components/", "/dist/js/", "/dist/css/",
}

// derivedAssetPath reports whether p is a build/vendor artifact that
// IsStaticAssetPath's plain-extension check misses (LT-117): a
// server-script wrapper over a static asset (foo.js.php, style.css.php), or
// a path inside a dependency-manager / build-output subtree
// (node_modules/, bower_components/, dist/js/, dist/css/). High-precision
// by construction — each pattern is one that has no legitimate
// application-route meaning.
func derivedAssetPath(p string) bool {
	lower := strings.ToLower(p)
	for _, seg := range dependencyTreeSegments {
		if strings.Contains(lower, seg) {
			return true
		}
	}
	if outer := strings.ToLower(path.Ext(p)); dynamicScriptWrapperExts[outer] {
		inner := strings.ToLower(path.Ext(strings.TrimSuffix(p, path.Ext(p))))
		if staticAssetExtensions[inner] {
			return true
		}
	}
	return false
}

// IsNonRouteAssetPath is IsStaticAssetPath widened with derivedAssetPath's
// build/vendor cases (LT-117) — used by pkg/webui's Endpoints table to keep
// katana's minified-JS-literal noise (foo.js.php, node_modules/…, dist/js/…)
// out of the displayed rows, folding it into the "static asset omitted"
// count instead. The candidate suggesters deliberately use the narrower
// IsStaticAssetPath plus their own guarded derivedAssetPath check, since a
// *.js.php carrying a real id query param can still be a live target.
func IsNonRouteAssetPath(p string) bool {
	return IsStaticAssetPath(p) || derivedAssetPath(p)
}

// looksLikeStaticAssetOrJunk reports whether p is a front-end build
// artifact (by extension) or too degenerate to be a real candidate (no
// alphanumeric content at all — e.g. the lone "/\" a crawler occasionally
// surfaces from a malformed page reference). Only used by
// SuggestAuthBypassPathsFromRecon, whose narrower "protected-path
// candidate" semantics can afford to also drop a bare "/" — unlike
// IsStaticAssetPath above, which the Endpoints table display uses and
// which must keep it.
func looksLikeStaticAssetOrJunk(p string) bool {
	if IsStaticAssetPath(p) || derivedAssetPath(p) {
		return true // LT-117: also a *.js.php wrapper or a node_modules/dist tree file
	}
	if !hasAlphanumeric(p) {
		return true
	}
	// A JavaScript-syntax fragment ("/library/ideabox/'+e.query...") has
	// alphanumeric content but is not a real path (LT-85).
	return !IsPlausibleURLPath(p)
}

func hasAlphanumeric(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// ssrfParamKeywords is the small, hand-authored curated table
// docs/14-implementation-plan-ph5.md Step 7 specifies — the same
// "small curated table" shape pkg/registry's techRules and
// pkg/detectors/misconfig's MissingHeaders already use, not a novel
// mechanism.
var ssrfParamKeywords = map[string]bool{
	"url": true, "uri": true, "link": true, "redirect": true, "return": true,
	"next": true, "callback": true, "webhook": true, "target": true,
	"dest": true, "continue": true, "src": true, "img": true, "image": true,
	"avatar": true, "feed": true, "host": true, "domain": true, "path": true,
}

// SuggestSSRFParamsFromRecon matches query-parameter keys observed across
// result's EndpointFacts against ssrfParamKeywords. Standalone and unit-
// tested per doc14 Step 7, not currently wired into any Web UI tab — ssrf
// isn't one of the Launch page's three detector tabs, a named, separate scope
// call from this function's own existence.
func SuggestSSRFParamsFromRecon(result *ReconResult) []string {
	if result == nil {
		return nil
	}

	seen := map[string]bool{}
	var params []string
	for _, ep := range result.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		for _, pair := range strings.Split(u.RawQuery, "&") {
			key := strings.SplitN(pair, "=", 2)[0]
			if key == "" || seen[key] {
				continue
			}
			if ssrfParamKeywords[strings.ToLower(key)] {
				seen[key] = true
				params = append(params, key)
			}
		}
	}
	return params
}

// SQLiTarget pairs one concrete, already-observed path+query (scheme+host
// stripped — same contract as scanner.Config.EndpointTemplate/
// SuggestIDOREndpointCandidates, joined onto a target later by
// pkg/scanner/engine.go's runDetector) with the query-parameter names on it
// recon judges worth testing for SQL injection
// (docs/18-implementation-plan-ph9.md Step 4) — the same ID-/value-shaped
// param surface idorCandidatesAndSeeds already mines for IDOR, since both
// vulnerability classes share it: a parameter that carries a database ID is
// exactly where a SQL query's WHERE clause is built from untrusted input.
type SQLiTarget struct {
	Path   string
	Params []string
}

// SuggestSQLiTargets walks result's EndpointFacts for query parameters
// worth SQLi-testing, grouped by path so one Target carries every candidate
// param for that route. Two signals, same discipline idorCandidatesAndSeeds
// already applies:
//
//   - an ID-named key ("id", "report_id") holding an ID-shaped value — a
//     single observation is enough, since the key's own name already
//     signals intent (idShapedQueryCandidate's rule);
//   - LT-83's unnamed-numeric-key signal (numericQueryIDCandidates): a
//     value that varies across >= 2 distinct observations on the same path
//     even when the key name gives no hint ("article", "topic").
//
// Each returned Target.Path is one representative path+query observed for
// that route — good enough to mutate one param at a time from (sqli.Detector
// never needs more than one base request per path).
func SuggestSQLiTargets(result *ReconResult) []SQLiTarget {
	if result == nil {
		return nil
	}

	type target struct {
		pathQuery string
		params    map[string]bool
	}
	targets := map[string]*target{}
	var order []string
	get := func(p, repPathQuery string) *target {
		t, ok := targets[p]
		if !ok {
			t = &target{pathQuery: repPathQuery, params: map[string]bool{}}
			targets[p] = t
			order = append(order, p)
		}
		return t
	}

	for _, ep := range result.Endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || u.RawQuery == "" {
			continue
		}
		p := u.Path
		if IsStaticAssetPath(p) || !IsPlausibleURLPath(p) {
			continue
		}
		for _, pair := range strings.Split(u.RawQuery, "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 || kv[0] == "" {
				continue
			}
			val, err := url.QueryUnescape(kv[1])
			if err != nil || !looksLikeIDKey(kv[0]) || !isIDShaped(val) {
				continue
			}
			get(p, p+"?"+u.RawQuery).params[kv[0]] = true
		}
	}
	for _, tmpl := range numericQueryIDCandidates(result.Endpoints) {
		parts := strings.SplitN(tmpl, "?", 2)
		if len(parts) != 2 {
			continue
		}
		p, key := parts[0], strings.TrimSuffix(parts[1], "={{id}}")
		repPathQuery := firstQueryPathForPath(result.Endpoints, p)
		if repPathQuery == "" {
			continue
		}
		get(p, repPathQuery).params[key] = true
	}

	var out []SQLiTarget
	for _, p := range order {
		t := targets[p]
		params := make([]string, 0, len(t.params))
		for k := range t.params {
			params = append(params, k)
		}
		sort.Strings(params)
		out = append(out, SQLiTarget{Path: t.pathQuery, Params: params})
	}
	return out
}

// firstQueryPathForPath returns the first observed "path?query" (scheme+
// host stripped) whose path is p and which carries a query string, "" if
// none.
func firstQueryPathForPath(endpoints []EndpointFact, p string) string {
	for _, ep := range endpoints {
		u, err := url.Parse(ep.URL)
		if err == nil && u.Path == p && u.RawQuery != "" {
			return p + "?" + u.RawQuery
		}
	}
	return ""
}

// SuggestSSRFBodyParamsFromRecon matches EndpointFact.BodyParamKeys entries
// (populated only from an api-spec fact's requestBody schema, see
// walkOpenAPISpec) against ssrfParamKeywords — LT-96, docs/follow-up.md's
// fix for a real live-observed miss (crAPI's contact_mechanic takes the
// attacker URL in a JSON body field, not a query param). Unlike
// SuggestSSRFParamsFromRecon's exact-key lookup, this matches by substring:
// a real body field name is typically compound ("mechanic_api",
// "repair_url", "webhook_endpoint") rather than a bare "url"/"redirect".
func SuggestSSRFBodyParamsFromRecon(result *ReconResult) []string {
	if result == nil {
		return nil
	}

	seen := map[string]bool{}
	var params []string
	for _, ep := range result.Endpoints {
		for _, key := range ep.BodyParamKeys {
			if seen[key] {
				continue
			}
			lower := strings.ToLower(key)
			for keyword := range ssrfParamKeywords {
				if strings.Contains(lower, keyword) {
					seen[key] = true
					params = append(params, key)
					break
				}
			}
		}
	}
	return params
}
