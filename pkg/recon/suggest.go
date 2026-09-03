package recon

import (
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

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
	if result == nil {
		return nil
	}

	seen := map[string]bool{}
	var candidates []string
	for _, ep := range result.Endpoints {
		tmpl, ok := idShapedCandidate(ep.URL)
		if !ok || seen[tmpl] {
			continue
		}
		seen[tmpl] = true
		candidates = append(candidates, tmpl)
	}
	return candidates
}

// idShapedCandidate returns the {{id}}-templated path(+query) for rawURL, if
// any — an ID-shaped path segment first, else an ID-shaped query value whose
// key name itself suggests an identifier.
func idShapedCandidate(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}

	if tmpl, ok := idShapedPathCandidate(u); ok {
		return tmpl, true
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
func idShapedPathCandidate(u *url.URL) (string, bool) {
	segments := strings.Split(u.Path, "/")
	for i, seg := range segments {
		if !isIDShaped(seg) {
			continue
		}
		newSegments := append([]string(nil), segments...)
		newSegments[i] = "{{id}}"
		return strings.Join(newSegments, "/"), true
	}
	return "", false
}

// idShapedQueryCandidate requires the query key's own name to look
// ID-shaped (looksLikeIDKey), not just its value — a value-only check would
// treat any small integer as a candidate, including the same real target's
// image-resize params ("w=96", "h=48", "dpr=3") that motivated
// idShapedPathCandidate's fix above; those keys don't look like an
// identifier by name, so they're excluded before the value pattern is even
// checked.
func idShapedQueryCandidate(u *url.URL) (string, bool) {
	if u.RawQuery == "" {
		return "", false
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
		val, err := url.QueryUnescape(rawVal)
		if err != nil || !isIDShaped(val) {
			continue
		}
		return u.Path + "?" + strings.Replace(u.RawQuery, pair, key+"={{id}}", 1), true
	}
	return "", false
}

// looksLikeIDKey reports whether key's own name suggests an object
// identifier ("id", "report_id", "userId") rather than an unrelated
// parameter that just happens to hold a small integer.
func looksLikeIDKey(key string) bool {
	return strings.Contains(strings.ToLower(key), "id")
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

// looksLikeStaticAssetOrJunk reports whether p is a front-end build
// artifact (by extension) or too degenerate to be a real candidate (no
// alphanumeric content at all — e.g. the lone "/\" a crawler occasionally
// surfaces from a malformed page reference). Uses the "path" package, not
// "path/filepath" — these are URL paths (forward-slash), not OS paths.
func looksLikeStaticAssetOrJunk(p string) bool {
	if staticAssetExtensions[strings.ToLower(path.Ext(p))] {
		return true
	}
	return !hasAlphanumeric(p)
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
