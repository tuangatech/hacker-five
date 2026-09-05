package recon

import (
	"net/url"
	"regexp"
	"strings"
)

// wpPluginPathPattern matches a wp-content plugin or theme asset path
// ("/wp-content/plugins/contact-form-7/includes/js/scripts.js") and
// captures the slug — the directory name WordPress.org itself uses to
// identify the plugin/theme, and the same string the synced corpus tags
// its plugin-specific templates with (verified against the real 7,716-
// entry templates/index.json, 2026-09-04: "contact-form-7",
// "litespeed-cache", "wp-fastest-cache", "elementor", "woocommerce",
// "wordfence" all confirmed tagged by this literal slug).
var wpPluginPathPattern = regexp.MustCompile(`/wp-content/(?:plugins|themes)/([a-zA-Z0-9._-]+)/`)

// wpVersionShapePattern guards against LT-21 (docs/follow-up.md, 2026-09-04):
// a "?ver=" value isn't always a real version — WordPress's own
// wp_enqueue_script/style convention lets a plugin pass any cache-busting
// string, and WooCommerce Blocks' own asset bundler confirmed live to pass a
// content hash there instead ("?ver=a02cc7ababe22e5abaaf"). Accepting that
// verbatim produced a TechFact silently contradicting the correct,
// httpx-sourced version fact for the same plugin on the same host. A
// version-shaped value is plain dot-separated digits (WordPress.org's own
// plugin version convention, "1", "2.5", "6.1.1.2" — no semver
// pre-release/build suffixes observed on real plugin readme.txt "Stable
// tag:" values); anything else is dropped, not guessed — an unversioned
// fact (name == slug alone) is strictly better than a wrong one, per this
// function's own doc comment below.
var wpVersionShapePattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+){0,3}$`)

// wordPressPluginFacts scans endpoints — already-crawled URLs, no new
// network round trip — for wp-content plugin/theme asset paths and returns
// one TechFact per distinct (host, slug), versioned from that same URL's
// "?ver=" cache-bust query parameter when present (WordPress's own
// wp_enqueue_script/style convention appends it automatically, so it's
// already sitting in Wave 3's crawl output on most real WordPress sites —
// confirmed live, 2026-09-04: andertone.com's own crawl carried 7 distinct
// plugin slugs with versions this way with zero extra requests).
//
// Deliberately narrower than docs/follow-up.md's original P1-3 text, which
// also named readme.txt/style.css version *probes* — an active fetch this
// function does not perform. That's real, separate follow-up work (a new
// probe, not a parse of data already collected) rather than a P1
// "turn recon signal into leaves" pass; logged, not silently dropped, in
// docs/follow-up.md.
//
// A slug observed without a "?ver=" value anywhere still produces an
// unversioned TechFact (name == slug) — matchTemplateTags' stale-CVE
// penalty only applies when a version is present (P0-1a), so an
// unversioned plugin fact still ranks CVE templates normally, just without
// that recency-vs-version nuance. Name uses the flat "<slug>:<version>"
// shape (not "wp-plugin:<slug>:<version>") deliberately: NormalizeTechName
// splits on the first ':' only, so a second colon would truncate the slug
// itself down to the literal "wp-plugin" and lose the product identity.
func wordPressPluginFacts(endpoints []EndpointFact) []TechFact {
	type pluginKey struct{ host, slug string }
	var order []pluginKey
	seenKey := map[pluginKey]bool{}
	versions := map[pluginKey]string{} // "" until a versioned occurrence is found

	for _, ep := range endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		m := wpPluginPathPattern.FindStringSubmatch(u.Path)
		if m == nil {
			continue
		}
		k := pluginKey{host: u.Hostname(), slug: strings.ToLower(m[1])}
		if !seenKey[k] {
			seenKey[k] = true
			order = append(order, k)
		}
		if versions[k] == "" {
			if ver := u.Query().Get("ver"); ver != "" && wpVersionShapePattern.MatchString(ver) {
				versions[k] = ver
			}
		}
	}

	facts := make([]TechFact, 0, len(order))
	for _, k := range order {
		name := k.slug
		if v := versions[k]; v != "" {
			name += ":" + v
		}
		facts = append(facts, TechFact{
			Name:       name,
			Host:       k.host,
			Source:     "recon-wp-plugin-path",
			Confidence: ConfidenceMedium,
		})
	}
	return facts
}
