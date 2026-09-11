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

// sanitizeWordPressCoreVersion drops a "WordPress" core TechFact's version
// suffix when it exactly matches a plugin/theme version pluginFacts (this
// same wordPressPluginFacts pass) separately recorded for the same host —
// LT-105 (docs/follow-up.md): a live-observed httpx-tech-detect failure
// mode where its embedded fingerprint catalog occasionally attributes a
// bundled asset's or plugin's version to the WordPress *core* product fact
// instead (real example: "WordPress:7.1" — WordPress core has never shipped
// a 7.x release; every real WordPress.org release to date is still on the
// 6.x line). Left uncaught, that poisoned core version would have fed
// straight into Phase 8 Step 4's affected-range gate and wrongly dropped
// wordpress-eol.yaml-style templates (a genuinely old, genuinely EOL core
// install misreported as implausibly new).
//
// Rather than a hardcoded plausibility ceiling on WordPress's version
// number (fragile — it ages out every time WordPress ships a new release),
// this checks for the bug's own described mechanism directly: does the
// core fact's version exactly match a version this SAME pass independently
// attributed to a plugin/theme slug on the same host? An unversioned
// "WordPress" fact is strictly safer than a wrong one — matchTemplateTags'
// affected-range gate (versionInAffectedRange) already treats "no
// fingerprinted version" as "can't rule a template out", the identical
// posture this function's own sibling (wordPressPluginFacts, above) already
// takes for an individual plugin with no trustworthy version.
func (a *aggregator) sanitizeWordPressCoreVersion(pluginFacts []TechFact) {
	suspect := make(map[string]map[string]bool) // NormalizeHost(host) -> version -> true
	for _, f := range pluginFacts {
		i := strings.IndexByte(f.Name, ':')
		if i < 0 {
			continue
		}
		host := NormalizeHost(f.Host)
		if suspect[host] == nil {
			suspect[host] = map[string]bool{}
		}
		suspect[host][f.Name[i+1:]] = true
	}
	if len(suspect) == 0 {
		return
	}

	for i := range a.techStack {
		t := &a.techStack[i]
		if techProductKey(t.Name) != "wordpress" {
			continue
		}
		ci := strings.IndexByte(t.Name, ':')
		if ci < 0 {
			continue
		}
		version := t.Name[ci+1:]
		if suspect[NormalizeHost(t.Host)][version] {
			t.Name = t.Name[:ci]
			a.addWarning("wave3: %s: WordPress core version %q matches a plugin/theme's own version — likely an httpx tech-detect misattribution, dropped rather than trusted (LT-105)", t.Host, version)
		}
	}
}
