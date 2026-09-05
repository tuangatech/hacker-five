package registry

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// maxTemplateLeavesPerTech bounds how many template-tag-matched leaves one
// TechFact can produce. Raised 5 -> 8 alongside P0-2's ranked selection
// (2026-09-04): the old cap paired with first-in-file-order selection, so a
// low number was pure damage control against arbitrary matches; the entries
// kept now are the highest-scoring (exact-tag + severity + CVE recency), so
// a slightly wider window surfaces more genuinely-relevant templates
// without reintroducing noise. Cross-fact duplicates still collapse via
// leafDedupKey, so in practice this is a per-(host, template) ceiling.
const maxTemplateLeavesPerTech = 8

// cveRecencyBaseYear is the pivot for matchTemplateTags' CVE-recency score
// component: a CVE-YYYY template scores (YYYY - this) * cveRecencyWeight
// when YYYY is at or after it, so a 2024 CVE outranks a 2017 one for the
// same product/severity. Chosen to sit below the bulk of the synced
// corpus's CVE mass while still spreading modern years apart. Bump it
// forward every few years so the spread stays meaningful.
const (
	cveRecencyBaseYear = 2016
	cveRecencyWeight   = 4
	// staleCVEPenalty is applied to a pre-cveRecencyBaseYear CVE template
	// only when the TechFact carried an explicit version — a current-looking
	// version is very unlikely to be affected by a decade-plus-old CVE, but
	// recon's version can be wrong or spoofed, so this deprioritizes rather
	// than drops (CLAUDE.md: "flag doubtful matchers instead of guessing").
	// True affected-version gating waits on an index schema that carries
	// version ranges (docs/follow-up.md P0-1b / P1-4).
	staleCVEPenalty = 20
)

// techRule maps a case-insensitive substring of a TechFact.Name to the
// registry Capability names it should dispatch — the deterministic
// tech-signature-to-plan lookup doc90's Decision 6/I3 specifies. Small and
// hand-authored on purpose: an unmatched TechFact becomes a visible
// unresolved leaf (Decision 6), not a guess.
type techRule struct {
	Match        string
	Capabilities []string
}

var techRules = []techRule{
	{Match: "php", Capabilities: []string{"misconfig"}},
	{Match: "wordpress", Capabilities: []string{"misconfig"}},
	{Match: "mysql", Capabilities: []string{"misconfig"}},
	{Match: "postgresql", Capabilities: []string{"misconfig"}},
	{Match: "mongodb", Capabilities: []string{"misconfig"}},
	{Match: "redis", Capabilities: []string{"misconfig"}},
	{Match: "phpmyadmin", Capabilities: []string{"misconfig"}},
	{Match: "swagger", Capabilities: []string{"misconfig", "idor"}},
	{Match: "graphql", Capabilities: []string{"misconfig", "idor"}},
	{Match: "openresty", Capabilities: []string{"idor", "authbypass", "misconfig"}},
	{Match: "nginx", Capabilities: []string{"misconfig"}},
	{Match: "apache", Capabilities: []string{"misconfig"}},
	{Match: "express", Capabilities: []string{"idor", "authbypass", "misconfig"}},
	{Match: "django", Capabilities: []string{"misconfig"}},
	{Match: "iis", Capabilities: []string{"misconfig"}},
	{Match: "litespeed", Capabilities: []string{"misconfig"}},
	{Match: "woocommerce", Capabilities: []string{"misconfig"}},
}

// apiSpecTechName maps an APISpecFact.Kind to the techRules tech name whose
// capabilities/template-tag matching resolveAPISpecFact reuses (LT-3,
// docs/follow-up.md): an APISpecFact is a stronger-than-usual signal for
// exactly the same tech a fingerprint would otherwise guess at from a UI
// page (e.g. "Swagger UI" via fingerprint's swagger-ui body match), so it
// earns identical dispatch — not a second, bespoke rule to keep in sync by
// hand. An unlisted Kind produces no leaves, not a guess.
var apiSpecTechName = map[string]string{
	"openapi":     "swagger",
	"graphql-sdl": "graphql",
}

// businessLogicPathKeywords are endpoint-path substrings (case-insensitive)
// suggesting a coupon/cart/checkout flow exists — enough signal to surface
// a businesslogic leaf worth a human's --allow-writes decision, not enough
// to auto-derive real mint/apply paths for a non-crAPI target (P1-1,
// docs/follow-up.md). businesslogic's own checks stay hardcoded to
// --coupon-mint-path/--coupon-apply-path (or crAPI's defaults) either way —
// deriving real mutating-request paths from a heuristic is exactly the kind
// of guess CLAUDE.md's write-safety rule warns against, so this only
// decides whether the leaf appears at all, gated at execution time by
// missingRequiredField (pkg/mcpserver/executor.go) on --allow-writes and an
// auth token, neither of which recon can supply or should auto-enable.
var businessLogicPathKeywords = []string{"cart", "checkout", "coupon", "add-to-cart", "promo"}

func looksLikeCouponOrCartFlow(path string) bool {
	lower := strings.ToLower(path)
	for _, kw := range businessLogicPathKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// endpointSignal ties a directly-observed endpoint signature to specific
// synced-template IDs — stronger evidence than a tag match, since it
// confirms the exact behavior the template checks for (P1-1,
// docs/follow-up.md), rather than inferring plausibility from a tag like
// "wordpress" shared with hundreds of unrelated CVE templates that can
// crowd an info-severity fingerprint template out of matchTemplateTags' own
// top-N ranking (docs/15-implementation-plan-ph6.md Step 2's Batch 2
// addendum hit exactly this: wordpress-user-enum outranked by real CVEs on
// a real target). A signal whose template ID isn't present in
// templateIndex is silently skipped — the synced corpus this install has
// may not carry it. IDs verified against the real synced corpus, 2026-09-04.
type endpointSignal struct {
	pathSubstr  string
	templateIDs []string
}

var endpointSignals = []endpointSignal{
	{pathSubstr: "xmlrpc.php", templateIDs: []string{"wordpress-xmlrpc-detect", "wordpress-xmlrpc-listmethods"}},
	{pathSubstr: "wp-json/wp/v2/users", templateIDs: []string{"wordpress-user-enum"}},
}

// interestingPorts is a small, hand-authored table of non-HTTP service
// ports worth surfacing when naabu finds one open (P1-2, docs/follow-up.md)
// — real recon signal that currently goes entirely unused downstream of a
// single low-confidence fingerprint-port TechFact. Deliberately produces
// only a visible StatusUnresolved leaf, never a dispatched one: no built-in
// detector or loadable template can check any of these today —
// pkg/template/nuclei/loader.go's disallowedBlocks hard-rejects any
// template with a top-level tcp:/network: block at load time, so the
// entire class of templates that could test "anonymous FTP" or "unauth
// Redis" is unloadable in this codebase, not just currently unmatched. A
// real TCP-capable detector is tracked separately (follow-up.md's
// "Detection Coverage — TCP" row) — this is visibility only, closing the
// gap for an MCP client, whose planOutput carries no raw ReconResult and
// so has no other way to see an open port at all (the Web UI's own Hosts
// table already shows this for a human operator).
//
// Known, accepted cost: an unresolved leaf reaches
// llmfallback.ResolveTreeLeaves like any other, which fires a real
// (frontier-tier, if no local tier is configured) LLM call per leaf even
// though a port leaf can never resolve into anything real — accepted
// deliberately rather than adding a new PlanNodeStatus to exclude it, per
// the explicit 2026-09-04 scoping call (docs/follow-up.md).
var interestingPorts = map[int]string{
	21:    "ftp",
	23:    "telnet",
	3306:  "mysql",
	5432:  "postgresql",
	6379:  "redis",
	9200:  "elasticsearch",
	27017: "mongodb",
}

// hostnameProductHints maps a first-DNS-label token (lowercased, trailing
// digits stripped — so "guacamole01" -> "guacamole") to a tech name whose
// registry capabilities / template tags are worth dispatching even when no
// TechFact fingerprinted that product on the host. LT-9 (docs/follow-up.md,
// 2026-09-04): a real target's `guacamole01.*` host literally names Apache
// Guacamole and the synced corpus carries `apache-guacamole`/
// `guacamole-default-login` templates, but nothing tried them — recon never
// got a fingerprint (the host was behind an internal cert, see LT-4) and no
// other signal reached the decision engine.
//
// Deliberately keyed on an exact first-label token match, not a substring:
// "guacamole01.corp" hits, "myjira-notes.corp" does not. Every entry is a
// product with unambiguous naming and real product-specific templates in the
// corpus; a hint leaf is ConfidenceLow (a hostname is weaker evidence than a
// live fingerprint) and dedups against any real TechFact-driven leaf for the
// same (host, capability) via pendingDedupKey.
var hostnameProductHints = map[string]string{
	"guacamole":  "guacamole",
	"jenkins":    "jenkins",
	"gitlab":     "gitlab",
	"grafana":    "grafana",
	"kibana":     "kibana",
	"jira":       "jira",
	"confluence": "confluence",
	"phpmyadmin": "phpmyadmin",
	"sonarqube":  "sonarqube",
	"portainer":  "portainer",
	"prometheus": "prometheus",
}

// hostnameProductHint returns the tech name hostnameProductHints associates
// with host's first DNS label (trailing digits stripped), or "" if none.
func hostnameProductHint(host string) string {
	label := host
	if i := strings.IndexByte(label, '.'); i >= 0 {
		label = label[:i]
	}
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.TrimRight(label, "0123456789")
	label = strings.TrimRight(label, "-_")
	return hostnameProductHints[label]
}

// nonActionableTech is a small denylist of TechFact names that should
// produce no PlanTree leaf at all — not even a visible unresolved one.
// Each entry is either a transport/protocol fact ("HTTP/2", "HTTP/3"), a
// security-posture fact the misconfig detector already checks directly
// ("HSTS" — see checkMissingHeaders' Strict-Transport-Security rule), a
// hosting/CDN brand that names no scannable product surface of its own
// ("Hostinger", "Google Cloud"), or a sub-component fully covered by a
// broader sibling fact ("WordPress Block Editor" — the plain "WordPress"
// fact already drives every check it would). Without this, a real recon
// pass against andertone.com produced a cluster of unresolved leaves and
// duplicate misconfig leaves purely from facts nothing downstream can act
// on (docs/follow-up.md P0-5, 2026-09-04).
//
// Matched on the normalized (version-stripped, lower-cased, trimmed) whole
// name via NormalizeTechName — deliberately NOT a substring check, which
// would over-reach (e.g. a "Google Cloud" entry must not also silence a
// hypothetical "Google Cloud Storage" bucket-exposure finding). Keep this
// list short and every entry justified; when in doubt leave a fact in, so
// it surfaces as an inspectable unresolved leaf rather than vanishing.
var nonActionableTech = map[string]bool{
	"http/2":                 true,
	"http/3":                 true,
	"hsts":                   true,
	"wordpress block editor": true,
	"hostinger":              true,
	"hostinger cdn":          true,
	"google cloud":           true,
	"google cloud cdn":       true,
	// LT-10 (docs/follow-up.md, 2026-09-04): a client-side analytics tag
	// (Google Analytics / GA / gtag.js) names no scannable server surface of
	// its own — left in, it matched 3 keyword-collision templates
	// (piwik-unauthenticated-access / sonicwall-analytics-panel /
	// versa-analytics-server) purely on the shared "analytics" tag word.
	"google analytics":   true,
	"google tag manager": true,
}

// tagQuery pins a tech name to the template tag(s) that actually mean
// "this product", plus the tag(s) / ID substrings that disqualify a
// template even when an include tag also matched.
type tagQuery struct {
	include         []string // a template carrying any of these tags is a candidate
	exclude         []string // ...unless it also carries one of these tags
	excludeIDSubstr []string // ...or its ID contains one of these substrings (for false friends the corpus tags with the bare product tag anyway)
}

// canonicalTechTags overrides matchTemplateTags' generic word-level tag
// match for names where that match is demonstrably wrong. Without it, a
// real andertone.com pass tied "Nginx" to ingress-nginx / nginx-proxy-
// manager CVEs, and "jQuery" to a jquery-file-upload plugin RCE — unrelated
// templates whose tags merely share a word (docs/follow-up.md P0-2,
// 2026-09-04). Deliberately small: only the observed false-friend cases
// plus a few unambiguous single-product pins. A name absent here falls
// back to the generic-word-filtered path in matchTemplateTags. (Pure
// hosting/CDN brands like "Google Cloud" / "Hostinger CDN" need no entry —
// nonActionableTech already drops them before matching.)
// Exclude/excludeIDSubstr values below are verified against the real synced
// corpus's tags/IDs (2026-09-04), not guessed: nginx-proxy-manager is
// tagged "proxy-manager" (not "nginx-proxy-manager"); the jQuery-File-
// Upload plugin templates carry a bare "jquery" tag with "jquery-file-
// upload" only in the ID; several product-specific templates (eSafeNet,
// Eventum, Weaver/Fanwei OA, Odoo) are tagged "mysql" despite not being
// MySQL-server issues.
var canonicalTechTags = map[string]tagQuery{
	// LT-19 (docs/follow-up.md, 2026-09-04): "ingress-nginx"/"proxy-manager"
	// were never real corpus tags — both no-ops, confirmed live: 4
	// Kubernetes Ingress-Nginx-Controller CVEs (real tags include "ingress",
	// "kubernetes", "k8s", none of them "ingress-nginx") outranked genuine
	// Nginx templates against a plain Nginx web-server TechFact.
	// nginx-proxy-manager's real tags are ["panel","nginx","proxy",
	// "discovery"] — no "proxy-manager" tag either, so that exclusion moved
	// to excludeIDSubstr (its ID does contain "proxy-manager"), mirroring
	// the jquery entry's own established pattern below.
	"nginx":       {include: []string{"nginx"}, exclude: []string{"ingress", "kubernetes", "k8s", "nginxwebui"}, excludeIDSubstr: []string{"proxy-manager"}},
	"jquery":      {include: []string{"jquery"}, exclude: []string{"file-upload"}, excludeIDSubstr: []string{"jquery-file-upload"}},
	"mysql":       {include: []string{"mysql"}, exclude: []string{"esafenet", "eventum", "weaver", "ecology", "fanwei", "odoo"}},
	"wordpress":   {include: []string{"wordpress"}},
	"woocommerce": {include: []string{"woocommerce"}},
	"litespeed":   {include: []string{"litespeed"}},
}

// genericTechWords are words that carry no product identity on their own —
// a tag match on just one of these ("cloud", "editor", "server") is noise,
// not a signal. matchTemplateTags drops them from a multi-word name's
// match set and never lets one be the "primary" (product) word.
var genericTechWords = map[string]bool{
	"http": true, "https": true, "web": true, "server": true, "client": true,
	"cloud": true, "cdn": true, "proxy": true, "gateway": true, "api": true,
	"app": true, "application": true, "core": true, "plugin": true, "theme": true,
	"module": true, "extension": true, "addon": true, "block": true, "editor": true,
	"cache": true, "caching": true, "js": true, "ui": true, "cms": true,
	"framework": true, "platform": true, "service": true, "manager": true,
	"management": true, "console": true, "dashboard": true, "portal": true,
	"google": true, "amazon": true, "aws": true, "azure": true, "microsoft": true,
	"oracle": true, "ibm": true, "adobe": true, "cloudflare": true,
}

var cveYearPattern = regexp.MustCompile(`(?i)CVE-(\d{4})-\d+`)

// matchTechRules returns every registry Capability name techRules maps
// techName to, case-insensitive substring match.
func matchTechRules(techName string) []string {
	lower := strings.ToLower(techName)
	var caps []string
	for _, rule := range techRules {
		if strings.Contains(lower, rule.Match) {
			caps = append(caps, rule.Capabilities...)
		}
	}
	return caps
}

// matchTemplateTags returns up to maxTemplateLeavesPerTech template entries
// relevant to techName, best first — R9's template index consumed by the
// decision engine (doc14 Step 3's R8 text).
//
// Selection (P0-2, 2026-09-04) replaced the original "first
// maxTemplateLeavesPerTech entries in file order whose tags share any word
// with the normalized name". That over-matched on generic words and, worse,
// surfaced whatever happened to sit early in the index file rather than the
// most relevant template. Now every entry that ties to the tech at all is
// scored — exact product-tag hit > any tag/word hit > ID/Name token hit,
// plus severity and CVE-recency weight, minus a stale-CVE penalty when a
// known version makes a decade-old CVE implausible (P0-1a) — then the top
// maxTemplateLeavesPerTech are returned. canonicalTechTags pins the tag set
// for names whose word match is known-wrong; everything else uses the
// generic-word-filtered word set. index may be nil (R9 index not generated
// yet) — returns nil, matching Resolve's documented soft-degrade.
func matchTemplateTags(techName string, index []templatesync.Entry) []templatesync.Entry {
	normalized := NormalizeTechName(techName)
	version := techVersionSuffix(techName)

	q, canonical := canonicalTechTags[normalized]
	var matchWords map[string]bool
	if canonical {
		matchWords = make(map[string]bool, len(q.include))
		for _, w := range q.include {
			matchWords[strings.ToLower(w)] = true
		}
	} else {
		matchWords = nonGenericTechWords(techName)
	}
	if len(matchWords) == 0 {
		return nil
	}
	primary := primaryTechWord(normalized)
	// fullSlug catches a hyphenated multi-word name the corpus tags as one
	// literal compound token — "contact-form-7", "wp-fastest-cache",
	// "litespeed-cache" all confirmed tagged this way on the real synced
	// corpus (P1-3, docs/follow-up.md), but primary/matchWords below always
	// word-split on non-alphanumeric separators (including hyphens), so
	// neither would ever equal a compound tag like that. Only relevant for
	// slug-shaped names (wp-plugin facts, see pkg/recon's plugin-path
	// extraction); a plain multi-word name like "Yoast SEO Premium" has no
	// hyphen and this stays "", unchanged behavior.
	fullSlug := ""
	if strings.Contains(normalized, "-") {
		fullSlug = normalized
	}
	exclude := lowerSet(q.exclude)

	type scored struct {
		entry templatesync.Entry
		score int
		year  int
	}
	var cands []scored
	for _, entry := range index {
		if hasAnyTag(entry, exclude) || idContainsAny(entry.ID, q.excludeIDSubstr) {
			continue
		}
		score, year, ok := scoreTemplateForTech(entry, matchWords, primary, fullSlug, version)
		if !ok {
			continue
		}
		cands = append(cands, scored{entry, score, year})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		if cands[i].year != cands[j].year {
			return cands[i].year > cands[j].year
		}
		return cands[i].entry.ID < cands[j].entry.ID
	})
	if len(cands) == 0 {
		return nil
	}
	if len(cands) > maxTemplateLeavesPerTech {
		cands = cands[:maxTemplateLeavesPerTech]
	}
	out := make([]templatesync.Entry, len(cands))
	for i, c := range cands {
		out[i] = c.entry
	}
	return out
}

// detectorTemplateTagFloor is the always-applied, tech-agnostic slice of
// the synced corpus each built-in detector should run even when recon
// produced no tech facts to narrow by (doc15 Step 6a). Keyed by the same
// detector names scanner.Config.Detector accepts. These are the template
// *categories* whose value doesn't depend on a fingerprint: a missing
// security header, an exposed .env/.git, an open admin panel, a
// default-login page — checks the detector is conceptually paired with.
// Product-specific templates (a WordPress CVE, a Confluence RCE) are NOT
// here; those come back in only when TechStackTags adds the product's own
// tag from a real recon fact. Tag coverage was measured against the real
// corpus before pinning each set (e.g. "misconfig" on 960 of 980
// http/misconfiguration/ files, "panel" on 1,591, "default-login" on 323).
// "businesslogic" has no floor — both its checks are native, corpus-driven
// templates add nothing.
var detectorTemplateTagFloor = map[string][]string{
	"misconfig":     {"misconfig", "exposure", "config", "default-login", "panel"},
	"authbypass":    {"auth-bypass", "default-login", "panel", "exposure"},
	"ssrf":          {"ssrf", "redirect", "oob"},
	"idor":          {"idor", "bola", "apidocs", "swagger", "graphql"},
	"businesslogic": nil,
}

// DetectorTemplateTags returns the tech-agnostic category-tag floor for a
// built-in detector — the templates scanner.Engine.loadTemplates should run
// for that detector regardless of what recon fingerprinted (doc15 Step 6a).
// Compose the result with TechStackTags (the product-specific "extras") for
// the full scoped tag set: floor ∪ extras, an OR-match. Returns nil for an
// unknown detector name or "businesslogic" (native-only) — the caller's
// documented fallback for a nil/empty result is the full unnarrowed corpus,
// never zero templates.
func DetectorTemplateTags(detector string) []string {
	floor := detectorTemplateTagFloor[detector]
	if len(floor) == 0 {
		return nil
	}
	out := make([]string, len(floor))
	copy(out, floor)
	return out
}

// TechStackTags returns the union of Tags from every templateIndex entry
// matchTemplateTags ranks as relevant to at least one fact in techStack —
// the tag allowlist scanner.Engine.loadTemplates' Config.Tags narrowing
// needs to run only templates plausibly relevant to a target's detected
// tech stack, instead of the full synced corpus (LT-16, docs/follow-up.md:
// a real aceautowreckers.com run loaded and ran all ~9,244 templates
// against a target httpx fingerprinted as running only a handful of real
// technologies). Deliberately reuses matchTemplateTags as-is rather than
// re-implementing its scoring: canonicalTechTags' false-friend exclusions
// (e.g. "Nginx" not pulling in unrelated ingress-nginx/proxy-manager CVEs,
// docs/follow-up.md P0-2) apply identically here, and every fact's own
// maxTemplateLeavesPerTech cap only limits how many entries seed the tag
// set per tech, not how many templates the resulting tags let back in —
// once a tag like "wordpress" is in the returned set, every WordPress-
// tagged template in the corpus matches it, not just the top few
// matchTemplateTags picked for fact.Name specifically. Returns nil when
// techStack or templateIndex is empty, or when nothing in techStack ties
// to any template tag — scanner.Engine's documented fallback for either
// case is running the full, unnarrowed corpus, never zero templates.
func TechStackTags(techStack []recon.TechFact, templateIndex []templatesync.Entry) []string {
	if len(techStack) == 0 || len(templateIndex) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(techStack))
	tagSet := map[string]bool{}
	for _, fact := range techStack {
		normalized := NormalizeTechName(fact.Name)
		if normalized == "" || seen[normalized] || nonActionableTech[normalized] {
			continue
		}
		seen[normalized] = true
		for _, entry := range matchTemplateTags(fact.Name, templateIndex) {
			for _, tag := range entry.Tags {
				if t := strings.ToLower(strings.TrimSpace(tag)); t != "" {
					tagSet[t] = true
				}
			}
		}
	}
	if len(tagSet) == 0 {
		return nil
	}
	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

// scoreTemplateForTech scores one template entry's relevance to a tech
// fact. ok is false when nothing ties the entry to this tech — it is then
// dropped, never made into a leaf. year is the entry's CVE year (0 if not
// a CVE template), used as a sort tiebreak by the caller.
func scoreTemplateForTech(entry templatesync.Entry, matchWords map[string]bool, primary, fullSlug, version string) (score int, year int, ok bool) {
	tagHit, primaryTagHit := false, false
	for _, raw := range entry.Tags {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if tag == "" {
			continue
		}
		if (primary != "" && tag == primary) || (fullSlug != "" && tag == fullSlug) {
			primaryTagHit = true
			tagHit = true
		} else if matchWords[tag] {
			tagHit = true
		}
	}

	switch {
	case primaryTagHit:
		score = 100
	case tagHit:
		score = 50
	default:
		// No product tag on this template. An ID/Name substring match was
		// tried here originally but pulled in far more false friends than
		// real templates on the live corpus (product-prefixed slugs like
		// "weaver-jquery-file-upload", "ecology-mysql-config") — a genuine
		// product template essentially always carries the product tag, and
		// the rare ID-only one still surfaces under its broader tag (a
		// "wp-yoast-*" template via its "wordpress" tag).
		return 0, 0, false
	}

	switch strings.ToLower(entry.Severity) {
	case "critical":
		score += 25
	case "high":
		score += 15
	case "medium":
		score += 6
	}

	year = cveYear(entry)
	switch {
	case year == 0:
		// A non-CVE template (-detect, -panel, default-login exposure): kept,
		// no recency adjustment either way.
	case year >= cveRecencyBaseYear:
		score += (year - cveRecencyBaseYear) * cveRecencyWeight
	case version != "":
		score -= staleCVEPenalty
	}
	return score, year, true
}

// nonGenericTechWords is normalizedTechWords minus genericTechWords and
// pure-numeric fragments — the word set matchTemplateTags matches tags
// against for a name not pinned in canonicalTechTags.
func nonGenericTechWords(name string) map[string]bool {
	words := normalizedTechWords(name)
	for w := range words {
		if genericTechWords[w] || isAllDigits(w) {
			delete(words, w)
		}
	}
	if len(words) == 0 {
		return nil
	}
	return words
}

// primaryTechWord returns the first non-generic, non-numeric word of a
// normalized tech name — the product word ("wordpress" from "wordpress
// block editor", "yoast" from "yoast seo premium"). "" if the name is
// entirely generic (those are handled by nonActionableTech upstream).
func primaryTechWord(normalized string) string {
	for _, w := range strings.FieldsFunc(normalized, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		if w != "" && !genericTechWords[w] && !isAllDigits(w) {
			return w
		}
	}
	return ""
}

// techVersionSuffix returns the trimmed text after the first ':' in a raw
// TechFact.Name ("PHP:8.3.30" -> "8.3.30"), or "" if there is none —
// NormalizeTechName discards it, but matchTemplateTags' CVE scoring needs
// it (P0-1a).
func techVersionSuffix(name string) string {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		return strings.TrimSpace(name[i+1:])
	}
	return ""
}

// cveYear extracts the year from a CVE-YYYY-NNNN identifier in the entry's
// ID or tags, or 0 if the entry isn't CVE-identified.
func cveYear(entry templatesync.Entry) int {
	if m := cveYearPattern.FindStringSubmatch(entry.ID); m != nil {
		y, _ := strconv.Atoi(m[1])
		return y
	}
	for _, tag := range entry.Tags {
		if m := cveYearPattern.FindStringSubmatch(tag); m != nil {
			y, _ := strconv.Atoi(m[1])
			return y
		}
	}
	return 0
}

func hasAnyTag(entry templatesync.Entry, want map[string]bool) bool {
	if len(want) == 0 {
		return false
	}
	for _, raw := range entry.Tags {
		if want[strings.ToLower(strings.TrimSpace(raw))] {
			return true
		}
	}
	return false
}

func lowerSet(ss []string) map[string]bool {
	if len(ss) == 0 {
		return nil
	}
	out := make(map[string]bool, len(ss))
	for _, s := range ss {
		out[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return out
}

func idContainsAny(id string, substrs []string) bool {
	if len(substrs) == 0 {
		return false
	}
	lower := strings.ToLower(id)
	for _, s := range substrs {
		if s != "" && strings.Contains(lower, strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// NormalizeTechName strips a version suffix (e.g. "OpenResty:1.27.1.2" ->
// "openresty") so a TechFact's product name has a chance of matching a
// template's own short tag.
func NormalizeTechName(name string) string {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// normalizedTechWords splits NormalizeTechName's output on non-alphanumeric
// separators into a set of words — nuclei template tags are conventionally
// a single short word ("litespeed", "yoast"), while a Wappalyzer-style
// TechFact.Name is often multiple words ("LiteSpeed Cache", "Yoast SEO
// Premium"); matchTemplateTags' original whole-string-equality check meant
// a multi-word tech name could never match any tag at all. Found live,
// 2026-09-04: a real target's "LiteSpeed Cache" and "Yoast SEO"/"Yoast SEO
// Premium" TechFacts matched zero templates despite the synced corpus
// holding real, relevant CVE templates tagged "litespeed"/"yoast" for
// exactly those plugins (CVE-2024-47374, a LiteSpeed Cache stored XSS;
// CVE-2021-25118, a Yoast SEO information disclosure) — invisible to the
// Plan Tree purely because of this string-matching gap, not a coverage
// gap in the template corpus itself. Word-level equality (not a raw
// substring check) avoids a short/generic tag spuriously matching an
// unrelated multi-word name.
func normalizedTechWords(name string) map[string]bool {
	fields := strings.FieldsFunc(NormalizeTechName(name), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	if len(fields) == 0 {
		return nil
	}
	words := make(map[string]bool, len(fields))
	for _, w := range fields {
		words[w] = true
	}
	return words
}

// LeafContext is the structured data resolveTechFact/resolvePortFacts
// already have in hand when building an unresolved leaf's human-readable
// Rationale — kept in a side map Resolve returns alongside the tree, never
// merged into agenttask.PlanNode itself (that type is the shared MCP tool
// output schema; jsonschema-go's reflection can't represent PlanNode's own
// self-referential Children field, let alone a new one — see doc15's
// planOutputSchema comment). pkg/llmfallback.ResolveLeaf reads this instead
// of regexing a tech name back out of Rationale prose (P2-2,
// docs/follow-up.md) — a real, live gap that regex had: P1-2's port leaves
// use an entirely different Rationale sentence shape
// ("port %d/%s (%s) open...") the old pattern never matched at all, so
// ResolveLeaf's tag-relevance ranking silently got zero signal for every
// port-open unresolved leaf. Exactly one of TechFact/Port is set, matching
// which of the two functions below produced the leaf; Endpoints may be set
// alongside TechFact (the same correlatedEndpoints data already folded into
// Rationale prose).
type LeafContext struct {
	TechFact  *recon.TechFact
	Port      *recon.PortFact
	Endpoints []recon.EndpointFact
}

// Resolve builds a PlanTree from result: one child node per host that
// produced at least one TechFact, and under each host one leaf per
// registry/template-tag match (Status: StatusPending) or, if a TechFact
// matched neither, one leaf with Status: StatusUnresolved — visible and
// inspectable, never silently dropped (Decision 6). templateIndex may be
// nil (R9's index not yet generated) — template-tag matching is simply
// skipped in that case, the registry-capability matches still run. The
// second return value carries every unresolved leaf's LeafContext, keyed by
// leaf ID (P2-2) — empty map, never nil, so a caller can range over it
// unconditionally.
func Resolve(result *recon.ReconResult, templateIndex []templatesync.Entry) (*agenttask.PlanTree, map[string]LeafContext) {
	leafContexts := make(map[string]LeafContext)
	byHost := make(map[string][]recon.TechFact)
	hostSet := make(map[string]bool)
	var hosts []string
	addHost := func(h string) {
		if h != "" && !hostSet[h] {
			hostSet[h] = true
			hosts = append(hosts, h)
		}
	}
	for _, fact := range result.TechStack {
		addHost(fact.Host)
		byHost[fact.Host] = append(byHost[fact.Host], fact)
	}
	// A host can appear only in Endpoints (never fingerprinted with a
	// TechFact) and still carry real endpoint-driven signal — P1-1's
	// endpoint-driven pass below is otherwise unreachable for such a host,
	// since the loop used to build hosts from result.TechStack alone (the
	// root cause diagnosis in docs/follow-up.md's "Decision Engine &
	// Recon→Plan Signal Use" section: Resolve reasoned only over TechStack,
	// never Endpoints or Hosts[].Ports).
	for _, ep := range result.Endpoints {
		addHost(endpointHostname(ep.URL))
	}
	// Same reasoning for Hosts[].Ports (P1-2): a naabu-only host (a raw TCP
	// service with no HTTP surface at all, so httpx/fingerprint never
	// produced a TechFact and katana never crawled it) would otherwise be
	// unreachable too.
	portsByHost := make(map[string][]recon.PortFact, len(result.Hosts))
	for _, hf := range result.Hosts {
		addHost(hf.Host)
		portsByHost[hf.Host] = hf.Ports
	}
	// LT-3 (docs/follow-up.md): an APISpecFact's host is usually already
	// covered by the Endpoints loop above (probeCommonPaths always records
	// both), but that's a coincidence of today's caller, not a guarantee —
	// add it explicitly so a host known only via its API spec still gets a
	// host node.
	if result.APISpec != nil {
		addHost(endpointHostname(result.APISpec.URL))
	}
	sort.Strings(hosts) // deterministic tree shape for the same input

	templateByID := make(map[string]templatesync.Entry, len(templateIndex))
	for _, entry := range templateIndex {
		templateByID[entry.ID] = entry
	}

	root := &agenttask.PlanNode{ID: "root", Target: result.Target}
	for _, host := range hosts {
		hostNode := &agenttask.PlanNode{ID: "host:" + host, Target: host}
		leafIdx := 0
		seen := make(map[string]bool)
		addLeaf := func(leaf *agenttask.PlanNode, key string) {
			if seen[key] {
				return // an earlier leaf already produced this exact check (P0-4)
			}
			seen[key] = true
			hostNode.Children = append(hostNode.Children, leaf)
		}
		for _, fact := range byHost[host] {
			for _, leaf := range resolveTechFact(host, fact, templateIndex, result.Endpoints, &leafIdx, leafContexts) {
				addLeaf(leaf, leafDedupKey(fact, leaf))
			}
		}
		resolveAPISpecFact(host, result.APISpec, templateIndex, &leafIdx, addLeaf)
		for _, leaf := range resolveEndpointFacts(host, result.Endpoints, templateByID, &leafIdx) {
			addLeaf(leaf, pendingDedupKey(leaf.Target, leaf.Detector))
		}
		resolvePortFacts(host, portsByHost[host], &leafIdx, addLeaf, leafContexts)
		resolveHostnameHints(host, templateIndex, &leafIdx, addLeaf)
		if len(hostNode.Children) == 0 {
			continue // every TechFact/endpoint on this host was non-actionable or produced no signal (P0-5) — no empty host node
		}
		root.Children = append(root.Children, hostNode)
	}
	return &agenttask.PlanTree{Root: root}, leafContexts
}

// leafDedupKey returns a stable key identifying what a leaf will actually
// *do*, so Resolve can drop a second leaf that would run the identical
// check against the identical target. Multiple TechFacts on one host
// routinely converge on the same capability (PHP, WordPress, nginx and
// MySQL all → "misconfig") or the same template ("Yoast SEO" and "Yoast
// SEO Premium" → the same yoast-tagged template); without this a real
// recon pass produced 17 byte-identical misconfig leaves under one host
// (docs/follow-up.md P0-4, 2026-09-04). A pending leaf is keyed by
// (target, detector); an unresolved leaf — which carries no Detector — by
// (target, normalized tech name), so two unresolved facts naming the same
// product from different recon sources still collapse to one. The first
// occurrence in recon order wins, keeping its Rationale/Confidence as-is
// (merging those across duplicates is a deliberate later polish, not P0).
func leafDedupKey(fact recon.TechFact, leaf *agenttask.PlanNode) string {
	if leaf.Status == agenttask.StatusUnresolved {
		return unresolvedDedupKey(leaf.Target, fact.Name)
	}
	return pendingDedupKey(leaf.Target, leaf.Detector)
}

// pendingDedupKey is leafDedupKey's pending-leaf half, factored out so
// resolveEndpointFacts' leaves — which carry no originating TechFact — can
// dedup against the same per-host `seen` set Resolve already maintains.
func pendingDedupKey(target, detector string) string {
	return "pending\x00" + target + "\x00" + detector
}

// unresolvedDedupKey is leafDedupKey's unresolved-leaf half, factored out
// so resolvePortFacts' leaves — which carry no originating TechFact, just a
// synthetic "port:<N>" name — can dedup the same way.
func unresolvedDedupKey(target, techName string) string {
	return "unresolved\x00" + target + "\x00" + NormalizeTechName(techName)
}

func resolveTechFact(host string, fact recon.TechFact, templateIndex []templatesync.Entry, endpoints []recon.EndpointFact, leafIdx *int, leafContexts map[string]LeafContext) []*agenttask.PlanNode {
	if nonActionableTech[NormalizeTechName(fact.Name)] {
		return nil // transport/posture/hosting-brand fact — nothing to dispatch, not even an unresolved leaf (P0-5)
	}

	confidence := agenttask.Confidence(fact.Confidence)
	var leaves []*agenttask.PlanNode

	for _, capName := range matchTechRules(fact.Name) {
		leaves = append(leaves, &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Detector:   capName,
			Rationale:  fmt.Sprintf("tech fact %q (source: %s) matched registry capability %q", fact.Name, fact.Source, capName),
			Status:     agenttask.StatusPending,
			Confidence: confidence,
		})
		*leafIdx++
	}

	for _, entry := range matchTemplateTags(fact.Name, templateIndex) {
		leaves = append(leaves, &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Detector:   entry.ID,
			Rationale:  fmt.Sprintf("tech fact %q (source: %s) ranked %q among the most relevant synced templates", fact.Name, fact.Source, entry.ID),
			Status:     agenttask.StatusPending,
			Confidence: confidence,
		})
		*leafIdx++
	}

	if len(leaves) == 0 {
		rationale := fmt.Sprintf("tech fact %q (source: %s) matched no registry capability or template tag", fact.Name, fact.Source)
		obs := correlatedEndpoints(host, endpoints)
		if len(obs) > 0 {
			rationale += "; observed on this host: " + describeEndpoints(obs)
		}
		leaf := &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Rationale:  rationale,
			Status:     agenttask.StatusUnresolved,
			Confidence: confidence,
		}
		*leafIdx++
		leafContexts[leaf.ID] = LeafContext{TechFact: &fact, Endpoints: obs}
		leaves = append(leaves, leaf)
	}
	return leaves
}

// resolveEndpointFacts is P0-2's tech-fact-driven resolveTechFact's
// sibling: it reasons directly over host's observed EndpointFacts (P1-1,
// docs/follow-up.md), rather than only over TechStack. idor/authbypass/ssrf
// reuse the exact same recon.Suggest*FromRecon functions that already fill
// scanner.Config.EndpointTemplate/ProtectedPaths/SSRFParams elsewhere in the
// plan pipeline (pkg/mcpserver/tools_plan.go's resolveFieldSuggestions,
// pkg/webui's fillReconFields) — those functions were already deriving the
// right candidate values, Resolve simply never emitted a leaf to use them,
// so idor/authbypass/ssrf could go fully unresolved on a real target with
// textbook surface but no TechFact matching techRules' small capability
// table. No new candidate-derivation logic and no PlanNode schema change:
// the leaf just names the capability, and the already-independently-filled
// baseCfg field supplies the value at execution time. businesslogic and the
// endpointSignals template-ID map are new signal, not reuse — see their own
// doc comments.
func resolveEndpointFacts(host string, endpoints []recon.EndpointFact, templateByID map[string]templatesync.Entry, leafIdx *int) []*agenttask.PlanNode {
	hostEndpoints := endpointsForHost(host, endpoints)
	if len(hostEndpoints) == 0 {
		return nil
	}
	hostResult := &recon.ReconResult{Endpoints: hostEndpoints}
	var leaves []*agenttask.PlanNode

	if candidates := recon.SuggestIDOREndpointCandidates(hostResult); len(candidates) > 0 {
		leaves = append(leaves, newEndpointLeaf(host, "idor", agenttask.ConfidenceMedium,
			fmt.Sprintf("recon observed %d ID-shaped endpoint candidate(s) on this host (e.g. %s)", len(candidates), candidates[0]), leafIdx))
	}
	if protected, _, _ := recon.SuggestAuthBypassPathsFromRecon(hostResult); len(protected) > 0 {
		leaves = append(leaves, newEndpointLeaf(host, "authbypass", agenttask.ConfidenceMedium,
			fmt.Sprintf("recon observed %d endpoint(s) returning 401/403 on this host (e.g. %s)", len(protected), protected[0]), leafIdx))
	}
	if params := recon.SuggestSSRFParamsFromRecon(hostResult); len(params) > 0 {
		leaves = append(leaves, newEndpointLeaf(host, "ssrf", agenttask.ConfidenceMedium,
			fmt.Sprintf("recon observed URL-shaped query param(s) on this host: %s", strings.Join(params, ", ")), leafIdx))
	}
	for _, ep := range hostEndpoints {
		p := endpointURLPath(ep.URL)
		// LT-20 (docs/follow-up.md, 2026-09-04): a static asset filename can
		// still contain a businessLogicPathKeywords substring purely by
		// coincidence — confirmed live: a WordPress theme's purely cosmetic
		// "cart-header-element-lazy.min.css" bundle matched on "cart" alone
		// and produced a wrong, noisy businesslogic leaf. Mirrors
		// suggest.go's own established pattern (SuggestIDOREndpointCandidates
		// already skips IsStaticAssetPath for the identical reason).
		if recon.IsStaticAssetPath(p) {
			continue
		}
		if looksLikeCouponOrCartFlow(p) {
			leaves = append(leaves, newEndpointLeaf(host, "businesslogic", agenttask.ConfidenceLow,
				fmt.Sprintf("recon observed a cart/checkout/coupon-shaped endpoint on this host (%s) — still requires --allow-writes and real coupon paths for a non-crAPI target", p), leafIdx))
			break // one is enough to justify the leaf; not every matching endpoint
		}
	}

	for _, sig := range endpointSignals {
		for _, ep := range hostEndpoints {
			if !strings.Contains(strings.ToLower(ep.URL), sig.pathSubstr) {
				continue
			}
			for _, id := range sig.templateIDs {
				entry, ok := templateByID[id]
				if !ok {
					continue // this install's synced corpus doesn't carry it
				}
				leaves = append(leaves, &agenttask.PlanNode{
					ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
					Target:     host,
					Detector:   entry.ID,
					Rationale:  fmt.Sprintf("recon directly observed %s — matches synced template %q", endpointURLPath(ep.URL), entry.ID),
					Status:     agenttask.StatusPending,
					Confidence: agenttask.ConfidenceHigh,
				})
				*leafIdx++
			}
			break // one observed match is enough to justify this signal's leaves
		}
	}
	return leaves
}

// newEndpointLeaf builds one Pending leaf for resolveEndpointFacts —
// factored out since every one of its cases shares the same shape, unlike
// resolveTechFact's leaves which additionally carry a source TechFact.
func newEndpointLeaf(host, detector string, confidence agenttask.Confidence, rationale string, leafIdx *int) *agenttask.PlanNode {
	leaf := &agenttask.PlanNode{
		ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
		Target:     host,
		Detector:   detector,
		Rationale:  rationale,
		Status:     agenttask.StatusPending,
		Confidence: confidence,
	}
	*leafIdx++
	return leaf
}

// endpointHostname returns rawURL's hostname, "" on a malformed URL.
func endpointHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// endpointURLPath returns rawURL's path (+query, if any), falling back to
// the raw string on a malformed URL — display-only, mirrors
// describeEndpoints' own path extraction.
func endpointURLPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}

// endpointsForHost returns every EndpointFact in endpoints whose URL
// hostname equals host, preserving order.
func endpointsForHost(host string, endpoints []recon.EndpointFact) []recon.EndpointFact {
	var matched []recon.EndpointFact
	for _, ep := range endpoints {
		if endpointHostname(ep.URL) == host {
			matched = append(matched, ep)
		}
	}
	return matched
}

// resolvePortFacts is P1-2's port-driven pass (docs/follow-up.md): one
// StatusUnresolved leaf per open port on host that interestingPorts
// recognizes — visibility only, see that map's own doc comment for why
// this deliberately never dispatches. Takes addLeaf directly (rather than
// returning a slice, like resolveTechFact/resolveEndpointFacts do) because
// its dedup key needs the specific port number, which isn't reconstructable
// from the returned PlanNode alone (Detector stays "" like any other
// unresolved leaf) — this way the key is computed right where p.Port is in
// scope, using a "port-<N>" synthetic name (a dash, not a colon —
// unresolvedDedupKey normalizes via NormalizeTechName, which strips
// everything from the first ':' onward, so "port:21" and "port:3306" would
// both normalize to the same "port" key and silently dedup two genuinely
// different ports down to one leaf; caught live against the real
// andertone.com data, which has both 21 and 3306 open on the same host).
func resolvePortFacts(host string, ports []recon.PortFact, leafIdx *int, addLeaf func(*agenttask.PlanNode, string), leafContexts map[string]LeafContext) {
	for _, p := range ports {
		service, known := interestingPorts[p.Port]
		if !known {
			continue
		}
		if p.Service != "" {
			service = p.Service // naabu/httpx's own service-detection name, when present, is more specific than our static table
		}
		leaf := &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Rationale:  fmt.Sprintf("port %d/%s (%s) open (source: %s) — no automated check exists yet for this protocol; manually verify", p.Port, p.Protocol, service, p.Source),
			Status:     agenttask.StatusUnresolved,
			Confidence: agenttask.ConfidenceMedium,
		}
		*leafIdx++
		leafContexts[leaf.ID] = LeafContext{Port: &p}
		addLeaf(leaf, unresolvedDedupKey(host, fmt.Sprintf("port-%d", p.Port)))
	}
}

// resolveHostnameHints emits LT-9's hostname-driven leaves (docs/follow-up.md):
// when host's first DNS label names a known product (hostnameProductHint) and
// nothing else on this host already dispatched that product's checks, run the
// same registry-capability + template-tag matching a real TechFact would,
// at ConfidenceLow. Routes through addLeaf so a real fingerprint-driven leaf
// for the same (host, capability) always wins the dedup (pendingDedupKey).
func resolveHostnameHints(host string, templateIndex []templatesync.Entry, leafIdx *int, addLeaf func(*agenttask.PlanNode, string)) {
	techName := hostnameProductHint(host)
	if techName == "" {
		return
	}
	rationale := fmt.Sprintf("hostname %q names %q — no fingerprint on this host, dispatching product checks on the name alone", host, techName)

	for _, capName := range matchTechRules(techName) {
		leaf := &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Detector:   capName,
			Rationale:  rationale,
			Status:     agenttask.StatusPending,
			Confidence: agenttask.ConfidenceLow,
		}
		*leafIdx++
		addLeaf(leaf, pendingDedupKey(host, capName))
	}
	for _, entry := range matchTemplateTags(techName, templateIndex) {
		leaf := &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Detector:   entry.ID,
			Rationale:  rationale,
			Status:     agenttask.StatusPending,
			Confidence: agenttask.ConfidenceLow,
		}
		*leafIdx++
		addLeaf(leaf, pendingDedupKey(host, entry.ID))
	}
}

// resolveAPISpecFact dispatches result.APISpec — recorded at most once per
// Resolve call, never per-host (addAPISpec's "first one wins": see its own
// doc comment and pkg/recon/aggregate.go) — to the one host its URL actually
// names, so it doesn't leak onto every other host in a multi-host recon run.
// Fixes LT-3 (docs/follow-up.md): a real swagger.json/openapi.json hit is
// recorded as an APISpecFact, not a TechFact (nothing fingerprints raw spec
// JSON as "Swagger UI" the way it does an HTML page containing "swagger-ui"),
// so matchTechRules — which only ever read TechStack — never dispatched
// idor/misconfig for it at all, even though the "swagger" techRule exists
// specifically for this signal. Leaves route through addLeaf so they dedup
// (pendingDedupKey) against any leaf a same-capability TechFact already
// produced on this host.
func resolveAPISpecFact(host string, spec *recon.APISpecFact, templateIndex []templatesync.Entry, leafIdx *int, addLeaf func(*agenttask.PlanNode, string)) {
	if spec == nil || endpointHostname(spec.URL) != host {
		return
	}
	techName, ok := apiSpecTechName[spec.Kind]
	if !ok {
		return // unrecognized Kind — no rule to reuse, not a guess
	}
	rationale := fmt.Sprintf("api spec (%s) publicly reachable at %s", spec.Kind, spec.URL)

	for _, capName := range matchTechRules(techName) {
		leaf := &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Detector:   capName,
			Rationale:  rationale,
			Status:     agenttask.StatusPending,
			Confidence: agenttask.ConfidenceHigh,
		}
		*leafIdx++
		addLeaf(leaf, pendingDedupKey(host, capName))
	}
	for _, entry := range matchTemplateTags(techName, templateIndex) {
		leaf := &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Detector:   entry.ID,
			Rationale:  rationale,
			Status:     agenttask.StatusPending,
			Confidence: agenttask.ConfidenceHigh,
		}
		*leafIdx++
		addLeaf(leaf, pendingDedupKey(host, entry.ID))
	}
}

// maxCorrelatedEndpoints caps how many real observed endpoints get folded
// into an unresolved leaf's Rationale — enough to give I4's LLM fallback
// (pkg/llmfallback.ResolveLeaf and its draft-authoring call, both of which
// embed Rationale verbatim into their prompt) something concrete to reason
// about — a real path/status instead of a bare hostname — while staying
// short, since Rationale is also a human-facing display field on the Web
// UI's plan-preview page.
const maxCorrelatedEndpoints = 3

// correlatedEndpoints returns up to maxCorrelatedEndpoints EndpointFacts
// observed on host. Not a precise "this endpoint caused this TechFact"
// link — recon.TechFact carries no such reference — just "something real
// recon actually saw on this host" instead of nothing at all.
func correlatedEndpoints(host string, endpoints []recon.EndpointFact) []recon.EndpointFact {
	matched := endpointsForHost(host, endpoints)
	if len(matched) > maxCorrelatedEndpoints {
		matched = matched[:maxCorrelatedEndpoints]
	}
	return matched
}

// describeEndpoints renders endpoints as a short, comma-separated "METHOD
// path (status)" list — path only (scheme+host stripped, mirroring
// pkg/recon/suggest.go's own EndpointTemplate contract), truncated so one
// unusually long observed URL can't blow out an otherwise-short Rationale.
func describeEndpoints(endpoints []recon.EndpointFact) string {
	parts := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		path := ep.URL
		if u, err := url.Parse(ep.URL); err == nil {
			path = u.Path
			if u.RawQuery != "" {
				path += "?" + u.RawQuery
			}
		}
		if len(path) > 60 {
			path = path[:60] + "..."
		}
		status := ""
		if ep.StatusCode != 0 {
			status = fmt.Sprintf(" (%d)", ep.StatusCode)
		}
		parts = append(parts, fmt.Sprintf("%s %s%s", ep.Method, path, status))
	}
	return strings.Join(parts, ", ")
}
