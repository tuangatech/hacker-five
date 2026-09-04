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
	"nginx":       {include: []string{"nginx"}, exclude: []string{"proxy-manager", "ingress-nginx", "nginxwebui"}},
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
		score, year, ok := scoreTemplateForTech(entry, matchWords, primary, version)
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

// scoreTemplateForTech scores one template entry's relevance to a tech
// fact. ok is false when nothing ties the entry to this tech — it is then
// dropped, never made into a leaf. year is the entry's CVE year (0 if not
// a CVE template), used as a sort tiebreak by the caller.
func scoreTemplateForTech(entry templatesync.Entry, matchWords map[string]bool, primary, version string) (score int, year int, ok bool) {
	tagHit, primaryTagHit := false, false
	for _, raw := range entry.Tags {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if tag == "" {
			continue
		}
		if primary != "" && tag == primary {
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

// Resolve builds a PlanTree from result: one child node per host that
// produced at least one TechFact, and under each host one leaf per
// registry/template-tag match (Status: StatusPending) or, if a TechFact
// matched neither, one leaf with Status: StatusUnresolved — visible and
// inspectable, never silently dropped (Decision 6). templateIndex may be
// nil (R9's index not yet generated) — template-tag matching is simply
// skipped in that case, the registry-capability matches still run.
func Resolve(result *recon.ReconResult, templateIndex []templatesync.Entry) *agenttask.PlanTree {
	byHost := make(map[string][]recon.TechFact)
	var hosts []string
	for _, fact := range result.TechStack {
		if _, seen := byHost[fact.Host]; !seen {
			hosts = append(hosts, fact.Host)
		}
		byHost[fact.Host] = append(byHost[fact.Host], fact)
	}
	sort.Strings(hosts) // deterministic tree shape for the same input

	root := &agenttask.PlanNode{ID: "root", Target: result.Target}
	for _, host := range hosts {
		hostNode := &agenttask.PlanNode{ID: "host:" + host, Target: host}
		leafIdx := 0
		seen := make(map[string]bool)
		for _, fact := range byHost[host] {
			for _, leaf := range resolveTechFact(host, fact, templateIndex, result.Endpoints, &leafIdx) {
				key := leafDedupKey(fact, leaf)
				if seen[key] {
					continue // an earlier TechFact already produced this exact check (P0-4)
				}
				seen[key] = true
				hostNode.Children = append(hostNode.Children, leaf)
			}
		}
		if len(hostNode.Children) == 0 {
			continue // every TechFact on this host was non-actionable (P0-5) — no empty host node
		}
		root.Children = append(root.Children, hostNode)
	}
	return &agenttask.PlanTree{Root: root}
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
		return "unresolved\x00" + leaf.Target + "\x00" + NormalizeTechName(fact.Name)
	}
	return "pending\x00" + leaf.Target + "\x00" + leaf.Detector
}

func resolveTechFact(host string, fact recon.TechFact, templateIndex []templatesync.Entry, endpoints []recon.EndpointFact, leafIdx *int) []*agenttask.PlanNode {
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
		if obs := correlatedEndpoints(host, endpoints); len(obs) > 0 {
			rationale += "; observed on this host: " + describeEndpoints(obs)
		}
		leaves = append(leaves, &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-leaf-%d", host, *leafIdx),
			Target:     host,
			Rationale:  rationale,
			Status:     agenttask.StatusUnresolved,
			Confidence: confidence,
		})
		*leafIdx++
	}
	return leaves
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
	var matched []recon.EndpointFact
	for _, ep := range endpoints {
		u, err := url.Parse(ep.URL)
		if err != nil || u.Hostname() != host {
			continue
		}
		matched = append(matched, ep)
		if len(matched) >= maxCorrelatedEndpoints {
			break
		}
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
