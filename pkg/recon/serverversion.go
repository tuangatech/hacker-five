package recon

import (
	"regexp"
	"strings"
)

// serverHeaderVersionPattern matches the "<product>/<version>" shape a
// handful of high-value server products' own `Server:` response header
// convention always carries (real examples: "nginx/1.25.3", "Apache/2.4.41
// (Ubuntu)", "Microsoft-IIS/10.0") — LT-7/Phase 8 Step 4. httpx's own
// tech-detect (rec.Tech, wave2's httpx-tech-detect TechFacts) names these
// products but never a version (confirmed live, 2026-09-11: httpx's "tech"
// array carries bare "Nginx"/"Apache" on every sampled target), so without
// this, matchTemplateTags' new affected-range gate had nothing to compare a
// candidate CVE/EOL template's declared range against — every Nginx/Apache/
// IIS host got the identical template list regardless of its actual patch
// level, LT-7's own original complaint. Anything the regex doesn't
// recognize (a custom/obscured Server string, a CDN-branded one) is left
// alone rather than guessed.
var serverHeaderVersionPattern = regexp.MustCompile(`(?i)^\s*(nginx|apache|microsoft-iis)/([0-9]+(?:\.[0-9]+){0,3})\b`)

// serverHeaderProductNames maps serverHeaderVersionPattern's lower-cased
// capture group to the TechFact.Name this project's other product-tag
// conventions already use (canonicalTechTags/detectorCapabilityHints in
// pkg/registry — confirmed "nginx"/"apache"/"iis" all present there).
var serverHeaderProductNames = map[string]string{
	"nginx":         "Nginx",
	"apache":        "Apache",
	"microsoft-iis": "IIS",
}

// serverProductVersion parses a raw `Server:` response header value for one
// of serverHeaderProductNames' handful of high-value products, returning
// the product's canonical name and its version — ok is false when
// serverHeader doesn't match the recognized "<product>/<version>" shape at
// all.
func serverProductVersion(serverHeader string) (name, version string, ok bool) {
	m := serverHeaderVersionPattern.FindStringSubmatch(serverHeader)
	if m == nil {
		return "", "", false
	}
	product, known := serverHeaderProductNames[strings.ToLower(m[1])]
	if !known {
		return "", "", false
	}
	return product, m[2], true
}

// headerValue looks up name in headers case-insensitively — httpx's own
// JSON header map is lower-cased in practice (confirmed:
// pkg/recon/schema_test.go's fixture, `"header":{"server":"nginx/1.25"}`),
// but this doesn't assume that, matching headersCorroborateCDN's own
// case-insensitive convention above.
func headerValue(headers map[string]string, name string) string {
	name = strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == name {
			return v
		}
	}
	return ""
}
