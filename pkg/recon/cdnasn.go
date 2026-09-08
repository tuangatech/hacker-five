package recon

import "strings"

// cdnEdgeASNs maps an Autonomous System number (bare, as Team Cymru's
// origin TXT reports it in lookupASN's first field) to the CDN/edge network
// that operates it. Membership means "an address in this AS is a CDN's edge
// POP, never a customer's origin server" — so a port scan of it maps the
// CDN's infrastructure, not the target, and recon says so instead of
// implying origin coverage (LT-61, docs/follow-up.md).
//
// Deliberately limited to networks that ONLY ever serve as CDN edge.
// Generic clouds (AWS AS16509/AS14618, GCP AS15169, Azure AS8075) are
// excluded on purpose even though CloudFront / Cloud CDN / Front Door run
// on them: a target's real origin can legitimately live in the same AS, so
// "in this AS ⇒ it's just an edge" does not hold there. Numbers checked
// against public BGP / PeeringDB records, 2026-09-07.
var cdnEdgeASNs = map[string]string{
	// Cloudflare
	"13335":  "Cloudflare",
	"209242": "Cloudflare",
	"132892": "Cloudflare",
	"395747": "Cloudflare",
	// Akamai
	"20940": "Akamai",
	"16625": "Akamai",
	"16702": "Akamai",
	"18680": "Akamai",
	"20189": "Akamai",
	"21342": "Akamai",
	"21357": "Akamai",
	"23454": "Akamai",
	"35994": "Akamai",
	"12222": "Akamai",
	"9989":  "Akamai",
	"31108": "Akamai",
	"33905": "Akamai",
	"43639": "Akamai",
	// Fastly
	"54113": "Fastly",
	// Edgio (Limelight / Verizon Media / Edgecast)
	"22822": "Edgio",
	"15133": "Edgecast",
	"38622": "Edgio",
	// Other dedicated CDNs
	"60068":  "CDN77",
	"200325": "BunnyCDN",
	"19551":  "Imperva Incapsula",
	"30148":  "Sucuri",
	"33438":  "StackPath",
	"20446":  "StackPath",
}

// cdnForASNField returns the CDN name for a Team Cymru origin-ASN field
// value, or "". The field can name more than one origin AS (space-separated)
// when a prefix is announced by several — the first known CDN AS wins.
func cdnForASNField(asnField string) string {
	for _, a := range strings.Fields(asnField) {
		a = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(a)), "AS")
		if name, ok := cdnEdgeASNs[a]; ok {
			return name
		}
	}
	return ""
}
