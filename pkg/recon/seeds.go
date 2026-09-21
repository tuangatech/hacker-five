package recon

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Seed harvesting (LT-186 item c).
//
// A route keyed by a UUID (".../vehicle/{carId}/location") cannot be enumerated
// the way an integer id can: the idor detector needs one real id to test
// cross-account access against. The only place that id appears is in a response,
// typically a list the signed-in user can fetch (".../vehicle/vehicles"). The
// response-shape probe already reads those bodies, so it also lifts one object id
// from each list and matches it to the templated route by resource name.
//
// The id is response data. It is kept in memory only: EndpointFact.SeedID is
// json:"-", the coverage ledger never sees it, and no prompt reads it. It is used
// in exactly one place, the request the idor dispatch sends.

var seedUUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// seedScanObjects bounds how many objects of a list are looked at; one id is
// enough, so a long list is not walked.
const seedScanObjects = 5

// harvestUUIDSeed returns one UUID that is an object's own identifier ("uuid" or
// "id") from the first few objects of body, a JSON array of objects, an object,
// or an object that wraps such an array under one key. "" when there is none.
// Foreign keys ("owner_id", "user_uuid") are not read: they identify some other
// resource, which would seed the wrong route.
func harvestUUIDSeed(body []byte) string {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return ""
	}
	for _, obj := range seedObjects(v) {
		for _, key := range []string{"uuid", "id"} {
			if s, ok := obj[key].(string); ok && seedUUIDRe.MatchString(s) {
				return s
			}
		}
	}
	return ""
}

func seedObjects(v any) []map[string]any {
	objectsOf := func(items []any) []map[string]any {
		var out []map[string]any
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
				if len(out) == seedScanObjects {
					break
				}
			}
		}
		return out
	}
	switch x := v.(type) {
	case []any:
		return objectsOf(x)
	case map[string]any:
		out := []map[string]any{x}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if items, ok := x[k].([]any); ok {
				out = append(out, objectsOf(items)...)
			}
		}
		return out
	}
	return nil
}

// resourceStem reduces a path segment to a comparable resource name:
// "vehicles" and "vehicle" and "Vehicle_s" all meet at "vehicle".
func resourceStem(seg string) string {
	s := strings.ToLower(seg)
	s = strings.NewReplacer("_", "", "-", "").Replace(s)
	switch {
	case strings.HasSuffix(s, "ies") && len(s) > 4:
		return s[:len(s)-3] + "y"
	case strings.HasSuffix(s, "s") && len(s) > 2:
		return s[:len(s)-1]
	}
	return s
}

func isTemplateSegment(seg string) bool {
	return len(seg) > 2 && strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

func pathSegments(rawURL string) (host string, segs []string, ok bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", nil, false
	}
	for _, s := range strings.Split(u.Path, "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	return strings.ToLower(u.Host), segs, true
}

// attachHarvestedSeeds gives each templated route (".../vehicle/{carId}/location")
// the id of a list on the same host whose path names the same resource: it must
// start with the route's path up to the segment before the placeholder's
// resource, and contain a segment with the same resource stem as the one just
// before the placeholder ("vehicle" matches ".../vehicle/vehicles" and
// ".../vehicles"). sources maps list URL to one id in it. Returns how many routes
// were seeded. Deterministic: sources are tried in sorted order.
func attachHarvestedSeeds(agg *aggregator, sources map[string]string) int {
	if len(sources) == 0 {
		return 0
	}
	urls := make([]string, 0, len(sources))
	for u := range sources {
		urls = append(urls, u)
	}
	sort.Strings(urls)

	seeded := 0
	for i := range agg.endpoints {
		ep := &agg.endpoints[i]
		if ep.SeedID != "" {
			continue
		}
		host, segs, ok := pathSegments(ep.URL)
		if !ok {
			continue
		}
		at := -1
		for j, s := range segs {
			if isTemplateSegment(s) {
				at = j
				break
			}
		}
		if at < 1 {
			continue
		}
		want := resourceStem(segs[at-1])
		shared := segs[:at-1]
		for _, src := range urls {
			if src == ep.URL {
				continue
			}
			srcHost, srcSegs, ok := pathSegments(src)
			if !ok || srcHost != host || len(srcSegs) <= len(shared) {
				continue
			}
			prefixOK := true
			for k, s := range shared {
				if srcSegs[k] != s {
					prefixOK = false
					break
				}
			}
			if !prefixOK {
				continue
			}
			for _, s := range srcSegs[len(shared):] {
				if !isTemplateSegment(s) && resourceStem(s) == want {
					ep.SeedID = sources[src]
					seeded++
					break
				}
			}
			if ep.SeedID != "" {
				break
			}
		}
	}
	return seeded
}
