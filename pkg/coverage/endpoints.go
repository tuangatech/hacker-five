// Package coverage answers "where did the pipeline lose this?" for a target or
// an endpoint, from what one `hackerfive agent` run already produced: what recon
// observed, the plan tree it built, the turns that dispatched its leaves, and
// the findings (docs/94-llm-finding-capability-strategy.md, LT-185).
//
// With ground truth (a known vulnerability) it says at which stage that
// vulnerability was lost, so a feature aimed at creating leaves can be scored by
// how many vulnerabilities it moves out of "no leaf built". Without ground truth
// it says how many observed endpoints have no leaf at all, an upper bound on the
// population the same feature could reach. It is a library, not harness code, so
// the agent can use the same classification as a coverage ledger on a real
// target. It is unrelated to pkg/coveragegap, which reports fingerprinted
// technologies that no detector or template covers.
package coverage

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/recon"
)

// Endpoint is one recon observation reduced to what coverage needs. It carries
// no values: path segments that look like data collapse to "{id}" and a query
// string keeps only its key names, so the ledger can be written to a stream or
// a results file without leaking an id, an email or a token.
type Endpoint struct {
	Method       string   `json:"method"`
	URL          string   `json:"url"`
	Source       string   `json:"source,omitempty"`
	Status       int      `json:"status,omitempty"`
	AuthRequired bool     `json:"auth_required,omitempty"`
	Params       []string `json:"params,omitempty"` // query-string keys and JSON body keys, names only
}

var (
	numericSegment = regexp.MustCompile(`^[0-9]+$`)
	uuidSegment    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexSegment     = regexp.MustCompile(`^[0-9a-fA-F]{20,}$`)
)

// redactSegment collapses a path segment that is a value rather than a route
// name. Spec placeholders ("{id}", "{{id}}") are already value-free.
func redactSegment(seg string) string {
	switch {
	case seg == "":
		return seg
	case numericSegment.MatchString(seg), uuidSegment.MatchString(seg), hexSegment.MatchString(seg), strings.ContainsAny(seg, "@"):
		return "{id}"
	}
	return seg
}

// RedactURL returns raw with data-shaped path segments collapsed, the query
// string reduced to "key=" pairs, and the fragment dropped, plus the query keys.
func RedactURL(raw string) (redacted string, queryKeys []string) {
	u, err := url.Parse(raw)
	if err != nil {
		return raw, nil
	}
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		segs[i] = redactSegment(s)
	}
	// Assembled by hand: url.URL.String would percent-encode a spec placeholder's braces.
	var b strings.Builder
	if u.Scheme != "" {
		b.WriteString(u.Scheme + "://")
	}
	b.WriteString(u.Host) // u.User is dropped on purpose: credentials are values
	b.WriteString(strings.Join(segs, "/"))
	var parts []string
	for _, pair := range strings.Split(u.RawQuery, "&") {
		k, _, _ := strings.Cut(pair, "=")
		if k == "" {
			continue
		}
		queryKeys = append(queryKeys, k)
		parts = append(parts, k+"=")
	}
	if len(parts) > 0 {
		b.WriteString("?" + strings.Join(parts, "&"))
	}
	return b.String(), queryKeys
}

// FromRecon reduces a recon result to its endpoint ledger entries.
func FromRecon(r *recon.ReconResult) []Endpoint {
	if r == nil {
		return nil
	}
	out := make([]Endpoint, 0, len(r.Endpoints))
	for _, ep := range r.Endpoints {
		redacted, keys := RedactURL(ep.URL)
		method := ep.Method
		if method == "" {
			method = "GET"
		}
		params := append(append([]string(nil), keys...), ep.BodyParamKeys...)
		sort.Strings(params)
		out = append(out, Endpoint{
			Method: strings.ToUpper(method), URL: redacted, Source: ep.Source,
			Status: ep.StatusCode, AuthRequired: ep.AuthRequired, Params: dedupe(params),
		})
	}
	return out
}

func dedupe(sorted []string) []string {
	var out []string
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// MaxLedgerEndpoints bounds an EndpointSet. A crawl of a large site can observe
// thousands of URLs; the ledger is for coverage arithmetic, not an archive.
const MaxLedgerEndpoints = 5000

// EndpointSet accumulates endpoints across the initial recon and any later
// refresh, one entry per method+URL. It is not safe for concurrent use; the
// orchestrator's loop is single-threaded.
type EndpointSet struct {
	seen    map[string]bool
	list    []Endpoint
	dropped int
}

// Add merges endpoints, ignoring ones already present.
func (s *EndpointSet) Add(eps []Endpoint) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	for _, ep := range eps {
		k := ep.Method + " " + ep.URL
		if s.seen[k] {
			continue
		}
		if len(s.list) >= MaxLedgerEndpoints {
			s.dropped++
			continue
		}
		s.seen[k] = true
		s.list = append(s.list, ep)
	}
}

// AddRecon is Add(FromRecon(r)).
func (s *EndpointSet) AddRecon(r *recon.ReconResult) { s.Add(FromRecon(r)) }

// List returns the accumulated endpoints in first-seen order.
func (s *EndpointSet) List() []Endpoint { return append([]Endpoint(nil), s.list...) }

// Dropped is how many endpoints were not kept because the set was full.
func (s *EndpointSet) Dropped() int { return s.dropped }
