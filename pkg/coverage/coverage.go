package coverage

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// Stage is the furthest point in the pipeline something reached, in pipeline
// order. Everything below StageFound is a way of losing it; the numbers are the
// ones docs/follow-up.md LT-185 and docs/94 use.
type Stage int

const (
	StageNotObserved   Stage = 0 // recon never observed the endpoint
	StageNoLeaf        Stage = 1 // observed, but no leaf of the right class was built for it
	StageBlocked       Stage = 2 // a leaf exists but cannot run: a required field is missing, it is unresolved, or a gate is off
	StageNotDispatched Stage = 3 // runnable, but no turn ever dispatched it
	StageNoFinding     Stage = 4 // dispatched, and the detector raised nothing for it
	StageMismatch      Stage = 5 // dispatched and same-class findings exist elsewhere: possibly a ground-truth mismatch
	StageGated         Stage = 6 // unreachable by design: no agent route to the capability
	StageFound         Stage = 7 // a matching finding exists
)

var stageNames = map[Stage]string{
	StageNotObserved:   "not-observed",
	StageNoLeaf:        "no-leaf",
	StageBlocked:       "blocked",
	StageNotDispatched: "not-dispatched",
	StageNoFinding:     "no-finding",
	StageMismatch:      "mismatch",
	StageGated:         "gated",
	StageFound:         "found",
}

// String is the stable label results files carry, e.g. "1-no-leaf".
func (s Stage) String() string { return fmt.Sprintf("%d-%s", int(s), stageNames[s]) }

// Run is what one agent run produced. Every field is optional; a missing input
// only lowers what can be concluded (with no Endpoints nothing can be observed).
type Run struct {
	Endpoints []Endpoint
	Tree      *agenttask.PlanTree
	History   []llmfallback.TurnRecord
	Findings  []detectors.Finding
}

// Target is one thing to trace through the pipeline: a documented vulnerability,
// or a hypothesis about an endpoint.
type Target struct {
	Name string
	// EndpointContains selects the recon endpoints it lives on (case-insensitive
	// substring of the redacted URL), and the findings that count as detecting
	// it. Empty means it is not tied to one endpoint.
	EndpointContains string
	// FindingPrefixes are the finding-ID prefixes that detect it ("idor-"). They
	// also decide which leaves are of the right class: a leaf counts when its
	// detector is the first token of a prefix, or the prefix starts with the
	// detector's name. Empty accepts any leaf and any finding.
	FindingPrefixes []string
	// Gated, when set, says why no agent route reaches it; an unfound target with
	// it reports StageGated whatever else is true.
	Gated string
}

// Attribution is where a Target was lost, and why in one sentence.
type Attribution struct {
	Stage   Stage
	Why     string
	LeafIDs []string // the leaves that cover the target, if any
}

// Attribute reports the furthest stage t reached in run.
func Attribute(run Run, t Target) Attribution {
	want := strings.ToLower(t.EndpointContains)
	var matched []Endpoint
	for _, ep := range run.Endpoints {
		if want == "" || strings.Contains(strings.ToLower(ep.URL), want) {
			matched = append(matched, ep)
		}
	}

	var classFindings int
	for _, f := range run.Findings {
		if !hasPrefixIn(f.ID, t.FindingPrefixes) {
			continue
		}
		classFindings++
		if want == "" || strings.Contains(strings.ToLower(f.Target), want) {
			return Attribution{Stage: StageFound, Why: "finding " + f.ID + " on " + f.Target}
		}
	}
	if t.Gated != "" {
		return Attribution{Stage: StageGated, Why: t.Gated}
	}

	turns := turnsByLeaf(run.History)
	var covering []*agenttask.PlanNode
	observedViaLeaf := false
	if run.Tree != nil {
		for _, leaf := range agenttask.Leaves(run.Tree.Root) {
			if !classMatches(leaf.Detector, t.FindingPrefixes) {
				continue
			}
			cov := leafCoverage(leaf)
			if want != "" && cov.pathContains(want) {
				observedViaLeaf = true
			}
			if cov.covers(matched, leaf.Target) {
				covering = append(covering, leaf)
			}
		}
	}

	if len(matched) == 0 && !observedViaLeaf {
		if want == "" {
			return Attribution{Stage: StageNotObserved, Why: "recon observed no endpoints"}
		}
		return Attribution{Stage: StageNotObserved, Why: fmt.Sprintf("no recon endpoint contains %q", t.EndpointContains)}
	}
	if len(covering) == 0 {
		return Attribution{Stage: StageNoLeaf, Why: fmt.Sprintf("%d recon endpoint(s) observed, but no leaf of this class covers them", len(matched))}
	}

	best, why := StageBlocked, ""
	var ids []string
	for _, leaf := range covering {
		ids = append(ids, leaf.ID)
		if st, w := leafStage(leaf, turns[leaf.ID]); st >= best {
			best, why = st, w
		}
	}
	if best == StageNoFinding && hasUnseededTemplate(matched) && len(t.FindingPrefixes) > 0 && hasPrefixIn("idor-", t.FindingPrefixes) {
		return Attribution{Stage: StageNoFinding, LeafIDs: ids,
			Why: "dispatched, but the route is keyed by an id placeholder and recon read no id for it from any list response, so a UUID-keyed route had no seed to test with"}
	}
	if best == StageNoFinding && classFindings > 0 && want != "" {
		return Attribution{Stage: StageMismatch, LeafIDs: ids,
			Why: fmt.Sprintf("dispatched, and %d same-class finding(s) exist on other endpoints: check the ground truth before blaming the detector", classFindings)}
	}
	return Attribution{Stage: best, Why: why, LeafIDs: ids}
}

// hasUnseededTemplate reports whether any endpoint is a templated route (a spec
// or bundle placeholder, no concrete id seen) that recon did not seed.
func hasUnseededTemplate(eps []Endpoint) bool {
	for _, ep := range eps {
		if ep.Templated && !ep.Seeded {
			return true
		}
	}
	return false
}

// EndpointRow is one recon endpoint and how far the endpoint-specific leaves
// that cover it got.
type EndpointRow struct {
	Endpoint Endpoint
	Stage    Stage // StageNoLeaf when no endpoint-specific leaf covers it
	LeafIDs  []string
}

// EndpointStages classifies every non-static recon endpoint by the furthest
// stage of any leaf that names it (its path, or a parameter it carries). Leaves
// that sweep a whole host do not count: they cover everything and so say nothing
// about a specific endpoint. The share left at StageNoLeaf is an upper bound on
// what a feature that builds leaves could reach; it includes endpoints no
// vulnerability class applies to. skippedStatic counts the static assets left out.
func EndpointStages(run Run) (rows []EndpointRow, skippedStatic int) {
	turns := turnsByLeaf(run.History)
	var leaves []*agenttask.PlanNode
	if run.Tree != nil {
		leaves = agenttask.Leaves(run.Tree.Root)
	}
	for _, ep := range run.Endpoints {
		if p := endpointPath(ep.URL); recon.IsStaticAssetPath(p) {
			skippedStatic++
			continue
		}
		row := EndpointRow{Endpoint: ep, Stage: StageNoLeaf}
		for _, leaf := range leaves {
			cov := leafCoverage(leaf)
			if !cov.specific() || !cov.covers([]Endpoint{ep}, leaf.Target) {
				continue
			}
			row.LeafIDs = append(row.LeafIDs, leaf.ID)
			st, _ := leafStage(leaf, turns[leaf.ID])
			if row.Stage == StageNoLeaf || st > row.Stage {
				row.Stage = st
			}
		}
		if row.Stage <= StageNoFinding && findingOn(run.Findings, ep) {
			row.Stage = StageFound
		}
		rows = append(rows, row)
	}
	return rows, skippedStatic
}

// Histogram counts rows per stage.
func Histogram(rows []EndpointRow) map[Stage]int {
	h := map[Stage]int{}
	for _, r := range rows {
		h[r.Stage]++
	}
	return h
}

// FormatHistogram renders a stage histogram as "1-no-leaf: 40, 3-not-dispatched: 2".
func FormatHistogram(h map[Stage]int) string {
	stages := make([]int, 0, len(h))
	for s := range h {
		stages = append(stages, int(s))
	}
	sort.Ints(stages)
	parts := make([]string, 0, len(stages))
	for _, s := range stages {
		parts = append(parts, fmt.Sprintf("%s: %d", Stage(s), h[Stage(s)]))
	}
	return strings.Join(parts, ", ")
}

// ---- leaf coverage --------------------------------------------------------

// leafCover is what a leaf names: the endpoint paths and parameters it was built
// for. A leaf naming neither sweeps its whole host.
type leafCover struct {
	paths  []string // path shapes, see pathShape
	params []string // query/body parameter names
}

func (c leafCover) specific() bool { return len(c.paths) > 0 || len(c.params) > 0 }

func leafCoverage(l *agenttask.PlanNode) leafCover {
	var c leafCover
	add := func(p string) {
		if p != "" {
			c.paths = append(c.paths, pathShape(p))
		}
	}
	add(l.EndpointTemplate)
	add(l.SQLiPath)
	add(l.SSRFPath)
	add(l.CouponMintPath)
	add(l.CouponApplyPath)
	for _, p := range l.ProtectedPaths {
		add(p)
	}
	c.params = append(append(c.params, l.SSRFParams...), l.SSRFBodyParams...)
	c.params = append(c.params, l.SQLiParams...)
	return c
}

// pathContains reports whether any of the leaf's paths contains want.
func (c leafCover) pathContains(want string) bool {
	for _, p := range c.paths {
		if strings.Contains(strings.ToLower(p), want) {
			return true
		}
	}
	return false
}

// covers reports whether the leaf applies to any of eps. A host-wide leaf covers
// every endpoint on its host; a specific one covers an endpoint whose path shape
// it names (the leaf's path may lack the service prefix a target URL adds, so a
// suffix match counts) or that carries a parameter it names.
func (c leafCover) covers(eps []Endpoint, leafTarget string) bool {
	for _, ep := range eps {
		if !c.specific() {
			if hostOf(ep.URL) == hostOf(leafTarget) {
				return true
			}
			continue
		}
		shape := pathShape(endpointPath(ep.URL))
		for _, p := range c.paths {
			if shape == p || strings.HasSuffix(shape, p) {
				return true
			}
		}
		for _, want := range c.params {
			for _, have := range ep.Params {
				if strings.EqualFold(want, have) {
					return true
				}
			}
		}
	}
	return false
}

// pathShape normalises a URL path (query dropped) so a leaf's templated path and
// an observed one compare equal: every id-shaped or placeholder segment becomes
// "{}", and case is folded.
func pathShape(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		switch {
		case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
			segs[i] = "{}"
		case redactSegment(s) == "{id}":
			segs[i] = "{}"
		default:
			segs[i] = strings.ToLower(s)
		}
	}
	return strings.Join(segs, "/")
}

func endpointPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return path.Clean("/" + strings.TrimPrefix(u.Path, "/"))
}

// hostOf returns the hostname of a URL or a bare "host[:port]" leaf target.
func hostOf(s string) string {
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.ToLower(s)
	}
	return strings.ToLower(u.Hostname())
}

func findingOn(fs []detectors.Finding, ep Endpoint) bool {
	shape := pathShape(endpointPath(ep.URL))
	host := hostOf(ep.URL)
	for _, f := range fs {
		if hostOf(f.Target) == host && pathShape(endpointPath(f.Target)) == shape {
			return true
		}
	}
	return false
}

// ---- leaf stage -----------------------------------------------------------

func turnsByLeaf(history []llmfallback.TurnRecord) map[string][]llmfallback.TurnRecord {
	m := map[string][]llmfallback.TurnRecord{}
	for _, t := range history {
		if t.Action.Kind == "scan.leaf" && t.Action.NodeID != "" {
			m[t.Action.NodeID] = append(m[t.Action.NodeID], t)
		}
	}
	return m
}

const maxReasonLen = 200

// leafStage is the furthest stage one leaf reached: blocked (it never ran, with
// the reason), runnable but never dispatched, or dispatched. A leaf dispatched
// more than once counts by its best attempt, since a field-miss retry can turn a
// skip into a run.
func leafStage(l *agenttask.PlanNode, turns []llmfallback.TurnRecord) (Stage, string) {
	best, why := Stage(-1), ""
	for _, t := range turns {
		st, w := StageNoFinding, "dispatched; its detector raised nothing for it"
		switch {
		case t.Error != "":
			st, w = StageBlocked, "dispatch failed: "+clip(t.Error)
		case strings.HasPrefix(t.ResultSummary, "skipped:"):
			st, w = StageBlocked, clip(t.ResultSummary)
		}
		if st > best {
			best, why = st, w
		}
	}
	if best >= 0 {
		return best, why
	}
	switch {
	case l.Status == agenttask.StatusPending && l.Detector != "":
		return StageNotDispatched, "runnable, but no turn dispatched it"
	case l.Status == agenttask.StatusDone:
		return StageNoFinding, "executed outside the turn history; its detector raised nothing for it"
	default:
		return StageBlocked, fmt.Sprintf("leaf is %s and cannot run", statusLabel(l))
	}
}

func statusLabel(l *agenttask.PlanNode) string {
	if l.Detector == "" {
		return string(l.Status) + " with no detector assigned"
	}
	return string(l.Status)
}

func clip(s string) string {
	if len(s) > maxReasonLen {
		return s[:maxReasonLen] + "…"
	}
	return s
}

// ---- class matching -------------------------------------------------------

func hasPrefixIn(id string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// classMatches reports whether a leaf with this detector could produce a finding
// with one of prefixes: "idor" for "idor-", "authbypass" for "authbypass-jwt-",
// and a template-ID detector for the finding IDs it names. No prefixes accepts
// any leaf; no detector never matches.
func classMatches(detector string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	d := strings.ToLower(detector)
	if d == "" {
		return false
	}
	for _, p := range prefixes {
		p = strings.ToLower(p)
		tok, _, _ := strings.Cut(p, "-")
		if d == tok || strings.HasPrefix(d, tok+"-") || strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
