package registry

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// maxTemplateLeavesPerTech bounds how many template-tag-matched leaves one
// TechFact can produce — a popular tag (e.g. "misconfig") could otherwise
// match hundreds of synced templates and explode the tree.
const maxTemplateLeavesPerTech = 5

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
}

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
// whose Tags contain techName's normalized form (case-insensitive exact tag
// match) — R9's template index consumed by the decision engine, per doc14
// Step 3's R8 text.
func matchTemplateTags(techName string, index []templatesync.Entry) []templatesync.Entry {
	want := NormalizeTechName(techName)
	if want == "" {
		return nil
	}
	var matched []templatesync.Entry
	for _, entry := range index {
		for _, tag := range entry.Tags {
			if strings.ToLower(tag) == want {
				matched = append(matched, entry)
				break
			}
		}
		if len(matched) >= maxTemplateLeavesPerTech {
			break
		}
	}
	return matched
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
		for _, fact := range byHost[host] {
			leaves := resolveTechFact(host, fact, templateIndex, result.Endpoints, &leafIdx)
			hostNode.Children = append(hostNode.Children, leaves...)
		}
		root.Children = append(root.Children, hostNode)
	}
	return &agenttask.PlanTree{Root: root}
}

func resolveTechFact(host string, fact recon.TechFact, templateIndex []templatesync.Entry, endpoints []recon.EndpointFact, leafIdx *int) []*agenttask.PlanNode {
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
			Rationale:  fmt.Sprintf("tech fact %q (source: %s) matches template tag on %q", fact.Name, fact.Source, entry.ID),
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
