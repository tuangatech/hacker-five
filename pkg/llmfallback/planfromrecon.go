package llmfallback

import (
	"context"
	"fmt"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
)

// PlanProposal is one llm-suggested leaf PlanFromRecon returns — merged
// into (never replacing) registry.Resolve's own deterministic leaves by
// MergeLLMProposals. Detector must be a real registry.Capability name or
// templatesync.Entry.ID, the same dispatch contract ResolveLeaf's
// use_existing_tag decision already has to satisfy (P2-3) —
// MergeLLMProposals drops anything else rather than merging in a leaf that
// can never dispatch.
type PlanProposal struct {
	Target    string `json:"target"`
	Detector  string `json:"detector"`
	Rationale string `json:"rationale"`
}

type planFromReconResponse struct {
	Proposals       []PlanProposal `json:"proposals,omitempty"`
	EscalateToHuman string         `json:"escalate_to_human,omitempty"`
}

const planFromReconSystemPrompt = `You are HackerFive's recon-triage assistant. Given a full recon summary for one target (hosts, tech signals, endpoints, open ports) and the project's capability catalog, propose additional checks worth running that a simple per-fact rule table might miss — e.g. a combination of signals across hosts/endpoints that together suggest something a single tech fact alone wouldn't.

Only propose a target that already appears in the recon summary below — never invent a new host/domain. Only propose a detector that is an exact capability name from the catalog. If nothing beyond what a per-fact match would already find is worth proposing, return an empty proposals list.

Respond with ONLY a JSON object, no other text, matching this shape:
{"proposals": [{"target": "<exact host from the summary>", "detector": "<exact capability name from the catalog>", "rationale": "<short reason, referencing the specific signal(s) that justify it>"}], "escalate_to_human": "<optional short note, e.g. why proposals is empty despite something looking off>"}`

// maxSummaryHosts/Endpoints/TechFacts bound planFromReconSummary's prompt
// size against a large real recon result — a bounded sample, not the full
// result, mirrors buildLeafPrompt's own maxLeafPromptTags cap.
const (
	maxSummaryHosts     = 20
	maxSummaryTechFacts = 80
	maxSummaryEndpoints = 80
)

// planFromReconSummary renders result as plain text for the prompt.
// Deliberately omits HostFact.Notes (free-form WHOIS/ASN text that can
// carry a registrant's contact details) — not needed for template-selection
// reasoning, and result's other fields (TechFact/EndpointFact/PortFact) were
// already designed to carry no raw response body/header/cookie data at all
// (doc91 §4: "never raw tool stdout in an agent's context"), so there is
// little else here to redact — this is a bounded *summary*, not a
// data-stripping pass over otherwise-sensitive content.
func planFromReconSummary(result *recon.ReconResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n", result.Target)

	fmt.Fprintf(&b, "\nHosts (%d, showing up to %d):\n", len(result.Hosts), maxSummaryHosts)
	for i, h := range result.Hosts {
		if i >= maxSummaryHosts {
			break
		}
		ports := make([]string, 0, len(h.Ports))
		for _, p := range h.Ports {
			svc := p.Service
			if svc == "" {
				svc = "?"
			}
			ports = append(ports, fmt.Sprintf("%d/%s(%s)", p.Port, p.Protocol, svc))
		}
		fmt.Fprintf(&b, "- %s (source: %s)%s\n", h.Host, h.Source, portsSuffix(ports))
	}

	fmt.Fprintf(&b, "\nTech facts (%d, showing up to %d):\n", len(result.TechStack), maxSummaryTechFacts)
	for i, f := range result.TechStack {
		if i >= maxSummaryTechFacts {
			break
		}
		fmt.Fprintf(&b, "- %s: %q (source: %s, confidence: %s)\n", f.Host, f.Name, f.Source, f.Confidence)
	}

	fmt.Fprintf(&b, "\nEndpoints (%d, showing up to %d):\n", len(result.Endpoints), maxSummaryEndpoints)
	for i, e := range result.Endpoints {
		if i >= maxSummaryEndpoints {
			break
		}
		fmt.Fprintf(&b, "- %s %s (status %d)\n", e.Method, e.URL, e.StatusCode)
	}

	if len(result.Warnings) > 0 {
		fmt.Fprintf(&b, "\nRecon warnings: %s\n", strings.Join(result.Warnings, "; "))
	}
	return b.String()
}

func portsSuffix(ports []string) string {
	if len(ports) == 0 {
		return ""
	}
	return " ports: " + strings.Join(ports, ", ")
}

// PlanFromRecon is I4's 4th caller (P2-1, docs/follow-up.md): one
// local-tier-first call per plan run — not per leaf — that reasons over
// result's whole summarized recon output and proposes additional
// {target, detector, rationale} leaves a per-fact rule table might miss.
// Deliberately NOT wired into the MCP plan tool's or webui's default
// handlePlan flow: pkg/llmfallback's own package doc says I4 fires "only on
// a confirmed deterministic-decision-engine miss — never as a standing
// parallel path," and calling this unconditionally on every plan run (with
// leaves resolved or not) would make it exactly that. Wired only into CLI
// `plan --llm-assist` (cmd/hackerfive/plan.go), which is itself already an
// explicit opt-in — see docs/follow-up.md's P2-1 note for the full
// reasoning and the option to widen this later. costUSD is the cost of
// this one call (0 if only the local tier was used, or if fb is nil/errored
// — see PerCallDefaultSpendCeilingUSD's caller-side ceiling check, which
// callers should apply before invoking this the same way ResolveTreeLeaves
// does per leaf).
func (c *Client) PlanFromRecon(ctx context.Context, result *recon.ReconResult, capabilities []registry.Capability) ([]PlanProposal, float64, error) {
	var p strings.Builder
	p.WriteString(planFromReconSummary(result))
	p.WriteString("\nAvailable capabilities:\n")
	for _, cap := range capabilities {
		fmt.Fprintf(&p, "- %s: %s\n", cap.Name, cap.Description)
	}

	text, cost, err := c.completeBestAvailable(ctx, planFromReconSystemPrompt, p.String())
	if err != nil {
		return nil, cost, err
	}
	var resp planFromReconResponse
	if err := decodeJSONResponse(text, &resp); err != nil {
		return nil, cost, err
	}
	return resp.Proposals, cost, nil
}

// MergeLLMProposals adds proposals onto tree as new StatusPending leaves,
// with two hard safety filters neither ResolveLeaf nor ResolveField need
// (both only ever act on a leaf/field the deterministic engine already
// produced): (1) Target must already name a host node registry.Resolve
// itself created — never a new host string the model invented, since a
// merged leaf is real, dispatchable input to RunPlan against a live target,
// and CLAUDE.md's read/enumerate-only + explicit-scope rules apply just as
// much to an LLM-originated leaf as a deterministic one. (2) Detector must
// be a real registry.Capability name or knownTemplateIDs entry — the same
// dispatch contract P2-3 established for ResolveLeaf. A proposal failing
// either filter, or duplicating an existing (target, detector) leaf already
// under that host, is silently dropped, not escalated — this is best-effort
// broadened coverage, not a resolution the deterministic pass was relying
// on. Returns how many proposals were actually merged, for a caller that
// wants to log/report it.
func MergeLLMProposals(tree *agenttask.PlanTree, proposals []PlanProposal, capabilities []registry.Capability, knownTemplateIDs map[string]bool) int {
	if tree == nil || tree.Root == nil || len(proposals) == 0 {
		return 0
	}
	validDetector := make(map[string]bool, len(capabilities))
	for _, cap := range capabilities {
		validDetector[cap.Name] = true
	}

	merged := 0
	for _, p := range proposals {
		if p.Target == "" || p.Detector == "" {
			continue
		}
		if !validDetector[p.Detector] && !knownTemplateIDs[p.Detector] {
			continue // hallucinated/undispatchable name — never merged in
		}
		hostNode := tree.Find("host:" + p.Target)
		if hostNode == nil {
			continue // not a host registry.Resolve itself surfaced — never scan an LLM-invented target
		}
		if leafExists(hostNode, p.Target, p.Detector) {
			continue
		}
		rationale := p.Rationale
		if rationale == "" {
			rationale = "no rationale given"
		}
		hostNode.Children = append(hostNode.Children, &agenttask.PlanNode{
			ID:         fmt.Sprintf("%s-llm-plan-%d", p.Target, len(hostNode.Children)),
			Target:     p.Target,
			Detector:   p.Detector,
			Rationale:  ResolvedRationalePrefix + "recon-wide proposal: " + rationale,
			Status:     agenttask.StatusPending,
			Confidence: agenttask.ConfidenceLow,
		})
		merged++
	}
	return merged
}

func leafExists(hostNode *agenttask.PlanNode, target, detector string) bool {
	for _, child := range hostNode.Children {
		if child.Target == target && child.Detector == detector {
			return true
		}
	}
	return false
}
