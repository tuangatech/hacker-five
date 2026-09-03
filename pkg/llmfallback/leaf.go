package llmfallback

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

const leafSystemPrompt = `You are HackerFive's template-selection assistant. Given one unresolved recon tech fact and the project's own capability/template catalog, decide ONE of:
- an existing detector/template tag already covers this fact
- nothing in the catalog covers it and a brand-new nuclei template is warranted
- you are not confident enough either way and a human should decide

Respond with ONLY a JSON object, no other text, matching exactly one of these shapes:
{"decision": "use_existing_tag", "tag": "<exact name from the catalog>", "reason": "<short reason>"}
{"decision": "needs_new_template", "reason": "<short reason nothing in the catalog fits>"}
{"decision": "escalate", "reason": "<short reason you are not confident>"}`

type leafLocalResponse struct {
	Decision string `json:"decision"`
	Tag      string `json:"tag"`
	Reason   string `json:"reason"`
}

// draftTemplateSystemPrompt's rule list is a condensed subset of
// docs/template-writing-guide.md's "Supported" + "Rejected at load time"
// sections (the guide itself is not fed to the model — most of its length
// documents raw:/payloads:/flow: edge cases and the entirely separate
// native format, none of which this call ever needs, and teaching a model
// features it's told to avoid anyway just invites it to reach for them).
// Every rule named here is enforced for real at load time
// (pkg/template/nuclei/loader.go's validate + matcher/extractor
// ValidateWithContext) — a draft that ignores one doesn't silently run
// wrong, it gets rejected and the leaf escalates to a human with the raw
// parser error instead of a usable draft, wasting a real, metered frontier
// call. Keep this in sync with the guide's "Supported" section if that
// section's own list of types/parts ever changes.
const draftTemplateSystemPrompt = `You draft nuclei-compatible YAML vulnerability detection templates for HackerFive, a defensive security scanner used only against explicitly authorized targets. Draft a template for the given technology/gap.

Rules, every one enforced by a real load-time validator — a draft that breaks any of these is rejected outright, not run incompletely:
- Top-level YAML keys code, javascript, headless, file, dns, tcp, ssl, network, websocket, whois are rejected outright. Use only a top-level "http" block.
- Do not use raw:, payloads:, or flow: — each has narrow, easy-to-violate restrictions (multi-key payloads, wordlist-file payloads, and absolute-URI raw request lines are all rejected at load time). Use only plain http: requests: method, path, headers, body, matchers, extractors.
- Matcher "type" must be one of: word, regex, status, size, dsl. No other value is supported (e.g. "binary" is rejected).
- Extractor "type" must be one of: regex, kval, json, dsl.
- Matcher/extractor "part" must be one of: body (default), header, all, content_type, response.
- matchers-condition (top level, how multiple matchers combine) and condition (within one matcher's own word/regex/size list) are each "and" or "or"; default is "or" for both when omitted.
- Every path/headers/body string may use {{BaseURL}} substitution.

Respond with ONLY a JSON object, no other text, matching exactly one of these shapes:
{"draft_template": "<full YAML template as a string, following the rules and example above>", "reason": "<short reason>"}
{"escalate_to_human": "<short reason you cannot safely draft one within these rules>"}

Example of a valid, minimal draft_template value:
id: example-check
info:
  name: Example check
  severity: medium
  tags: example
http:
  - method: GET
    path:
      - "{{BaseURL}}/some/path"
    matchers:
      - type: word
        part: body
        words:
          - "some signature string"
        condition: or`

type draftTemplateResponse struct {
	DraftTemplate   string `json:"draft_template"`
	EscalateToHuman string `json:"escalate_to_human"`
	Reason          string `json:"reason"`
}

// ResolveLeaf is I4's first caller: leaf is an agenttask.StatusUnresolved
// PlanTree leaf (registry.Resolve found no registry/template-tag match —
// leaf.Rationale already documents which tech fact and why, so this takes
// no separate TechFact parameter), and this issues at most two stateless
// calls — one local-tier call to decide
// use_existing_tag/needs_new_template/escalate, and, only if that call says
// needs_new_template, one frontier-tier call to draft a new template.
// costUSD is the sum of every call actually made (0 if only the local tier
// was used).
func (c *Client) ResolveLeaf(ctx context.Context, leaf *agenttask.PlanNode, capabilities []registry.Capability, templates []templatesync.Entry) (LeafDecision, float64, error) {
	prompt := buildLeafPrompt(leaf, capabilities, templates)

	text, cost, err := c.completeBestAvailable(ctx, leafSystemPrompt, prompt)
	if err != nil {
		return LeafDecision{}, 0, err
	}

	var local leafLocalResponse
	if err := decodeJSONResponse(text, &local); err != nil {
		return LeafDecision{}, cost, err
	}

	switch local.Decision {
	case "use_existing_tag":
		if local.Tag == "" {
			return LeafDecision{EscalateToHuman: "model chose use_existing_tag with no tag"}, cost, nil
		}
		return LeafDecision{UseExistingTag: local.Tag}, cost, nil
	case "escalate":
		reason := local.Reason
		if reason == "" {
			reason = "model escalated with no reason given"
		}
		return LeafDecision{EscalateToHuman: reason}, cost, nil
	case "needs_new_template":
		if c.openRouterKey == "" {
			reason := local.Reason
			if reason == "" {
				reason = "model gave no reason"
			}
			return LeafDecision{EscalateToHuman: fmt.Sprintf("no existing tag fits (%s) and no frontier tier is configured to draft a new template", reason)}, cost, nil
		}
		draftText, draftCost, err := c.complete(ctx, tierFrontier, draftTemplateSystemPrompt, prompt)
		if err != nil {
			return LeafDecision{}, cost, err
		}
		var draft draftTemplateResponse
		if err := decodeJSONResponse(draftText, &draft); err != nil {
			return LeafDecision{}, cost + draftCost, err
		}
		if draft.DraftTemplate != "" {
			return LeafDecision{DraftTemplate: draft.DraftTemplate}, cost + draftCost, nil
		}
		reason := draft.EscalateToHuman
		if reason == "" {
			reason = "frontier tier declined to draft a template with no reason given"
		}
		return LeafDecision{EscalateToHuman: reason}, cost + draftCost, nil
	default:
		return LeafDecision{EscalateToHuman: fmt.Sprintf("model returned unrecognized decision %q", local.Decision)}, cost, nil
	}
}

// relevantTagLimit/maxLeafPromptTags bound buildLeafPrompt's tag sample in
// two tiers: up to relevantTagLimit tags scored relevant to this leaf's own
// tech fact (rankRelevantTags), then the existing fixed-order corpus walk
// fills any remaining capacity up to maxLeafPromptTags — a broad,
// deterministic base set (misconfig, exposed-panel, ...) as an escape
// hatch even when nothing scores well. Found live (doc15 Step 2's
// addendum, 2026-09-03): a fixed-order-only sample showed the same first
// ~200 of a 2,952-unique-tag corpus (before this project's own template
// categories were widened further) regardless of which tech fact
// triggered the call — a real, measured cause of avoidable
// needs_new_template decisions for cases that should have reused a tag.
const (
	relevantTagLimit  = 200
	maxLeafPromptTags = 300
)

// techFactNamePattern extracts the tech-fact name resolveTechFact
// (pkg/registry/decisionengine.go) embedded in an unresolved leaf's
// Rationale (`tech fact "X" (source: ...) matched no registry capability or
// template tag...`) — the one place that name is available to this prompt,
// since ResolveLeaf receives the leaf, not the originating TechFact itself.
var techFactNamePattern = regexp.MustCompile(`tech fact "([^"]*)"`)

func techNameFromRationale(rationale string) string {
	m := techFactNamePattern.FindStringSubmatch(rationale)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func buildLeafPrompt(leaf *agenttask.PlanNode, capabilities []registry.Capability, templates []templatesync.Entry) string {
	p := fmt.Sprintf("Unresolved leaf: target=%q\nRationale (names the unmatched tech fact): %s\n\nAvailable capabilities:\n",
		leaf.Target, leaf.Rationale)
	for _, cap := range capabilities {
		p += fmt.Sprintf("- %s: %s\n", cap.Name, cap.Description)
	}

	p += "\nAvailable template tags (sample):\n"
	seen := map[string]bool{}
	count := 0
	writeTag := func(tag string) {
		if seen[tag] || count >= maxLeafPromptTags {
			return
		}
		seen[tag] = true
		count++
		p += "- " + tag + "\n"
	}

	techName := techNameFromRationale(leaf.Rationale)
	for _, tag := range rankRelevantTags(techName, templates, relevantTagLimit) {
		writeTag(tag)
	}
	for _, t := range templates {
		for _, tag := range t.Tags {
			writeTag(tag)
		}
	}
	return p
}

// rankRelevantTags scores every unique tag across templates by relevance to
// techName and returns up to limit, highest-scored first — layered on top
// of (not a replacement for) buildLeafPrompt's own fixed-order fallback
// walk, so a techName that scores nothing still leaves the broader,
// deterministic base sample as an escape hatch. Mirrors this project's own
// established "cheap deterministic heuristic before an LLM read" pattern
// (pkg/registry's techRules/matchTemplateTags) applied one level deeper,
// inside I4's own prompt construction.
func rankRelevantTags(techName string, templates []templatesync.Entry, limit int) []string {
	if techName == "" || limit <= 0 {
		return nil
	}
	normalized := registry.NormalizeTechName(techName)
	if normalized == "" {
		return nil
	}
	words := tagWords(normalized)

	type scoredTag struct {
		original string
		score    int
	}
	seen := map[string]bool{}
	var candidates []scoredTag
	for _, t := range templates {
		for _, tag := range t.Tags {
			lower := strings.ToLower(tag)
			if seen[lower] {
				continue
			}
			score := tagRelevanceScore(normalized, words, lower)
			if score == 0 {
				continue
			}
			seen[lower] = true
			candidates = append(candidates, scoredTag{original: tag, score: score})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].original < candidates[j].original // deterministic tiebreak
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	out := make([]string, len(candidates))
	for i, c := range candidates {
		out[i] = c.original
	}
	return out
}

// tagRelevanceScore: exact match on the normalized tech name outranks a
// substring match either direction, which outranks a single-word overlap
// (for a multi-word product name like "apache http server") — anything
// else scores 0 and is dropped, not shown as a false-precision "match".
func tagRelevanceScore(normalized string, words []string, tag string) int {
	switch {
	case tag == normalized:
		return 3
	case strings.Contains(tag, normalized) || strings.Contains(normalized, tag):
		return 2
	default:
		for _, w := range words {
			if w != "" && (tag == w || strings.Contains(tag, w)) {
				return 1
			}
		}
		return 0
	}
}

// tagWords splits a normalized tech name on non-alphanumeric separators —
// "apache http server" -> ["apache", "http", "server"].
func tagWords(normalized string) []string {
	return strings.FieldsFunc(normalized, func(r rune) bool {
		return !isTagWordRune(r)
	})
}

func isTagWordRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

// completeBestAvailable tries the local tier first (the routine, low-cost
// case doc15 I4 describes), falling back to the frontier tier only if the
// local tier is unconfigured — draft-template authoring's own frontier call
// happens separately in ResolveLeaf, this is just "make the first,
// classification call somehow."
func (c *Client) completeBestAvailable(ctx context.Context, system, user string) (string, float64, error) {
	if c.localAvailable {
		text, cost, err := c.complete(ctx, tierLocal, system, user)
		if err == nil {
			return text, cost, nil
		}
		if c.openRouterKey == "" {
			return "", 0, err
		}
	}
	return c.complete(ctx, tierFrontier, system, user)
}
