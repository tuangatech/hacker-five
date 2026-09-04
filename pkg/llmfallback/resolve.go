package llmfallback

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner/workerpool"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// ResolvedRationalePrefix marks a leaf whose Detector was assigned by I4's
// fallback (ResolveLeaf's use_existing_tag), not deterministically by R8 —
// set on PlanNodePatch.Rationale by applyLeafDecision below.
// pkg/mcpserver's executor checks this prefix to pick a leaf's execution
// concurrency tier; it's a string convention rather than a new PlanNode
// field so agenttask's shared data model doesn't grow an executor-specific
// concept.
const ResolvedRationalePrefix = "llm-fallback: "

// proposedTemplatesDir is where an I4 draft_template decision's YAML lands.
// Deliberately a sibling of templates/, not a subdirectory of it: real gap
// found while wiring this — templatesync.DefaultBundledDir is "./templates/"
// and every existing loader (scanner.Engine, templates.list/search,
// cmd/hackerfive templates) walks it recursively, so templates/proposed
// would have been silently included in the live scan corpus the moment a
// draft landed there, defeating "never running against a live target
// without separate human promotion" outright. This path is never passed to
// any loader/dir list in this codebase.
const proposedTemplatesDir = "templates-proposed"

// resolveConcurrency caps how many I4 fallback calls (leaf resolution) run
// at once while ResolveTreeLeaves works through a tree — the real
// budget-burn-during-resolution concern doc15 Step 2's I4 section names
// (many parallel frontier calls burn spend before the spend ceiling gets a
// chance to trip). Small and fixed, not derived from a caller's own
// scan-concurrency setting.
const resolveConcurrency = 3

// ResolveTreeLeaves walks tree for StatusUnresolved leaves and resolves
// each via fb.ResolveLeaf, applying whichever decision comes back
// (use_existing_tag / needs_new_template / escalate) directly onto tree via
// ApplyLeafUpdate, respecting tree.SpendCeilingUSD. fb may be nil (e.g.
// New() returned ErrNoTierAvailable, fbErr) — every unresolved leaf is then
// reported as an escalation instead of attempting a call, rather than the
// caller having to special-case a nil client itself. leafContexts is
// registry.Resolve's own second return value (P2-2) — a missing entry for a
// given leaf ID degrades to ResolveLeaf's rationale-regex fallback, not an
// error, so a nil map is a valid argument. Returns one escalation note per
// leaf that couldn't be resolved (fb unavailable, spend ceiling reached, the
// call itself failed, or the model returned no usable decision) — shared by
// pkg/mcpserver's plan tool and pkg/webui's plan-preview page, so this
// orchestration is described once.
func ResolveTreeLeaves(ctx context.Context, fb *Client, fbErr error, tree *agenttask.PlanTree, capabilities []registry.Capability, templateIndex []templatesync.Entry, leafContexts map[string]registry.LeafContext) []string {
	var unresolved []*agenttask.PlanNode
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Status == agenttask.StatusUnresolved {
			unresolved = append(unresolved, leaf)
		}
	}
	if len(unresolved) == 0 {
		return nil
	}
	if fb == nil {
		var escalations []string
		for _, leaf := range unresolved {
			escalations = append(escalations, fmt.Sprintf("%s: LLM fallback unavailable (%v)", leaf.ID, fbErr))
		}
		return escalations
	}

	var (
		mu          sync.Mutex
		escalations []string
	)
	addEscalation := func(format string, args ...any) {
		mu.Lock()
		escalations = append(escalations, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	pool := workerpool.New(ctx, resolveConcurrency, 2*resolveConcurrency)
	for _, leaf := range unresolved {
		leaf := leaf
		_ = pool.Submit(func(ctx context.Context) error {
			if tree.SpendCeilingUSD > 0 && tree.SpendSoFar() >= tree.SpendCeilingUSD {
				addEscalation("%s: spend ceiling reached before this leaf could be resolved", leaf.ID)
				return nil
			}

			decision, cost, err := fb.ResolveLeaf(ctx, leaf, leafContexts[leaf.ID], capabilities, templateIndex)
			if tree.AddSpend(cost) {
				addEscalation("%s: spend ceiling exceeded resolving this leaf", leaf.ID)
			}
			if err != nil {
				addEscalation("%s: LLM fallback call failed: %v", leaf.ID, err)
				return nil
			}
			applyLeafDecision(tree, leaf, decision, addEscalation)
			return nil
		})
	}
	pool.Wait()
	return escalations
}

func applyLeafDecision(tree *agenttask.PlanTree, leaf *agenttask.PlanNode, decision LeafDecision, addEscalation func(format string, args ...any)) {
	switch {
	case decision.UseExistingTag != "":
		detector := decision.UseExistingTag
		status := agenttask.StatusPending
		rationale := ResolvedRationalePrefix + "resolved to existing tag " + detector
		_ = tree.ApplyLeafUpdate(leaf.ID, agenttask.PlanNodePatch{Detector: &detector, Status: &status, Rationale: &rationale})
	case decision.DraftTemplate != "":
		path, err := writeProposedTemplate(leaf.ID, decision.DraftTemplate)
		var rationale string
		if err != nil {
			rationale = "drafted template rejected: " + err.Error()
		} else {
			rationale = "drafted template written to " + path + " — pending human promotion, not executed by this plan run"
		}
		addEscalation("%s: %s", leaf.ID, rationale)
		_ = tree.ApplyLeafUpdate(leaf.ID, agenttask.PlanNodePatch{Rationale: &rationale})
	default:
		reason := decision.EscalateToHuman
		if reason == "" {
			reason = "LLM fallback returned no usable decision"
		}
		addEscalation("%s: %s", leaf.ID, reason)
		_ = tree.ApplyLeafUpdate(leaf.ID, agenttask.PlanNodePatch{Rationale: &reason})
	}
}

// writeProposedTemplate writes yamlBody to proposedTemplatesDir and
// validates it through the real existing untrusted-template rejection
// pipeline (pkg/template/nuclei's checkDisallowedBlocks, exercised via
// LoadDirDetailed) — a template that fails is deleted immediately, never
// left behind as a silent bad file.
func writeProposedTemplate(leafID, yamlBody string) (string, error) {
	if err := os.MkdirAll(proposedTemplatesDir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", proposedTemplatesDir, err)
	}
	safeName := strings.NewReplacer("/", "-", "\\", "-", ":", "-", " ", "-").Replace(leafID)
	path := filepath.Join(proposedTemplatesDir, safeName+".yaml")
	if err := os.WriteFile(path, []byte(yamlBody), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}

	_, loadErrs := nuclei.LoadDirDetailed(proposedTemplatesDir)
	for _, le := range loadErrs {
		if filepath.Clean(le.Path) == filepath.Clean(path) {
			_ = os.Remove(path)
			return "", le.Err
		}
	}
	return path, nil
}
