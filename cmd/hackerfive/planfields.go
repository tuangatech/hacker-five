package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/fieldsuggest"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// planCmdOutput is `hackerfive plan`'s stdout shape since doc16 Phase 7 Step
// 1 A6. Before A6 the command emitted a bare agenttask.PlanTree; it now emits
// the tree plus the recon-derived field suggestions that were previously
// computed only inside the MCP plan tool (follow-up.md LT-41). FieldSuggestions
// is omitempty, so a misconfig-only plan's output is unchanged bar the one
// added wrapper key.
type planCmdOutput struct {
	Tree             *agenttask.PlanTree         `json:"tree"`
	FieldSuggestions []agenttask.FieldSuggestion `json:"field_suggestions,omitempty"`
}

// planLeafDetectors is cmd/hackerfive's copy of mcpserver's helper of the same
// name: the set of detector names tree's leaves carry, gating which
// recon-derived field suggestions have a leaf to apply to (a suggestion only
// ever fills a field on an already-emitted leaf).
func planLeafDetectors(tree *agenttask.PlanTree) map[string]bool {
	out := map[string]bool{}
	if tree == nil {
		return out
	}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Detector != "" {
			out[leaf.Detector] = true
		}
	}
	return out
}

// treeHasEndpointDrivenIdorLeaf reports whether tree carries an idor leaf
// that already has its own EndpointTemplate (registry's LT-91 per-candidate
// fan-out) — idor's endpoint field then needs no further resolution.
func treeHasEndpointDrivenIdorLeaf(tree *agenttask.PlanTree) bool {
	if tree == nil {
		return false
	}
	for _, leaf := range agenttask.Leaves(tree.Root) {
		if leaf.Detector == "idor" && leaf.EndpointTemplate != "" {
			return true
		}
	}
	return false
}

// planFieldSuggestions returns the recon-derived field suggestions for tree's
// leaf detectors: fieldsuggest.Deterministic's no-LLM auto-fills always, plus
// — when llmAssist — an I4 resolution (llmfallback.ResolveFieldMiss) of each
// genuine miss (idor's 0-or-many endpoint case, authbypass's 0
// protected-paths case), its cost added to tree.SpendSoFar. Without llmAssist
// a miss is surfaced as an advisory escalate-to-human note and no model is
// called — mirrors the MCP plan tool's own fb==nil path. Unlike the MCP tool,
// this never writes a value into a scanner.Config: `hackerfive plan` only
// prints the tree, and `hackerfive scan` does its own single-candidate
// auto-fill from fieldsuggest.Deterministic directly.
func planFieldSuggestions(ctx context.Context, result *recon.ReconResult, tree *agenttask.PlanTree, llmAssist bool, fb *llmfallback.Client, fbErr error, stderr io.Writer) []agenttask.FieldSuggestion {
	sugs, misses := fieldsuggest.Deterministic(result, planLeafDetectors(tree))

	for _, m := range misses {
		// LT-91: idor's ">1 endpoint candidate" is not a miss once the
		// decision engine has fanned out a per-candidate idor leaf for each —
		// every candidate is already being enumerated on its own leaf.
		if m.Detector == "idor" && m.Field == "endpoint_template" && treeHasEndpointDrivenIdorLeaf(tree) {
			continue
		}
		fs := agenttask.FieldSuggestion{Detector: m.Detector, Field: m.Field, Candidates: m.Candidates}
		if !llmAssist {
			fs.EscalateToHuman = "no unambiguous recon candidate — pass the field explicitly to scan, or re-run plan with --llm-assist"
			sugs = append(sugs, fs)
			continue
		}
		decision, cost := llmfallback.ResolveFieldMiss(ctx, fb, fbErr, m.Detector, m.Field, m.Candidates)
		tree.AddSpend(cost)
		if decision.EscalateToHuman != "" {
			fs.EscalateToHuman = decision.EscalateToHuman
			_, _ = fmt.Fprintf(stderr, "llm-assist: %s.%s: %s\n", m.Detector, m.Field, decision.EscalateToHuman)
		} else {
			fs.SuggestedValue = decision.SuggestedValue
			fs.Rationale = decision.Rationale
		}
		sugs = append(sugs, fs)
	}
	return sugs
}

// applyReconFieldSuggestion writes a deterministic recon-derived field value
// into cfg, but only when that field is still unset — `hackerfive scan
// --recon-file`'s self-fill (A6). An explicit --endpoint / --protected-paths
// / --ssrf-param therefore always wins. Only fieldsuggest.Deterministic's own
// (non-LLM, no-ambiguity) suggestions are ever passed here; a genuine miss is
// left for the detector's own "required" validation. Returns whether a value
// was written and a human-readable form of it for the stderr note.
func applyReconFieldSuggestion(cfg *scanner.Config, s agenttask.FieldSuggestion) (applied bool, value string) {
	switch s.Field {
	case "endpoint_template":
		if cfg.EndpointTemplate != "" || s.SuggestedValue == "" {
			return false, ""
		}
		cfg.EndpointTemplate = s.SuggestedValue
		return true, s.SuggestedValue
	case "protected_paths":
		if len(cfg.ProtectedPaths) > 0 {
			return false, ""
		}
		v := s.Candidates
		if s.SuggestedValue != "" {
			v = []string{s.SuggestedValue}
		}
		if len(v) == 0 {
			return false, ""
		}
		cfg.ProtectedPaths = v
		return true, strings.Join(v, ", ")
	case "login_paths":
		if len(cfg.LoginPaths) > 0 || len(s.Candidates) == 0 {
			return false, ""
		}
		cfg.LoginPaths = s.Candidates
		return true, strings.Join(s.Candidates, ", ")
	case "logout_paths":
		if len(cfg.LogoutPaths) > 0 || len(s.Candidates) == 0 {
			return false, ""
		}
		cfg.LogoutPaths = s.Candidates
		return true, strings.Join(s.Candidates, ", ")
	case "ssrf_params":
		if len(cfg.SSRFParams) > 0 || len(s.Candidates) == 0 {
			return false, ""
		}
		cfg.SSRFParams = s.Candidates
		return true, strings.Join(s.Candidates, ", ")
	}
	return false, ""
}
