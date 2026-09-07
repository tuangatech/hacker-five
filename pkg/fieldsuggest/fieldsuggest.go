// Package fieldsuggest turns a recon.ReconResult into
// agenttask.FieldSuggestion values for a detector's required config field
// (idor's --endpoint, authbypass's --protected-paths, ssrf's --ssrf-param) —
// the deterministic, no-LLM half of what pkg/mcpserver's plan tool has done
// since doc15 Step 2 (resolveFieldSuggestions), lifted here so the CLI
// (cmd/hackerfive's plan/scan) can reuse the exact same logic instead of a
// second copy that drifts (follow-up.md LT-41, doc16 Phase 7 Step 1 A6).
//
// It imports only pkg/recon and pkg/agenttask: it never applies a value to a
// scanner.Config and never calls a model. A caller applies the returned
// suggestions to its own config, and — if it wants — resolves the returned
// Miss entries (idor's 0-or-many endpoint case, authbypass's 0
// protected-paths case) via llmfallback.ResolveField itself.
package fieldsuggest

import (
	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// Miss is a required field the deterministic pass could not fill: either no
// recon-derived candidate at all, or (for idor) more than one with no way to
// choose between them without judgement. A caller may leave it unfilled (the
// detector's own "required" validation then fires) or hand it to
// llmfallback.ResolveField.
type Miss struct {
	Detector   string
	Field      string
	Candidates []string // 0, or >1 for idor's ambiguous case
}

// Deterministic returns every no-LLM field auto-fill derivable from result
// for the detectors flagged in want, plus the genuine misses.
//
// want gates every per-detector block — a field suggestion only ever fills a
// field on an already-emitted leaf, so a detector with no leaf (want[d] ==
// false) yields nothing. This mirrors mcpserver.resolveFieldSuggestions'
// planLeafDetectors gate and the doc15 DoD rule that I4 "fires only on a
// confirmed decision-engine miss — never as a standing parallel path": a
// caller that only runs ResolveField on the returned misses keeps that
// property, since a want-excluded detector produces no Miss.
//
// The branching and rationale strings match mcpserver.resolveFieldSuggestions
// exactly, so moving a caller onto this function is a no-op for its output.
func Deterministic(result *recon.ReconResult, want map[string]bool) (suggestions []agenttask.FieldSuggestion, misses []Miss) {
	if result == nil {
		return nil, nil
	}

	if want["idor"] {
		cands := recon.SuggestIDOREndpointCandidates(result)
		if len(cands) == 1 {
			suggestions = append(suggestions, agenttask.FieldSuggestion{
				Detector:       "idor",
				Field:          "endpoint_template",
				SuggestedValue: cands[0],
				Rationale:      "single recon-derived candidate, auto-filled",
			})
		} else {
			misses = append(misses, Miss{Detector: "idor", Field: "endpoint_template", Candidates: cands})
		}
	}

	if want["authbypass"] {
		protected, login, logout := recon.SuggestAuthBypassPathsFromRecon(result)
		switch len(protected) {
		case 1:
			suggestions = append(suggestions, agenttask.FieldSuggestion{
				Detector:       "authbypass",
				Field:          "protected_paths",
				SuggestedValue: protected[0],
				Rationale:      "single recon-derived candidate, auto-filled",
			})
		case 0:
			misses = append(misses, Miss{Detector: "authbypass", Field: "protected_paths", Candidates: protected})
		default:
			suggestions = append(suggestions, agenttask.FieldSuggestion{
				Detector:   "authbypass",
				Field:      "protected_paths",
				Candidates: protected,
				Rationale:  "multiple recon-derived candidates — all usable directly, no ambiguity to resolve",
			})
		}
		if len(login) > 0 {
			suggestions = append(suggestions, agenttask.FieldSuggestion{
				Detector:   "authbypass",
				Field:      "login_paths",
				Candidates: login,
				Rationale:  "recon-derived, auto-fillable",
			})
		}
		if len(logout) > 0 {
			suggestions = append(suggestions, agenttask.FieldSuggestion{
				Detector:   "authbypass",
				Field:      "logout_paths",
				Candidates: logout,
				Rationale:  "recon-derived, auto-fillable",
			})
		}
	}

	if want["ssrf"] {
		if params := recon.SuggestSSRFParamsFromRecon(result); len(params) > 0 {
			suggestions = append(suggestions, agenttask.FieldSuggestion{
				Detector:   "ssrf",
				Field:      "ssrf_params",
				Candidates: params,
				Rationale:  "every recon-derived candidate is directly usable, no ambiguity to resolve",
			})
		}
	}

	return suggestions, misses
}
