package orchestrator

import (
	"context"
	"errors"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// ErrModelDisabled is what NoModelClient answers every call with.
var ErrModelDisabled = errors.New("the model is disabled for this run (--no-model)")

// NoModelClient is the LLMClient for a run that must not use a model: every
// method fails at once with ErrModelDisabled, and Run recognizes it and goes
// straight to the deterministic path (the fast lane) instead of spending failed
// decision calls to find out. It is the control arm of the ablation harness
// (docs/94-llm-finding-capability-strategy.md, Phase 0) — "what does this run
// find with no model at all" — and lets an unattended run proceed with no API
// key configured.
type NoModelClient struct{}

func (NoModelClient) NextAction(context.Context, *agenttask.PlanTree, []llmfallback.ToolSpec, []llmfallback.TurnRecord, llmfallback.RunDigest) (llmfallback.Action, float64, error) {
	return llmfallback.Action{}, 0, ErrModelDisabled
}

func (NoModelClient) TriageFindings(context.Context, []detectors.Finding) (llmfallback.TriageResult, float64, error) {
	return llmfallback.TriageResult{}, 0, ErrModelDisabled
}

func (NoModelClient) ResolveField(context.Context, string, string, []string) (llmfallback.FieldDecision, float64, error) {
	return llmfallback.FieldDecision{}, 0, ErrModelDisabled
}
