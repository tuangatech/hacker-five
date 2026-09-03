package mcpserver

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/workerpool"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// recognizedDetectors mirrors pkg/scanner/config.go's own unexported set —
// duplicated rather than exported from pkg/scanner, since it's a small,
// stable list and cfg.Validate() (called per leaf below) remains the real
// authority; this copy only decides whether a leaf is even worth building a
// Config for. A leaf whose Detector is a raw template ID (registry.Resolve's
// template-tag-match case, or an I4 use_existing_tag decision naming a
// template rather than a built-in detector) is dispatched separately, as a
// templates-only run — see RunPlan's eligibility loop and runLeaf, below
// (doc15 Step 2 addendum, 2026-09-03 — this used to be skipped entirely,
// matching pkg/webui's own still-informational-only treatment of the same
// case; RunPlan is now the one place that gap is closed).
var recognizedDetectors = map[string]bool{
	"idor": true, "misconfig": true, "authbypass": true, "ssrf": true, "businesslogic": true,
}

// executionResult is one leaf's dispatch outcome, folded into RunPlan's
// return value.
type executionResult struct {
	findings []detectors.Finding
	logs     []string
	err      error
}

// RunPlan walks tree's leaves and dispatches each eligible one to a real
// scanner.Engine run, using baseCfg as the shared template (Scope,
// AuthToken, EndpointTemplate, ProtectedPaths, SSRFParams, AllowWrites,
// ExtraHeaders, TemplatePaths, Concurrency/RateLimit/Timeout — everything
// except Targets/Detector/TemplateID, which this function fills per leaf).
// Eligible leaves are R8-matched or use_existing_tag-resolved leaves whose
// Detector is either one of scanner's recognized built-in names, or a real
// template ID/tag present in templateIndex — dispatched as a templates-only
// run in that second case (runLeaf). draft_template and escalate_to_human
// leaves, and any Detector matching neither a built-in name nor a real
// template ID (a hallucination), are skipped (never executed this step,
// per the Definition of Done's "never running against a live target
// without separate human promotion"). Skipped leaves are reported via
// skipped, not silently dropped.
func RunPlan(ctx context.Context, session *mcp.ServerSession, token any, tree *agenttask.PlanTree, baseCfg scanner.Config, templateIndex []templatesync.Entry) (findings []detectors.Finding, logs []string, skipped []string, err error) {
	knownTemplateIDs := make(map[string]bool, len(templateIndex))
	for _, entry := range templateIndex {
		knownTemplateIDs[entry.ID] = true
	}

	var deterministic, llmAssisted []*agenttask.PlanNode
	for _, leaf := range agenttask.Leaves(tree.Root) {
		eligible := recognizedDetectors[leaf.Detector] || (leaf.Detector != "" && knownTemplateIDs[leaf.Detector])
		if !eligible {
			if leaf.Detector != "" {
				skipped = append(skipped, fmt.Sprintf("%s: not executed this step (unrecognized detector/template-ID %q — requires separate human promotion or manual run)", leaf.ID, leaf.Detector))
			}
			continue
		}
		if reason := missingRequiredField(leaf.Detector, baseCfg); reason != "" {
			skipped = append(skipped, fmt.Sprintf("%s: skipped — %s (same skip-and-explain posture as pkg/webui's fillReconFields)", leaf.ID, reason))
			continue
		}
		if strings.HasPrefix(leaf.Rationale, llmfallback.ResolvedRationalePrefix) {
			llmAssisted = append(llmAssisted, leaf)
		} else {
			deterministic = append(deterministic, leaf)
		}
	}

	var mu sync.Mutex
	dispatch := func(pool *workerpool.Pool, batch []*agenttask.PlanNode) {
		for _, leaf := range batch {
			leaf := leaf
			_ = pool.Submit(func(ctx context.Context) error {
				res := runLeaf(ctx, session, token, leaf, baseCfg)
				mu.Lock()
				findings = append(findings, res.findings...)
				logs = append(logs, res.logs...)
				mu.Unlock()
				status := agenttask.StatusDone
				patch := agenttask.PlanNodePatch{Status: &status}
				if res.err != nil {
					msg := res.err.Error()
					patch.Rationale = &msg
				}
				_ = tree.ApplyLeafUpdate(leaf.ID, patch)
				return res.err
			})
		}
	}

	detPool := workerpool.New(ctx, defaultConcurrency, 2*defaultConcurrency)
	dispatch(detPool, deterministic)
	detErrs := detPool.Wait()

	llmPool := workerpool.New(ctx, llmAssistedExecConcurrency, 2*llmAssistedExecConcurrency)
	dispatch(llmPool, llmAssisted)
	llmErrs := llmPool.Wait()

	allErrs := append(detErrs, llmErrs...)
	if len(allErrs) > 0 {
		err = fmt.Errorf("plan execution completed with %d leaf error(s), first: %w", len(allErrs), allErrs[0])
	}
	return findings, logs, skipped, err
}

// missingRequiredField reports, in plain text, which of idor's
// EndpointTemplate, authbypass's ProtectedPaths, or ssrf's SSRFParams is
// still empty on cfg for detector — "" if detector has no such requirement
// or it's already filled. Mirrors pkg/webui's fillReconFields: a detector
// that needs a field recon/I4 couldn't resolve is skipped outright, never
// run against a live target with SkipXRequired papering over a blank
// value.
func missingRequiredField(detector string, cfg scanner.Config) string {
	switch detector {
	case "idor":
		if cfg.EndpointTemplate == "" {
			return "no --endpoint given and recon/I4 found no usable candidate"
		}
	case "authbypass":
		if len(cfg.ProtectedPaths) == 0 {
			return "no --protected-paths given and recon/I4 found no usable candidate"
		}
	case "ssrf":
		if len(cfg.SSRFParams) == 0 {
			return "no --ssrf-param given and recon found no usable candidate"
		}
	}
	return ""
}

func runLeaf(ctx context.Context, session *mcp.ServerSession, token any, leaf *agenttask.PlanNode, baseCfg scanner.Config) executionResult {
	cfg := baseCfg
	cfg.Targets = []string{leaf.Target}

	opts := scanner.ValidateOptions{
		SkipEndpointRequired:       true,
		SkipProtectedPathsRequired: true,
		SkipSSRFParamsRequired:     true,
		SkipAuthTokenRequired:      true,
	}
	if recognizedDetectors[leaf.Detector] {
		cfg.Detector = leaf.Detector
	} else {
		// A specific-template leaf, not a built-in detector — RunPlan's
		// eligibility loop only lets a leaf reach here if leaf.Detector is
		// either a recognized detector name or a real template ID/tag, so
		// anything not the former is the latter. TemplatePaths stays
		// baseCfg's own (the same synced+bundled directories the whole plan
		// already uses) — narrowing to just this one template happens by
		// exact id: match at load time (Config.TemplateID), not by pointing
		// at a different directory.
		cfg.Detector = ""
		cfg.TemplateID = leaf.Detector
		opts.SkipDetectorRequired = true
	}

	if err := cfg.ValidateWithOptions(opts); err != nil {
		return executionResult{err: fmt.Errorf("leaf %s: %w", leaf.ID, err)}
	}

	var res executionResult
	notify := func(message string) {
		if token == nil {
			return
		}
		_ = session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{
			ProgressToken: token,
			Message:       leaf.Target + ": " + message,
		})
	}

	engine := scanner.New(cfg).
		WithFindingCallback(func(f detectors.Finding) {
			res.findings = append(res.findings, f)
			notify("finding: " + f.Type)
		}).
		WithLogCallback(func(level, msg string) {
			res.logs = append(res.logs, level+": "+msg)
			notify(msg)
		})

	if _, err := engine.Run(ctx); err != nil {
		res.err = fmt.Errorf("leaf %s: %w", leaf.ID, err)
	}
	return res
}
