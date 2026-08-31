package webui

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// guidedReadyDetectors need no additional per-target input beyond the
// target itself (checked against scanner.Config.Validate,
// pkg/scanner/config.go) — safe to auto-select once matched.
var guidedReadyDetectors = map[string]bool{"misconfig": true}

// guidedInputDetectors need operator-supplied, per-target secrets
// scanner.Config.Validate requires (auth tokens, an endpoint template,
// protected paths) that recon has no way to discover — the same set the
// Web UI's New Scan page already supports via detector_fields_idor.html/
// detector_fields_authbypass.html (handlers_scan.go's detectorFields).
// ssrf/businesslogic aren't wired into the Web UI at all yet (CLI-only) —
// a pre-existing gap, not something Guided Scan introduces; they, along
// with promptinjection (tag-based invocation, not a --detector flag) and
// any template-tag-matched leaf, fall into the "unsupported" bucket below.
var guidedInputDetectors = map[string]bool{"idor": true, "authbypass": true}

// flattenPlanTree walks tree depth-first into a flat leaf slice — a small
// local copy of the same helper tests/integration/recon_plan_crapi_test.go
// already has; not shared across a module boundary for one 10-line
// function used by only two packages.
func flattenPlanTree(tree *agenttask.PlanTree) []*agenttask.PlanNode {
	var out []*agenttask.PlanNode
	var walk func(n *agenttask.PlanNode)
	walk = func(n *agenttask.PlanNode) {
		if n == nil {
			return
		}
		out = append(out, n)
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(tree.Root)
	return out
}

// bucketMatchedCapabilities groups a resolved PlanTree's StatusPending
// leaves into what Guided Scan can act on, deduplicated by detector/
// template-ID name — the same capability can match multiple hosts or tech
// facts, but Guided Scan runs it once, against the recon job's own target
// (see GuidedScanPlanData's doc comment on that scope cut).
func bucketMatchedCapabilities(tree *agenttask.PlanTree) (ready, needsInput, unsupported []string) {
	seen := make(map[string]bool)
	for _, leaf := range flattenPlanTree(tree) {
		if leaf.Status != agenttask.StatusPending || leaf.Detector == "" || seen[leaf.Detector] {
			continue
		}
		seen[leaf.Detector] = true
		switch {
		case guidedReadyDetectors[leaf.Detector]:
			ready = append(ready, leaf.Detector)
		case guidedInputDetectors[leaf.Detector]:
			needsInput = append(needsInput, leaf.Detector)
		default:
			unsupported = append(unsupported, leaf.Detector)
		}
	}
	return ready, needsInput, unsupported
}

// unresolvedRationales returns every StatusUnresolved leaf's rationale —
// same informational, never-silently-dropped treatment plan_preview.html
// already gives these (Decision 6).
func unresolvedRationales(tree *agenttask.PlanTree) []string {
	var out []string
	for _, leaf := range flattenPlanTree(tree) {
		if leaf.Status == agenttask.StatusUnresolved {
			out = append(out, leaf.Rationale)
		}
	}
	return out
}

func buildGuidedScanPlanData(job *ReconJob, token string, ready, needsInput, unsupported, unresolved, errs []string) GuidedScanPlanData {
	return GuidedScanPlanData{
		CSRFToken:   token,
		JobID:       job.ID,
		Target:      job.Target,
		Errors:      errs,
		Ready:       ready,
		NeedsInput:  needsInput,
		Unsupported: unsupported,
		Unresolved:  unresolved,
	}
}

// resolveGuidedScanTree loads job's ReconResult and resolves it exactly the
// way planPreview does — same graceful degrade when templates/index.json
// is missing (template-tag matching skipped, not a hard failure).
func resolveGuidedScanTree(job *ReconJob) (*agenttask.PlanTree, bool) {
	snap := job.Snapshot()
	if snap.Status != StatusDone || snap.Result == nil {
		return nil, false
	}
	index, _ := loadTemplateIndex(defaultTemplateIndexPath)
	return registry.Resolve(snap.Result, index), true
}

// guidedScanPlan is GET /guided-scan/plan?job={id} — the matched-
// capabilities page a "guided" ReconJob's status page links to once done.
func (h *handlers) guidedScanPlan(w http.ResponseWriter, r *http.Request) {
	job, ok := h.reconStore.Get(r.URL.Query().Get("job"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	tree, done := resolveGuidedScanTree(job)
	if !done {
		http.Error(w, "recon job is not done yet — this job has no ReconResult to plan a guided scan against", http.StatusConflict)
		return
	}

	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ready, needsInput, unsupported := bucketMatchedCapabilities(tree)
	data := buildGuidedScanPlanData(job, token, ready, needsInput, unsupported, unresolvedRationales(tree), nil)
	executeTemplate(w, h.tmpl, "guided_scan_plan.html", data)
}

// startGuidedScan is POST /guided-scan/run. Re-resolves the same PlanTree
// (never trusts the form's own hidden state for which capabilities were
// actually matched — only for which the operator checked/filled in),
// builds one scanner.Config per confirmed detector, and runs them
// sequentially against a single, shared Job — the same Job/JobStore
// startScan already uses, so /scans/{id}'s status page, SSE, and JSON
// export all work unchanged.
func (h *handlers) startGuidedScan(w http.ResponseWriter, r *http.Request) {
	job, ok := h.reconStore.Get(r.PostFormValue("job"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	tree, done := resolveGuidedScanTree(job)
	if !done {
		http.Error(w, "recon job is not done yet", http.StatusConflict)
		return
	}
	ready, needsInput, unsupported := bucketMatchedCapabilities(tree)

	authToken := r.PostFormValue("auth_token")
	otherAuthToken := r.PostFormValue("other_auth_token")
	endpoint := r.PostFormValue("endpoint")
	protectedPaths := r.PostFormValue("protected_paths")
	loginPaths := r.PostFormValue("login_paths")
	logoutPaths := r.PostFormValue("logout_paths")

	var errs []string
	var cfgs []scanner.Config

	for _, name := range ready {
		if r.PostFormValue("run_"+name) != "on" {
			continue
		}
		cfgs = append(cfgs, scanner.Config{
			Targets:       []string{job.Target},
			TemplatePaths: defaultWebTemplateDirs(),
			Detector:      name,
			Concurrency:   defaultConcurrency,
			RateLimit:     defaultRateLimit,
			Timeout:       defaultTimeout,
			OutputFormat:  "json",
		})
	}

	for _, name := range needsInput {
		if r.PostFormValue("run_"+name) != "on" {
			continue
		}
		cfg := scanner.Config{
			Targets:          []string{job.Target},
			TemplatePaths:    defaultWebTemplateDirs(),
			Detector:         name,
			Concurrency:      defaultConcurrency,
			RateLimit:        defaultRateLimit,
			Timeout:          defaultTimeout,
			OutputFormat:     "json",
			AuthToken:        authToken,
			OtherAuthToken:   otherAuthToken,
			EndpointTemplate: endpoint,
			ProtectedPaths:   splitCSV(protectedPaths),
			LoginPaths:       splitCSV(loginPaths),
			LogoutPaths:      splitCSV(logoutPaths),
		}
		if err := cfg.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		cfgs = append(cfgs, cfg)
	}

	if len(cfgs) == 0 && len(errs) == 0 {
		errs = append(errs, "select at least one detector to run")
	}

	if len(errs) > 0 {
		token, err := csrfToken(w, r)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		data := buildGuidedScanPlanData(job, token, ready, needsInput, unsupported, unresolvedRationales(tree), errs)
		data.AuthToken, data.OtherAuthToken, data.Endpoint = authToken, otherAuthToken, endpoint
		data.ProtectedPaths, data.LoginPaths, data.LogoutPaths = protectedPaths, loginPaths, logoutPaths
		w.WriteHeader(http.StatusUnprocessableEntity)
		executeTemplate(w, h.tmpl, "guided_scan_plan.html", data)
		return
	}

	id, err := randomHex(8)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	scanJob := newJob(id, job.Target,
		func(f detectors.Finding) template.HTML { return renderFragment(h.tmpl, "fragment_finding_row", f) },
		func(entry LogEntry) template.HTML { return renderFragment(h.tmpl, "fragment_log_line", entry) },
		func(status string, err error) template.HTML {
			return renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: status, Err: err})
		},
	)
	scanJob.AppendLog("info", fmt.Sprintf("guided scan from recon job %s: running %d detector(s)", job.ID, len(cfgs)))
	h.store.Add(scanJob)

	go h.runGuidedScanJob(scanJob, cfgs)

	// A real browser redirect (not an hx-swap) — Guided Scan's results are
	// the existing, unmodified /scans/{id} page, not a fragment target on
	// this one.
	w.Header().Set("HX-Redirect", "/scans/"+scanJob.ID)
	w.WriteHeader(http.StatusOK)
}

// runGuidedScanJob runs each cfg's scanner.Engine sequentially — no
// scanner.Engine change needed for "multiple detectors," findings/logs
// from every run land in the same Job, marked done only once all have
// finished. Runs on the server's lifecycle context, same reasoning as
// runJob/runReconJob.
func (h *handlers) runGuidedScanJob(job *Job, cfgs []scanner.Config) {
	job.SetRunning()
	var lastErr error
	for _, cfg := range cfgs {
		if _, err := scanner.New(cfg).WithFindingCallback(job.AppendFinding).WithLogCallback(job.AppendLog).Run(h.baseCtx); err != nil {
			lastErr = err
			job.AppendLog("error", fmt.Sprintf("%s: %v", cfg.Detector, err))
		}
	}
	job.MarkDone(lastErr)
}
