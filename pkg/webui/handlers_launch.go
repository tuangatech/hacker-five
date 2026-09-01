package webui

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// reconRunTimeout mirrors cmd/hackerfive/recon.go's own constant — bounds
// the whole multi-wave recon phase so a hung external binary can't stall a
// background job forever.
const reconRunTimeout = 10 * time.Minute

// launchRecentLimit mirrors the old dashboard.html's own limit — the full
// list stays available at /scans (scanHistory).
const launchRecentLimit = 10

// guidedReadyDetectors/guidedInputDetectors classify a matched registry
// capability for the "recon also suggests" informational callout below —
// same buckets Guided Scan's now-retired confirm page used to gate on; here
// they're purely descriptive, since detector selection already happened
// before recon ran.
var guidedReadyDetectors = map[string]bool{"misconfig": true}
var guidedInputDetectors = map[string]bool{"idor": true, "authbypass": true}

// launchForm is GET / — the single unified entry point (doc14 Step 6)
// replacing New Scan/Recon/Guided Scan's three separate pages.
func (h *handlers) launchForm(w http.ResponseWriter, r *http.Request) {
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := LaunchFormData{
		CSRFToken:    token,
		RunRecon:     true,
		Depth:        string(recon.DepthActive),
		RunMisconfig: true,
		RateLimit:    defaultRateLimit,
		Concurrency:  defaultConcurrency,
		Tools:        buildToolSetupData(false, ""),
	}
	h.fillRecentJobs(&data)
	executeTemplate(w, h.tmpl, "launch.html", data)
}

func (h *handlers) fillRecentJobs(data *LaunchFormData) {
	all := h.store.List()
	data.HasMore = len(all) > launchRecentLimit
	if data.HasMore {
		data.RecentJobs = all[:launchRecentLimit]
	} else {
		data.RecentJobs = all
	}
}

// launchTargetScheme mirrors pkg/recon's own unexported defaultScheme — a
// bare target needs a scheme before scanner.Config.Targets can use it too,
// not just before recon.Run does. Duplicated as a 4-line function rather
// than exported from pkg/recon, same "small, proportionate duplication"
// reasoning already applied to splitCSV/defaultWebTemplateDirsWithLabels.
// Found the hard way this session: passing a bare "host:port" straight into
// scanner.Config.Targets fails outright (url.Parse treats the digits before
// ":" as an invalid scheme).
func launchTargetScheme(target string) string {
	if strings.Contains(target, "://") {
		return target
	}
	return "https://" + target
}

// startLaunch is POST /scans — the unified submit handler replacing
// startScan/startRecon/startGuidedScan. r.Form/r.PostForm are already
// populated by csrfMiddleware.
func (h *handlers) startLaunch(w http.ResponseWriter, r *http.Request) {
	form, cfgs, errs := parseLaunchSubmission(r)

	if len(errs) > 0 {
		h.rerenderLaunchWithErrors(w, r, form, errs)
		return
	}

	id, err := randomHex(8)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	job := newJob(id, launchTargetScheme(form.Target),
		func(f detectors.Finding) template.HTML { return renderFragment(h.tmpl, "fragment_finding_row", f) },
		func(entry LogEntry) template.HTML { return renderFragment(h.tmpl, "fragment_log_line", entry) },
		func(status string, err error, waves []WaveStatus) template.HTML {
			return renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: status, Err: err, Waves: waves})
		},
	)
	// The authorization checkbox becomes the job's first log entry — the
	// "audit trail" doc12 calls for; reuses the one logging surface that
	// already does this rather than a separate audit mechanism.
	job.AppendLog("info", "authorized: target confirmed by operator acknowledgment")
	h.store.Add(job)

	go h.runLaunchJob(job, form, cfgs)

	w.Header().Set("HX-Push-Url", "/scans/"+job.ID)
	executeTemplate(w, h.tmpl, "fragment_scan_status_body", h.snapshotData(job))
}

func (h *handlers) rerenderLaunchWithErrors(w http.ResponseWriter, r *http.Request, form LaunchFormData, errs []string) {
	token, err := csrfToken(w, r)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	form.CSRFToken = token
	form.Errors = errs
	form.Tools = buildToolSetupData(false, "")
	h.fillRecentJobs(&form)
	w.WriteHeader(http.StatusUnprocessableEntity)
	executeTemplate(w, h.tmpl, "launch.html", form)
}

// parseLaunchSubmission maps POST /scans' form values onto a LaunchFormData
// (for error re-render / recon options) and one scanner.Config per checked
// AND valid detector tab. A detector tab left unchecked is simply omitted —
// no error. A checked-but-invalid tab (e.g. authbypass checked with no
// protected_paths) is a validation error, never a silent skip — same
// accumulate-errors-then-rerender pattern the pages this replaces already
// used.
func parseLaunchSubmission(r *http.Request) (LaunchFormData, []scanner.Config, []string) {
	var errs []string

	rawTarget := strings.TrimSpace(r.PostFormValue("target"))
	if rawTarget == "" {
		errs = append(errs, "target is required")
	}
	target := launchTargetScheme(rawTarget)

	runRecon := r.PostFormValue("run_recon") == "on"
	depth := r.PostFormValue("depth")
	if runRecon {
		switch recon.Depth(depth) {
		case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
		default:
			errs = append(errs, `recon depth must be "passive", "active", or "full"`)
		}
	}

	rateLimit, err := parsePositiveInt(r.PostFormValue("rate_limit"), defaultRateLimit)
	if err != nil {
		errs = append(errs, "rate limit must be a positive integer")
	}
	concurrency, err := parsePositiveInt(r.PostFormValue("concurrency"), defaultConcurrency)
	if err != nil {
		errs = append(errs, "concurrency must be a positive integer")
	}

	extraHeaders, err := parseHeaderLines(r.PostFormValue("headers"))
	if err != nil {
		errs = append(errs, err.Error())
	}

	if r.PostFormValue("authorized") != "on" {
		errs = append(errs, "you must confirm you are authorized to scan this target")
	}

	form := LaunchFormData{
		Target:           rawTarget,
		RunRecon:         runRecon,
		Depth:            depth,
		RunMisconfig:     r.PostFormValue("run_misconfig") == "on",
		RunIdor:          r.PostFormValue("run_idor") == "on",
		Endpoint:         r.PostFormValue("endpoint"),
		RunAuthbypass:    r.PostFormValue("run_authbypass") == "on",
		ProtectedPaths:   r.PostFormValue("protected_paths"),
		LoginPaths:       r.PostFormValue("login_paths"),
		LogoutPaths:      r.PostFormValue("logout_paths"),
		Tags:             r.PostFormValue("tags"),
		AuthToken:        r.PostFormValue("auth_token"),
		OtherAuthToken:   r.PostFormValue("other_auth_token"),
		AuthHeaderName:   r.PostFormValue("auth_header_name"),
		AuthHeaderFormat: r.PostFormValue("auth_header_format"),
		Headers:          r.PostFormValue("headers"),
		RateLimit:        rateLimit,
		Concurrency:      concurrency,
		Insecure:         r.PostFormValue("insecure") == "on",
		ScopeFile:        r.PostFormValue("scope_file"),
		Authorized:       r.PostFormValue("authorized") == "on",
	}

	baseCfg := func(detector string) scanner.Config {
		return scanner.Config{
			Targets:          []string{target},
			TemplatePaths:    defaultWebTemplateDirs(),
			Tags:             splitCSV(form.Tags),
			Detector:         detector,
			Concurrency:      concurrency,
			RateLimit:        rateLimit,
			Timeout:          defaultTimeout,
			OutputFormat:     "json",
			Insecure:         form.Insecure,
			AuthToken:        form.AuthToken,
			OtherAuthToken:   form.OtherAuthToken,
			AuthHeaderName:   form.AuthHeaderName,
			AuthHeaderFormat: form.AuthHeaderFormat,
			ScopeFile:        form.ScopeFile,
			ExtraHeaders:     extraHeaders,
		}
	}

	var cfgs []scanner.Config
	if form.RunMisconfig {
		cfg := baseCfg("misconfig")
		if err := cfg.Validate(); err != nil {
			errs = append(errs, "misconfig: "+err.Error())
		} else {
			cfgs = append(cfgs, cfg)
		}
	}
	if form.RunIdor {
		cfg := baseCfg("idor")
		cfg.EndpointTemplate = form.Endpoint
		if err := cfg.Validate(); err != nil {
			errs = append(errs, "idor: "+err.Error())
		} else {
			cfgs = append(cfgs, cfg)
		}
	}
	if form.RunAuthbypass {
		cfg := baseCfg("authbypass")
		cfg.ProtectedPaths = splitCSV(form.ProtectedPaths)
		cfg.LoginPaths = splitCSV(form.LoginPaths)
		cfg.LogoutPaths = splitCSV(form.LogoutPaths)
		if err := cfg.Validate(); err != nil {
			errs = append(errs, "authbypass: "+err.Error())
		} else {
			cfgs = append(cfgs, cfg)
		}
	}

	// Only surfaced when nothing else already explains why nothing will
	// run — avoids piling a redundant message on top of a target/detector
	// validation error that already says as much.
	if !runRecon && len(cfgs) == 0 && len(errs) == 0 {
		errs = append(errs, "select recon and/or at least one detector to run")
	}

	return form, cfgs, errs
}

// runLaunchJob runs the unified job in the background: an optional recon
// phase first, then each checked-and-validated detector's scanner.Engine
// run, sequentially — into one shared Job so the results page renders wave
// progress, recon facts, and detector findings from a single stream. Runs
// on the server's lifecycle context, same reasoning as the pages this
// replaces.
func (h *handlers) runLaunchJob(job *Job, form LaunchFormData, cfgs []scanner.Config) {
	job.SetRunning()

	if form.RunRecon {
		h.runLaunchRecon(job, form, cfgs)
	}

	var lastErr error
	for _, cfg := range cfgs {
		if _, err := scanner.New(cfg).WithFindingCallback(job.AppendFinding).WithLogCallback(job.AppendLog).Run(h.baseCtx); err != nil {
			lastErr = err
			job.AppendLog("error", fmt.Sprintf("%s: %v", cfg.Detector, err))
		}
	}

	job.MarkDone(lastErr)
}

// runLaunchRecon runs the recon phase and records its result on job — never
// fails the whole run: a recon error is logged and the job moves on to
// whatever detectors were checked, same "recon is enrichment, not a gate"
// reasoning the unified page's design settled on. cfgs is the set of
// detectors already confirmed to run this scan, so the "recon also
// suggests" callout never lists something that's already running.
func (h *handlers) runLaunchRecon(job *Job, form LaunchFormData, cfgs []scanner.Config) {
	var s *scope.Scope
	if form.ScopeFile != "" {
		parsed, err := scope.Parse(form.ScopeFile)
		if err != nil {
			job.AppendLog("error", fmt.Sprintf("recon: parsing scope file: %v", err))
			return
		}
		s = parsed
	}

	client := httpclient.New(httpclient.Config{
		Timeout:             defaultTimeout,
		MaxRedirects:        5,
		InsecureSkipVerify:  form.Insecure,
		MaxIdleConnsPerHost: form.Concurrency,
	}, httpclient.WithRateLimit(ratelimit.New(form.RateLimit)))

	opts := []recon.Option{
		recon.WithRateLimit(form.RateLimit),
		recon.WithConcurrency(form.Concurrency),
		recon.WithProgressCallback(job.SetWaveStatus),
	}
	if s != nil {
		opts = append(opts, recon.WithScope(s))
	}
	rc := recon.New(client, opts...)

	ctx, cancel := context.WithTimeout(h.baseCtx, reconRunTimeout)
	defer cancel()

	result, err := rc.Run(ctx, launchTargetScheme(form.Target), recon.Depth(form.Depth))
	if err != nil {
		job.AppendLog("error", fmt.Sprintf("recon: %v", err))
		return
	}
	job.SetReconResult(result)
	job.AppendLog("info", fmt.Sprintf("recon complete: %d host(s), %d endpoint(s), %d tech fact(s)", len(result.Hosts), len(result.Endpoints), len(result.TechStack)))

	// Informational only — never gates which detectors already ran/will
	// run, since selection was fixed before this scan started. Reuses
	// registry.Resolve exactly as Guided Scan's own (now-retired) confirm
	// page did.
	index, _ := loadTemplateIndex(defaultTemplateIndexPath)
	tree := registry.Resolve(result, index)
	selected := make(map[string]bool, len(cfgs))
	for _, cfg := range cfgs {
		selected[cfg.Detector] = true
	}
	if suggestions := suggestedDetectorNames(tree, selected); len(suggestions) > 0 {
		job.AppendLog("info", "recon also suggests: "+strings.Join(suggestions, ", ")+" (not run — selected before this scan started)")
	}
}

// flattenPlanTree walks tree depth-first into a flat leaf slice.
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
// leaves into ready/needsInput/unsupported by detector/template-ID name,
// deduplicated, along with every distinct PlanNode.Rationale per name —
// the same bucketing Guided Scan's now-retired confirm page used to gate
// on; here (runLaunchRecon's suggestedDetectorNames) it's purely
// informational.
func bucketMatchedCapabilities(tree *agenttask.PlanTree) (ready, needsInput, unsupported []string, rationales map[string][]string) {
	seen := make(map[string]bool)
	rationaleSeen := make(map[string]map[string]bool)
	rationales = make(map[string][]string)
	for _, leaf := range flattenPlanTree(tree) {
		if leaf.Status != agenttask.StatusPending || leaf.Detector == "" {
			continue
		}
		if leaf.Rationale != "" {
			if rationaleSeen[leaf.Detector] == nil {
				rationaleSeen[leaf.Detector] = make(map[string]bool)
			}
			if !rationaleSeen[leaf.Detector][leaf.Rationale] {
				rationaleSeen[leaf.Detector][leaf.Rationale] = true
				rationales[leaf.Detector] = append(rationales[leaf.Detector], leaf.Rationale)
			}
		}
		if seen[leaf.Detector] {
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
	return ready, needsInput, unsupported, rationales
}

// suggestedDetectorNames flattens bucketMatchedCapabilities' three buckets
// into one deduplicated list for the "recon also suggests" log line,
// excluding anything in alreadySelected — no point telling the operator
// recon "also suggests" a detector that's already running this scan.
func suggestedDetectorNames(tree *agenttask.PlanTree, alreadySelected map[string]bool) []string {
	ready, needsInput, unsupported, _ := bucketMatchedCapabilities(tree)
	seen := map[string]bool{}
	var out []string
	for _, name := range append(append(ready, needsInput...), unsupported...) {
		if alreadySelected[name] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}
