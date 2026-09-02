package webui

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/detectors/ssrf"
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
		Target:       "https://www.example.com",
		RunMisconfig: true,
		// idor/authbypass/ssrf default on too — "run whatever recon can
		// support without any input" (user decision, 2026-09-01): a
		// detector with nothing to work with just skips itself with a
		// clear log line (fillReconFields), so checking these by default
		// costs nothing and finds more when recon does have something.
		// businesslogic stays off — it hard-requires a real token and its
		// AllowWrites checkbox is a deliberate, explicit opt-in (CLAUDE.md).
		RunIdor:       true,
		RunAuthbypass: true,
		RunSsrf:       true,
		OOBServers:    defaultOOBServers,
		RateLimit:     defaultRateLimit,
		Concurrency:   defaultConcurrency,
		Tools:         buildToolSetupData(false, ""),
	}
	executeTemplate(w, h.tmpl, "launch.html", data)
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
		func(status string, err error, waves []WaveStatus, phase string) template.HTML {
			return renderFragment(h.tmpl, "fragment_progress", ProgressData{Status: status, Phase: phase, Err: err, Waves: waves})
		},
		func(result *recon.ReconResult) template.HTML {
			return renderFragment(h.tmpl, "fragment_recon_results", newReconView(result))
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
	w.WriteHeader(http.StatusUnprocessableEntity)
	executeTemplate(w, h.tmpl, "fragment_launch_body", form)
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

	raceConcurrency, err := parsePositiveInt(r.PostFormValue("race_concurrency"), 0)
	if err != nil {
		errs = append(errs, "race concurrency must be a positive integer")
	}

	if r.PostFormValue("authorized") != "on" {
		errs = append(errs, "you must confirm you are authorized to scan this target")
	}

	form := LaunchFormData{
		Target:           rawTarget,
		RunMisconfig:     r.PostFormValue("run_misconfig") == "on",
		RunIdor:          r.PostFormValue("run_idor") == "on",
		Endpoint:         r.PostFormValue("endpoint"),
		RunAuthbypass:    r.PostFormValue("run_authbypass") == "on",
		ProtectedPaths:   r.PostFormValue("protected_paths"),
		LoginPaths:       r.PostFormValue("login_paths"),
		LogoutPaths:      r.PostFormValue("logout_paths"),
		RunSsrf:          r.PostFormValue("run_ssrf") == "on",
		SSRFParams:       r.PostFormValue("ssrf_params"),
		OOBServers:       r.PostFormValue("oob_servers"),
		RunBusinesslogic: r.PostFormValue("run_businesslogic") == "on",
		AllowWrites:      r.PostFormValue("allow_writes") == "on",
		CouponMintPath:   r.PostFormValue("coupon_mint_path"),
		CouponApplyPath:  r.PostFormValue("coupon_apply_path"),
		RaceConcurrency:  raceConcurrency,
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

	// templatesAssigned ensures the nuclei/native template corpus is
	// attached to exactly one of this submission's scanner.Configs, not
	// one copy per checked detector. Found live, 2026-09-01: Engine.Run
	// runs every loaded template additively alongside whichever
	// --detector was selected (by design, for the CLI's one-config-per-
	// invocation model — see CLAUDE.md's own documented gotcha) — but
	// runLaunchJob calls scanner.New(cfg).Run() once per checked
	// checkbox, each with its own identical TemplatePaths. With 2+
	// boxes checked (now the default: misconfig+idor+authbypass+ssrf),
	// that reran the same ~3190 templates once per checked detector,
	// quadrupling both duplicate Findings and real requests sent to the
	// target. Which config keeps the templates is arbitrary — template
	// execution doesn't depend on cfg.Detector — so the first checked-
	// and-valid detector (misconfig, if checked, since its own if-block
	// runs first) keeps them; every later one gets TemplatePaths: nil.
	templatesAssigned := false
	baseCfg := func(detector string) scanner.Config {
		var templatePaths []string
		if !templatesAssigned {
			templatePaths = defaultWebTemplateDirs()
			templatesAssigned = true
		}
		return scanner.Config{
			Targets:          []string{target},
			TemplatePaths:    templatePaths,
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
		// Always on from the Web UI (doc14 Step 7) — closes the "wrong
		// --endpoint silently yields zero findings" gap for every idor run
		// this page starts, recon-derived endpoint or hand-typed alike. The
		// CLI's own --idor-preview default stays false; this is a Web UI-
		// specific choice, not a change to scanner.Config's own default.
		cfg.IDORPreview = true
		// A blank Endpoint isn't failed here — recon (which always runs)
		// gets a chance to fill it in first; see fillReconFields, called
		// from runLaunchJob once recon finishes. A blank AuthToken/
		// OtherAuthToken isn't failed either, unlike the CLI's own
		// cfg.Validate(): recon can never supply a credential, but idor's
		// heuristic mode is still meaningful fully unauthenticated (a
		// signature-comparison check, not a per-token requirement) — see
		// ValidateOptions' own doc comment. runLaunchJob logs plainly when
		// this mode is what actually ran.
		opts := scanner.ValidateOptions{SkipEndpointRequired: cfg.EndpointTemplate == "", SkipAuthTokenRequired: true}
		if err := cfg.ValidateWithOptions(opts); err != nil {
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
		// Same deferral as idor's Endpoint above, for ProtectedPaths only —
		// LoginPaths/LogoutPaths are already optional (authbypass's own
		// package defaults apply), so nothing here needs deferring for them.
		// SkipAuthTokenRequired, same reasoning as idor's above: a blank
		// AuthToken still lets checkMissingAuth/checkRateLimitSignal run
		// (neither references a token at all) — the other four checks
		// already no-op internally without one.
		opts := scanner.ValidateOptions{SkipProtectedPathsRequired: len(cfg.ProtectedPaths) == 0, SkipAuthTokenRequired: true}
		if err := cfg.ValidateWithOptions(opts); err != nil {
			errs = append(errs, "authbypass: "+err.Error())
		} else {
			cfgs = append(cfgs, cfg)
		}
	}
	if form.RunSsrf {
		cfg := baseCfg("ssrf")
		cfg.SSRFParams = splitCSV(form.SSRFParams)
		cfg.OOBServers = expandOOBServers(splitCSV(form.OOBServers))
		// Same deferral as authbypass's ProtectedPaths above — recon can
		// supply every SSRFParams candidate it finds (SuggestSSRFParamsFromRecon,
		// Step 7), and unlike idor's single-endpoint choice there's no
		// ambiguity to resolve: SSRFParams is a list, so every candidate
		// recon finds is usable directly, not just one of several.
		opts := scanner.ValidateOptions{SkipSSRFParamsRequired: len(cfg.SSRFParams) == 0}
		if err := cfg.ValidateWithOptions(opts); err != nil {
			errs = append(errs, "ssrf: "+err.Error())
		} else {
			cfgs = append(cfgs, cfg)
		}
	}
	if form.RunBusinesslogic {
		cfg := baseCfg("businesslogic")
		cfg.AllowWrites = form.AllowWrites
		cfg.CouponMintPath = form.CouponMintPath
		cfg.CouponApplyPath = form.CouponApplyPath
		cfg.RaceConcurrency = form.RaceConcurrency
		// No deferral here: AuthToken is businesslogic's only required
		// field, and a credential can never be recon-derived (the
		// permanent limit named in doc14 Step 7's Design section) —
		// CouponMintPath/CouponApplyPath/RaceConcurrency are all optional,
		// already defaulting to businesslogic's own package values
		// (crAPI's real paths) when left blank. AllowWrites stays
		// false unless the operator checks it themselves, same as the
		// authorization checkbox — never toggled by recon.
		if err := cfg.Validate(); err != nil {
			errs = append(errs, "businesslogic: "+err.Error())
		} else {
			cfgs = append(cfgs, cfg)
		}
	}

	return form, cfgs, errs
}

// expandOOBServers is cmd/hackerfive/scan.go's expandOOBServers, duplicated
// here since it's package-main-local there — small, proportionate
// duplication, same reasoning as splitCSV/launchTargetScheme. Expands the
// literal "public" (case-insensitive) into ssrf.PublicInteractshServers,
// leaving every other entry as-is; nil in, nil out.
func expandOOBServers(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	for _, entry := range raw {
		if strings.EqualFold(entry, "public") {
			out = append(out, ssrf.PublicInteractshServers...)
			continue
		}
		out = append(out, entry)
	}
	return out
}

// runLaunchJob runs the unified job in the background: a recon phase first
// (always full depth — recon is enrichment the operator never opts out of),
// then each checked-and-validated detector's scanner.Engine run,
// sequentially — into one shared Job so the results page renders wave
// progress, recon facts, and detector findings from a single stream. Runs
// on the server's lifecycle context, same reasoning as the pages this
// replaces.
func (h *handlers) runLaunchJob(job *Job, form LaunchFormData, cfgs []scanner.Config) {
	job.SetRunning()

	job.SetPhase("recon")
	h.runLaunchRecon(job, form, cfgs)

	cfgs = fillReconFields(job, cfgs)

	var lastErr error
	for _, cfg := range cfgs {
		job.SetPhase(cfg.Detector)
		job.AppendLog("info", "running detector: "+cfg.Detector)
		if note := noTokenNote(cfg); note != "" {
			job.AppendLog("info", note)
		}
		if _, err := scanner.New(cfg).WithFindingCallback(job.AppendFinding).WithLogCallback(job.AppendLog).Run(h.baseCtx); err != nil {
			lastErr = err
			job.AppendLog("error", fmt.Sprintf("%s: %v", cfg.Detector, err))
		}
	}

	job.MarkDone(lastErr)
}

// noTokenNote returns an informational log line when cfg is about to run
// fully unauthenticated (idor/authbypass only — see ValidateOptions'
// SkipAuthTokenRequired doc comment) — transparent about which checks that
// narrows the run to, since neither detector's own behavior otherwise
// signals this anywhere.
func noTokenNote(cfg scanner.Config) string {
	if cfg.AuthToken != "" || cfg.OtherAuthToken != "" {
		return ""
	}
	switch cfg.Detector {
	case "idor":
		return "idor: no auth token given — running unauthenticated (heuristic-mode signature comparison only; not a true cross-account IDOR test without one)"
	case "authbypass":
		return "authbypass: no auth token given — running only the checks that don't need one (missing-auth probe, login rate-limit signal); JWT/session/token-reuse checks skipped"
	default:
		return ""
	}
}

// waveDescription is a human-readable gloss on what a wave actually does —
// logged when it starts so a long-running wave (e.g. wave1's subfinder call
// against external passive sources can take tens of seconds) doesn't look
// stalled just because WaveStatus itself only has "running"/"done", no
// sub-progress. Mirrors doc91 §3's own wave descriptions.
func waveDescription(wave string) string {
	switch wave {
	case "wave0":
		return "recon wave0: zero-touch — parsing any provided spec, fetching security.txt"
	case "wave1":
		return "recon wave1: passive — subdomain/DNS enumeration (subfinder), TLS cert inspection (tlsx), WHOIS/ASN lookup"
	case "wave2":
		return "recon wave2: active — DNS resolve, port scan (naabu), HTTP probe/fingerprint (httpx)"
	case "wave3":
		return "recon wave3: full — bounded crawl (katana) + common-path probing"
	default:
		return "recon " + wave
	}
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
		recon.WithProgressCallback(func(wave, status string) {
			job.SetWaveStatus(wave, status)
			if status == "running" {
				job.AppendLog("info", waveDescription(wave))
			}
		}),
	}
	if s != nil {
		opts = append(opts, recon.WithScope(s))
	}
	rc := recon.New(client, opts...)

	ctx, cancel := context.WithTimeout(h.baseCtx, reconRunTimeout)
	defer cancel()

	result, err := rc.Run(ctx, launchTargetScheme(form.Target), recon.DepthFull)
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

// fillReconFields resolves any recon-fillable field parseLaunchSubmission
// deferred (idor's EndpointTemplate, authbypass's ProtectedPaths/
// LoginPaths/LogoutPaths) now that runLaunchRecon — called just before this,
// and already synchronous/blocking — has had its one chance to populate
// job's ReconResult. A field recon can't resolve isn't a job failure: that
// one detector's cfg is simply omitted from the returned, runnable slice,
// with a clear log line explaining why — mirroring PlanTree's
// StatusUnresolved-leaf posture (docs/14-implementation-plan-ph5.md Step 7):
// a gap the deterministic layer can't close stays visible, never silently
// dropped.
func fillReconFields(job *Job, cfgs []scanner.Config) []scanner.Config {
	result := job.Snapshot().ReconResult

	runnable := make([]scanner.Config, 0, len(cfgs))
	for _, cfg := range cfgs {
		switch cfg.Detector {
		case "idor":
			if cfg.EndpointTemplate == "" {
				candidates := recon.SuggestIDOREndpointCandidates(result)
				switch len(candidates) {
				case 0:
					job.AppendLog("warn", "idor: skipped — no --endpoint given and recon found no candidate; fill in manually and re-run")
					continue
				case 1:
					cfg.EndpointTemplate = candidates[0]
					job.AppendLog("info", "idor: using recon-derived endpoint "+cfg.EndpointTemplate)
				default:
					job.AppendLog("warn", fmt.Sprintf("idor: %d recon-derived candidates found, none auto-selected — pick one via --endpoint and re-run: %s", len(candidates), strings.Join(candidates, ", ")))
					continue
				}
			}
		case "authbypass":
			protected, login, logout := suggestPathsFromRecon(result)
			if len(cfg.ProtectedPaths) == 0 {
				if len(protected) == 0 {
					job.AppendLog("warn", "authbypass: skipped — no --protected-paths given and recon found no candidate; fill in manually and re-run")
					continue
				}
				cfg.ProtectedPaths = protected
				job.AppendLog("info", "authbypass: using recon-derived protected paths "+strings.Join(protected, ", "))
			}
			if len(cfg.LoginPaths) == 0 && len(login) > 0 {
				cfg.LoginPaths = login
				job.AppendLog("info", "authbypass: using recon-derived login paths "+strings.Join(login, ", "))
			}
			if len(cfg.LogoutPaths) == 0 && len(logout) > 0 {
				cfg.LogoutPaths = logout
				job.AppendLog("info", "authbypass: using recon-derived logout paths "+strings.Join(logout, ", "))
			}
		case "ssrf":
			if len(cfg.SSRFParams) == 0 {
				candidates := recon.SuggestSSRFParamsFromRecon(result)
				if len(candidates) == 0 {
					job.AppendLog("warn", "ssrf: skipped — no --ssrf-param given and recon found no candidate; fill in manually and re-run")
					continue
				}
				// Unlike idor's single-endpoint choice, every candidate
				// recon finds is directly usable — SSRFParams is a list,
				// so there's no ambiguity to resolve between them.
				cfg.SSRFParams = candidates
				job.AppendLog("info", "ssrf: using recon-derived params "+strings.Join(candidates, ", "))
			}
		}

		// SkipAuthTokenRequired must be carried through here too — a plain
		// Validate() would silently re-impose the requirement
		// parseLaunchSubmission already waived for idor/authbypass (a real
		// bug caught live: both were being skipped with a misleading
		// "requires --auth-token" error even after this exact fill step
		// succeeded, since Validate() has no way to know that requirement
		// was deliberately relaxed upstream). Endpoint/ProtectedPaths/
		// SSRFParams need no equivalent skip here — by this point they're
		// either filled or the cfg has already hit a `continue` above.
		opts := scanner.ValidateOptions{SkipAuthTokenRequired: true}
		if err := cfg.ValidateWithOptions(opts); err != nil {
			// Otherwise defensive only: a recon-filled value is already
			// known-shaped, so this should rarely fire beyond the
			// AuthToken case above.
			job.AppendLog("error", cfg.Detector+": "+err.Error())
			continue
		}
		runnable = append(runnable, cfg)
	}
	return runnable
}

// suggestPathsFromRecon buckets a ReconResult's EndpointFacts into
// authbypass's three path fields, per docs/14-implementation-plan-ph5.md
// Step 7's spec: a 401/403 response is evidence of a protected path; a fact
// wave3's auth-boundary heuristic itself produced, or a login-shaped path,
// suggests a login path; a logout/signout-shaped path suggests a logout
// path. Each list preserves recon's own discovery order (already
// deterministic) and is deduplicated.
func suggestPathsFromRecon(result *recon.ReconResult) (protected, login, logout []string) {
	if result == nil {
		return nil, nil, nil
	}

	seenProtected, seenLogin, seenLogout := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, ep := range result.Endpoints {
		path := endpointPath(ep.URL)
		if path == "" {
			continue
		}
		lower := strings.ToLower(path)
		switch {
		case ep.StatusCode == http.StatusUnauthorized || ep.StatusCode == http.StatusForbidden:
			if !seenProtected[path] {
				seenProtected[path] = true
				protected = append(protected, path)
			}
		case ep.Source == "wave3-auth-boundary-heuristic" || strings.Contains(lower, "login") || strings.Contains(lower, "signin"):
			if !seenLogin[path] {
				seenLogin[path] = true
				login = append(login, path)
			}
		case strings.Contains(lower, "logout") || strings.Contains(lower, "signout"):
			if !seenLogout[path] {
				seenLogout[path] = true
				logout = append(logout, path)
			}
		}
	}
	return protected, login, logout
}

// endpointPath extracts rawURL's path, "" on a malformed URL (skipped by
// suggestPathsFromRecon's caller).
func endpointPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
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
