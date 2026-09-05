package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/detectors/ssrf"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/registry"
	"github.com/tuangatech/hacker-five/pkg/reporter"
	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func newScanCmd(root *rootFlags) *cobra.Command {
	var (
		targets             string
		templatesPaths      []string
		tags                string
		concurrency         int
		templateConcurrency int
		rateLimit           int
		detector         string
		endpointTemplate string
		idorPreview      bool
		authToken        string
		otherAuthToken   string
		authHeaderName   string
		authHeaderFormat string
		insecure         bool
		scopeFile        string
		protectedPaths   string
		loginPaths       string
		logoutPaths      string
		headers          []string
		ssrfParams       []string
		oobServers       []string
		noOOB            bool
		allowWrites      bool
		couponMintPath   string
		couponApplyPath  string
		raceConcurrency  int
		format           string
		reconFile        string
		narrowByTech     bool
		allTemplates     bool
		templateIndex    string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a scan against one or more targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			if authToken == "" {
				authToken = os.Getenv("HACKERFIVE_AUTH_TOKEN")
			}
			if otherAuthToken == "" {
				otherAuthToken = os.Getenv("HACKERFIVE_OTHER_AUTH_TOKEN")
			}

			targetList, err := resolveTargets(targets)
			if err != nil {
				return fmt.Errorf("resolving targets: %w", err)
			}
			extraHeaders, err := parseHeaders(headers)
			if err != nil {
				return fmt.Errorf("parsing --header: %w", err)
			}
			expandedOOBServers := expandOOBServers(oobServers)
			if noOOB {
				expandedOOBServers = nil
			}

			// Only auto-append the synced templates directory when --templates
			// was left at its default — an explicit --templates value from the
			// user replaces the default entirely and is not extended, matching
			// normal flag-override semantics (see
			// docs/12-implementation-plan-ph3.md's "Template sync command" §3).
			// Silently skipped if 'hackerfive templates sync' was never run —
			// os.Stat failing just means there's nothing to add.
			if !cmd.Flags().Changed("templates") {
				if syncedDir, err := templatesync.DefaultSyncDir(); err == nil {
					if _, statErr := os.Stat(syncedDir); statErr == nil {
						templatesPaths = append(templatesPaths, syncedDir)
					}
				}
			}

			cfg := scanner.Config{
				Targets:          targetList,
				TemplatePaths:    templatesPaths,
				Tags:             parseTags(tags),
				Concurrency:         concurrency,
				TemplateConcurrency: templateConcurrency,
				RateLimit:           rateLimit,
				ProxyURL:         root.proxy,
				Timeout:          root.timeout,
				OutputFormat:     format,
				OutputPath:       root.output,
				Detector:         detector,
				EndpointTemplate: endpointTemplate,
				IDORPreview:      idorPreview,
				Insecure:         insecure,
				AuthToken:        authToken,
				OtherAuthToken:   otherAuthToken,
				AuthHeaderName:   authHeaderName,
				AuthHeaderFormat: authHeaderFormat,
				ScopeFile:        scopeFile,
				ProtectedPaths:   parseTags(protectedPaths),
				LoginPaths:       parseTags(loginPaths),
				LogoutPaths:      parseTags(logoutPaths),
				ExtraHeaders:     extraHeaders,
				SSRFParams:       ssrfParams,
				OOBServers:       expandedOOBServers,
				AllowWrites:      allowWrites,
				CouponMintPath:   couponMintPath,
				CouponApplyPath:  couponApplyPath,
				RaceConcurrency:  raceConcurrency,
			}
			// doc15 Step 6a: template scoping is on by default. An explicit
			// --tags wins untouched; --all-templates (or --narrow-by-tech=false)
			// forces the full synced corpus; otherwise the scan is scoped to
			// its --detector's category floor (registry.DetectorTemplateTags),
			// plus — when a --recon-file is supplied — the tech-matched tags
			// registry.TechStackTags derives from it (LT-16/LT-17: scan has no
			// recon step of its own, so it reads a prior `hackerfive recon
			// --output <path>` JSON).
			if len(cfg.Tags) == 0 && narrowByTech && !allTemplates {
				floor := registry.DetectorTemplateTags(detector)
				var extras []string
				if reconFile != "" {
					data, err := os.ReadFile(reconFile)
					if err != nil {
						return fmt.Errorf("reading --recon-file: %w", err)
					}
					var result recon.ReconResult
					if err := json.Unmarshal(data, &result); err != nil {
						return fmt.Errorf("parsing --recon-file: %w", err)
					}
					// A missing/unreadable index degrades to floor-only, the
					// same "missing optional input, warn and continue" posture
					// pkg/recon/plan's own template-index loading uses.
					index, idxErr := loadTemplateIndex(templateIndex)
					if idxErr != nil {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "scan: could not load template index %s (%v) — scoping by --detector category only\n", templateIndex, idxErr)
					}
					extras = registry.TechStackTags(result.TechStack, index)
				}
				cfg.DerivedTags = unionTags(floor, extras)
				describeTemplateScope(cmd.ErrOrStderr(), detector, cfg.DerivedTags, len(floor), len(extras), reconFile != "")
			}

			if err := cfg.Validate(); err != nil {
				return err
			}

			engine := scanner.New(cfg)
			findings, err := engine.Run(cmd.Context())
			if err != nil {
				return fmt.Errorf("running scan: %w", err)
			}
			findings = reporter.Dedup(findings)

			exporter, err := reporter.ExporterFor(cfg.OutputFormat)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if cfg.OutputPath != "" {
				f, err := os.Create(cfg.OutputPath)
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer func() { _ = f.Close() }()
				out = f
			}
			return exporter.Export(out, findings)
		},
	}

	cmd.Flags().StringVarP(&targets, "targets", "t", "", "target URL, or path to a file with one target per line (required)")
	cmd.Flags().StringArrayVar(&templatesPaths, "templates", []string{templatesync.DefaultBundledDir}, "template directory (repeatable); left at its default, the synced directory from 'hackerfive templates sync' is auto-appended if present")
	cmd.Flags().StringVar(&tags, "tags", "", "comma-separated tags — only load templates carrying at least one (default: no filtering)")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 25, "cross-target worker pool size")
	cmd.Flags().IntVar(&templateConcurrency, "template-concurrency", 0, "how many loaded templates fire in parallel against a single target (doc15 Step 6b); 0 = built-in default (10). Still bounded by --rate-limit; auto-capped to 5 when a prompt-injection template is loaded")
	cmd.Flags().IntVar(&rateLimit, "rate-limit", 10, "requests/sec across the whole scan (conservative default — raise it explicitly for a lab benchmark; most bounty/VDP programs' own limits are lower still)")
	cmd.Flags().StringVar(&detector, "detector", "", `detector to run (required): "idor", "misconfig", "authbypass", "ssrf", or "businesslogic"`)
	cmd.Flags().StringVar(&endpointTemplate, "endpoint", "", `endpoint path with an {{id}} placeholder to enumerate, e.g. "/workshop/api/mechanic/mechanic_report?report_id={{id}}" (required for --detector idor)`)
	cmd.Flags().BoolVar(&idorPreview, "idor-preview", false, "fire one extra preflight GET against the resolved --endpoint before enumeration begins, logging its status/body-length — off by default so scripted invocations see no behavior change")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "owner/primary account token (env: HACKERFIVE_AUTH_TOKEN)")
	cmd.Flags().StringVar(&otherAuthToken, "other-auth-token", "", "second account token for IDOR baseline mode / authbypass token-reuse check (env: HACKERFIVE_OTHER_AUTH_TOKEN)")
	cmd.Flags().StringVar(&authHeaderName, "auth-header-name", "", `HTTP header name for the idor/authbypass auth token (default "Authorization")`)
	cmd.Flags().StringVar(&authHeaderFormat, "auth-header-format", "", `header value template for the idor/authbypass auth token, must contain "{token}" (default "Bearer {token}")`)
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification — lab targets only, never the default")
	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to a target allow-list file (one domain/*.domain/CIDR entry per line, # comments); omitted = no enforcement (a warning is printed)")
	cmd.Flags().StringVar(&protectedPaths, "protected-paths", "", "comma-separated candidate endpoint paths the authbypass detector probes (required for --detector authbypass)")
	cmd.Flags().StringVar(&loginPaths, "login-paths", "", `comma-separated candidate login paths for authbypass's rate-limit-signal check (default: authbypass's built-in generic guesses, e.g. "/login")`)
	cmd.Flags().StringVar(&logoutPaths, "logout-paths", "", `comma-separated candidate logout paths for authbypass's broken-session check (default: authbypass's built-in generic guesses, e.g. "/logout")`)
	cmd.Flags().StringArrayVar(&headers, "header", nil, `static "Name: Value" header added to every template-driven request (repeatable) — e.g. a session cookie a login flow issued outside this scan, since template placeholders can't carry one yet`)
	cmd.Flags().StringArrayVar(&ssrfParams, "ssrf-param", nil, `candidate URL-accepting query parameter name for the ssrf detector to probe (repeatable), e.g. "url", "webhook", "callback" — required for --detector ssrf`)
	cmd.Flags().StringArrayVar(&oobServers, "oob-server", ssrf.DefaultOOBServers, `base URL of an Interactsh-protocol server for the ssrf detector's blind out-of-band check (repeatable — tried in order, falls back if one is unreachable); the literal value "public" expands to ProjectDiscovery's full known public server pool (6 servers) — an explicit, real leak tradeoff (see docs/follow-up.md and docs/discussions.md). Defaults to 2 of those public servers (oast.pro, oast.live) when omitted entirely — pass --no-oob to disable for a real third-party engagement, where sending target-request data to a public server is not appropriate`)
	cmd.Flags().BoolVar(&noOOB, "no-oob", false, "disable the ssrf detector's blind out-of-band check entirely, overriding --oob-server's default public servers — use for a real, authorized third-party engagement (see --oob-server's own help text)")
	cmd.Flags().BoolVar(&allowWrites, "allow-writes", false, "allow the businesslogic detector's mutating checks (coupon self-mint/apply, apply-race) to run — the one explicit exception to this tool's read/enumerate-only default; omitted, those checks are skipped with a warning")
	cmd.Flags().StringVar(&couponMintPath, "coupon-mint-path", "", `endpoint path the businesslogic detector mints a coupon against (default: crAPI's real "/community/api/v2/coupon/new-coupon")`)
	cmd.Flags().StringVar(&couponApplyPath, "coupon-apply-path", "", `endpoint path the businesslogic detector applies a coupon against (default: crAPI's real "/workshop/api/shop/apply_coupon")`)
	cmd.Flags().IntVar(&raceConcurrency, "race-concurrency", 0, "simultaneous requests the businesslogic detector's apply-race check fires via last-byte-sync (default: 15)")
	cmd.Flags().StringVar(&format, "format", "json", `output format: "json", "markdown", "html", or "hackerone-json" (an offline, best-effort HackerOne report_intent draft — see "hackerfive report" for the live API workflow)`)
	cmd.Flags().StringVar(&reconFile, "recon-file", "", "path to a prior 'hackerfive recon --output <path>' JSON result — when given, its detected tech stack adds product-specific template tags on top of the --detector category floor (LT-16/LT-17, docs/follow-up.md)")
	cmd.Flags().BoolVar(&narrowByTech, "narrow-by-tech", true, "scope the loaded template corpus to the --detector's categories (plus --recon-file's tech stack, if given) instead of loading all ~9.5k synced templates (doc15 Step 6a). On by default; set --narrow-by-tech=false or --all-templates to load everything. Never overrides an explicit --tags.")
	cmd.Flags().BoolVar(&allTemplates, "all-templates", false, "load the full synced corpus, bypassing the default detector/tech template scoping (doc15 Step 6a) — the escape hatch when you want every template regardless of --detector or detected tech. No effect when --tags is set.")
	cmd.Flags().StringVar(&templateIndex, "template-index", "templates/index.json", "path to the index generated by 'hackerfive templates index', used to derive tech-matched tags from --recon-file")

	return cmd
}

// unionTags returns the de-duplicated, order-stable union of two tag slices
// (lower-cased, blanks dropped) — the detector-category floor
// (registry.DetectorTemplateTags) plus any tech-matched extras
// (registry.TechStackTags), composed into scanner.Config.DerivedTags for
// doc15 Step 6a's default template scoping.
func unionTags(floor, extras []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, group := range [][]string{floor, extras} {
		for _, t := range group {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

// describeTemplateScope prints one stderr line explaining how the loaded
// template corpus was scoped (doc15 Step 6a), so a scan that quietly ran a
// few hundred templates instead of ~9.5k isn't a silent behaviour change.
func describeTemplateScope(stderr io.Writer, detector string, tags []string, floorN, extrasN int, hadReconFile bool) {
	if len(tags) == 0 {
		_, _ = fmt.Fprintf(stderr, "template scope: --detector %s has no category floor and no --recon-file tech match — loading the full corpus (pass --tags to narrow, or this is expected for businesslogic)\n", detector)
		return
	}
	if !hadReconFile {
		_, _ = fmt.Fprintf(stderr, "template scope: %d %s-category tag(s), no --recon-file — pass one for tech-matched CVE coverage, or --all-templates for everything: %s\n", floorN, detector, strings.Join(tags, ", "))
		return
	}
	_, _ = fmt.Fprintf(stderr, "template scope: %d tag(s) = %d %s-category floor + %d tech-matched from --recon-file: %s\n", len(tags), floorN, detector, extrasN, strings.Join(tags, ", "))
}

// resolveTargets treats value as a path to a file with one target per line if
// it exists on disk, otherwise as a single literal target URL.
func resolveTargets(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	if info, err := os.Stat(value); err == nil && !info.IsDir() {
		data, err := os.ReadFile(value)
		if err != nil {
			return nil, fmt.Errorf("reading targets file: %w", err)
		}
		var targetList []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				targetList = append(targetList, line)
			}
		}
		return targetList, nil
	}
	return []string{value}, nil
}

// parseHeaders turns repeated --header "Name: Value" flags into a map,
// splitting each entry on its first colon (a header value may itself
// contain a colon, e.g. a Cookie or URL — Name never does). Rejects an
// entry with no colon at all outright, rather than silently dropping it,
// since a malformed --header most likely means the user meant to supply a
// header and got the syntax wrong — failing fast beats scanning without the
// header they thought they'd set.
func parseHeaders(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	headers := make(map[string]string, len(raw))
	for _, entry := range raw {
		name, value, found := strings.Cut(entry, ":")
		if !found {
			return nil, fmt.Errorf(`--header %q must be in "Name: Value" form`, entry)
		}
		headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return headers, nil
}

// expandOOBServers expands the literal value "public" (case-insensitive)
// into ssrf.PublicInteractshServers (all 6) wherever it appears in raw,
// leaving every other entry as the literal URL the user gave — lets
// --oob-server public and --oob-server public --oob-server
// https://my-own.example.com both work, mixing the full public pool with a
// real self-hosted server if the user wants both tried in order. nil in,
// nil out — an omitted --oob-server never reaches this function at all
// (the flag's own default is ssrf.DefaultOOBServers, non-nil); this
// function's nil-safety exists for --no-oob's explicit override path and
// any programmatic caller passing an empty slice directly.
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

// parseTags splits a comma-separated --tags value into a trimmed slice,
// dropping empty entries; "" (the flag's default) returns nil, meaning no
// filtering. Case-normalizing happens later, in scanner.Engine — this just
// does the CLI-level split.
func parseTags(raw string) []string {
	if raw == "" {
		return nil
	}
	var tags []string
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}
