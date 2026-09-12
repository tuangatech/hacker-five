# Development Roadmap

> Part of the [HackerFive documentation set](../README.md).

## Phased Development Plan

### Phase 1: Foundation (Weeks 1-10) — Core Engine + IDOR + Misconfiguration

**Goal:** Deliver a working MVP that detects IDOR and misconfiguration issues with low false positives.

Split into two sub-phases so there's a real, working deliverable at the halfway point rather than one all-or-nothing 10-week push — see [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) for the file-by-file build plan behind Phase 1a.

---

### Phase 1a: Foundation Kickoff (Weeks 1-4) — Core Engine + IDOR Detector

**Goal:** A working, IDOR-only scanner — CLI, HTTP engine, and detector all functioning end-to-end against a live target — before misconfiguration and the template engine are added.

#### Week 1-2: Project Setup & Architecture — ✅ done
- [x] Initialize Go project structure
  ```
  hackerfive/
  ├── cmd/
  │   └── hackerfive/
  │       └── main.go
  ├── pkg/
  │   ├── scanner/
  │   │   ├── engine.go
  │   │   └── worker_pool.go
  │   ├── detectors/
  │   │   ├── idor.go
  │   │   └── misconfiguration.go
  │   ├── template/
  │   │   └── parser.go
  │   └── reporter/
  │       └── output.go
  ├── templates/
  │   ├── idor/
  │   └── misconfig/
  ├── tests/
  ├── go.mod
  ├── Dockerfile
  └── README.md
  ```
- [x] Set up GitHub repository and CI/CD (GitHub Actions)
- [x] Define YAML template schema
- [x] Create basic CLI structure (Cobra)

**Deliverable:** Project skeleton with working CLI that parses arguments

#### Week 2-3: HTTP Client & Request Engine — ✅ done
- [x] Implement custom HTTP client with middleware
  - Request/response logging
  - Rate limiting (configurable QPS)
  - Proxy support (SOCKS5, HTTP)
  - Custom headers (User-Agent, API keys)
  - Retry logic with exponential backoff
- [x] Implement worker pool for concurrent scanning
- [x] Add request templating ({{BaseURL}}, {{RangeInt}}, variables)

**Deliverable:** HTTP engine can fire 150+ requests/sec with configurable concurrency

#### Week 3-4: IDOR Detector (Module 1) — ✅ done
- [x] Implement ID enumeration strategies:
  - Sequential integers (1-100, 1-1000)
  - UUID variants (sequential, hash-based) — later widened to a dedicated `idor.RandomUUIDStrategy` (LT-95, 2026-09-09)
  - String patterns (user1, user2, alice, bob)
- [x] Implement response comparison algorithm:
  - HTTP status code
  - Response size (byte count)
  - Content hash (MD5/SHA256 to detect duplicates)
  - Keyword presence (email, name, user_id)
- [x] Implement **baseline mode** (primary, high-confidence): two unrelated account tokens, establish the "denied" signature from one account's sampled responses, flag IDs where that account's response deviates from denied — this is the actual authorization test, not just a content diff
- [x] Keep single-token signature-diff as a **heuristic fallback only** (low-confidence, flagged for manual triage) when a second test account isn't available — it cannot distinguish an IDOR from an endpoint that legitimately returns different public content per ID
- [x] Add JWT/Bearer token handling
- [x] Create test cases against crAPI "vehicle access" endpoint

**Test Target:** crAPI `/dashboard` and `/mechanic/receive_report` (known IDOR vulns)

**Deliverable:** Standalone IDOR detector, baseline mode finds real cross-account access issues on crAPI

**Phase 1a Success Metrics (Week 4 checkpoint):**
- [x] IDOR detector (baseline mode) finds ≥1 real cross-account issue in crAPI, using two distinct test accounts — confirmed against `report_id` 1-6
- [x] HTTP engine sustains 150+ req/sec against a local benchmark target
- [x] `go build`/`go vet`/`golangci-lint` clean and CI green, verified on both macOS and Windows/WSL2 checkouts — doc09's Definition of Done left the macOS leg unchecked at the time; since then this exact checkout has run `go build`/`go vet`/`go test -race`/`golangci-lint run ./...` clean on macOS repeatedly (most recently 2026-09-10), and CI's `macos-latest` job is part of the standing green gate
- [x] Full verification detail in [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)'s Definition of Done

---

### Phase 1b: Coverage Expansion (Weeks 5-10) — Misconfiguration + Template Engines (Nuclei-Compatible + Native) + Validation + Packaging

**Goal:** Extend the Phase 1a foundation with misconfiguration detection, a Nuclei-compatible template parser for static checks, the native YAML template engine for stateful checks, validate against all Phase 1 test targets, and ship the v0.1.0 release.

#### Week 5: Misconfiguration Detector (Module 2) — ✅ done
- [x] Implement path-based checks
  ```go
  paths := []string{"/admin", "/.env", "/.git", "/debug", "/swagger", "/graphql"}
  keywords := []string{"admin", "api_key", "password", "secret"}
  ```
- [x] Implement security header checks
  - CSP, X-Frame-Options, HSTS, etc.
- [x] Implement HTTP method testing (PUT, DELETE, PATCH on read-only endpoints)
- [x] Create 50+ built-in detection rules

**Test Targets:** OWASP Juice Shop, DVWA

**Deliverable:** Misconfiguration detector runs 200+ checks in <30 seconds per target

#### Week 6-7: Nuclei-Compatible Template Parser — ✅ done
- [x] Implement a parser supporting the Nuclei template schema: `http` requests, matchers (word/regex/status/size/binary/dsl), extractors (regex/kval/json/dsl), the `part` field, `matchers-condition`, and `req-condition` request chaining
- [x] Point at the upstream [`nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) repo (MIT-licensed) as the template source directly — no local fork or redistribution — **pinned to a specific tagged release/commit**, not `HEAD`, so an upstream compromise can't silently inject a malicious template into a scan run
- [x] Validate against a curated subset of upstream templates — target 50+ templates from the `exposed-panels`, `misconfiguration`, and `technologies` categories relevant to Phase 1 vuln classes — long since superseded by the full synced corpus (~9,652 templates as of 2026-09-03, see Phase 8's Rules note)
- [x] **Reject at load time** (not just "document as unsupported") any template containing `code:`, `javascript:`, `headless:`, or `file:` protocol blocks — these enable arbitrary code execution or local file access and are out of scope for a template source we don't hand-review; parser should error loudly rather than silently skip them
- [x] Document remaining unsupported Nuclei features (e.g. network/DNS protocols) as explicitly out of scope for v0.1.0 — tracked forward as the Template Engine & Detection Backlog in [follow-up.md](follow-up.md), most since closed (Phase 9 Step 2 covers what's left: `xpath`, `flow:` script constructs, a few DSL functions)

**Deliverable:** Misconfiguration/panel checks run against real upstream Nuclei templates with matching results, with non-HTTP protocol templates rejected rather than silently ignored

#### Week 7-8: Native YAML Template Engine — ✅ done
- [x] Implement YAML parser for the HackerFive-native format (gopkg.in/yaml.v3), reserved for stateful/authorization-aware checks (IDOR, later business logic) that Nuclei's format has no equivalent for
- [x] Support matchers:
  - Status code matching
  - Word/regex matching
  - Content-length comparison
  - JSON path extraction
- [x] Support request chaining, including baseline-mode two-account comparison (use output of request 1 in request 2)
- [x] Create 20+ native templates for Phase 1 stateful vulns (IDOR)

**Deliverable:** Template runner executes custom native YAML templates with full matcher support

#### Week 8-9: Testing & Validation — ✅ done
- [x] Set up automated tests
  - Unit tests for detector modules (80%+ coverage) — see the 2026-09-10 coverage-raise commit (`ccea67d`, 77.1% → 83.5%, CI gate at 80.0%)
  - Integration tests against crAPI, vAPI, DVWA
  - Benchmark tests for performance (req/sec, memory usage)
  - Fuzz targets for the HTTP client and template/response parsers (seeded in Phase 1a, expanded here)
- [x] Run against practice targets:
  - crAPI: 8+ IDOR findings — met, 9 unique findings (`idor-1`..`idor-9`), 100% accuracy, after re-seeding real test data (2026-08-26)
  - DVWA: 15+ misconfiguration findings — **not met, honestly**: real combined result is 11 (misconfig + templates); DVWA structurally lacks most of what the rule table checks for (no `.env`/`.git`/`/admin`/`/swagger`/`/graphql`), and padding the rule table just to inflate this one target's count was explicitly rejected as a design call (2026-08-26)
  - Juice Shop: 20+ findings (XSS, auth, etc.) — not separately re-measured against this exact wording; superseded by Phase 2's own, more detailed per-detector numbers (see Milestone 2)
- [x] Measure false positive rate (<5% target), covering both the Nuclei-compatible and native template paths

**Deliverable:** Passing test suite with documented results

#### Week 9-10: Packaging & Documentation — ✅ done
- [x] Create Docker image (multi-stage build)
- [x] Write README with:
  - Installation instructions (go install, docker, source)
  - Quick-start examples
  - Template writing guide, covering both the Nuclei-compatible template path and the native format
- [x] Write installation guide for common platforms (Linux, macOS, Windows), built via `goreleaser` for cross-compiled binaries
- [x] Create issue/PR templates for GitHub, plus `CONTRIBUTING.md` (PR process, code style, required checks before submitting)

**Deliverable:** v0.1.0 release with clean documentation

**Phase 1b Success Metrics (Week 10 / v0.1.0 release):**
- [x] Detects 8+ IDOR issues in crAPI (100% accuracy) — 9 findings
- [ ] Detects 15+ misconfiguration issues in DVWA (<5% false positives) — **not met, revised down deliberately**: 11 real findings against DVWA's actual, narrower attack surface; see Week 8-9 above
- [x] Scans 100 targets in <2 minutes — 99.0s after fixing a real per-request-vs-per-target rate-limiter bug found while measuring this (2026-08-26)
- [x] Documentation complete and clear

---

### Phase 2: Expansion (Weeks 11-18) — API Auth + XSS + SQL Injection

**Goal:** Add stateful detection (authentication, session management) and improve coverage of common web vulnerabilities.

**Note on GitHub Action:** once the CLI output schema is stable (post v0.1.0), build `hackerfive/scan-action` as a thin wrapper around the existing Docker image. Treated as a parallel/stretch item, not a blocking Phase 2 deliverable. **Status: not started** — no `scan-action` repository exists yet; still open, and not a blocker for Phase 2, 3, or 4 work.

#### Week 11-12: API Auth Bypass Detector — ✅ done; also added `--scope` allow-list (not in doc03, carried forward from a Phase 1 follow-up finding)
- [x] Implement JWT testing:
  - None algorithm attack
  - Signature bypass (key injection)
  - Weak secrets (dictionary check)
- [x] Implement rate limiting bypass detection
- [x] Implement token reuse detection across accounts — later split out into a dedicated high-confidence BFLA check (LT-92, 2026-09-09), see Phase 8
- [x] Create 15+ auth-focused templates — 16 live-verified findings against crAPI/vAPI, ≥10 target comfortably met

**Test Target:** vAPI, crAPI authentication endpoints

**Deliverable:** Auth bypass detector with stateful request support

#### Week 13-14: XSS Detection — 🟡 built, live-verified, breadth target not met (honest miss, not padded)
- [x] Implement payload injection across common parameters
- [x] Add passive XSS detection (HTML parsing, dangerous tags)
- [ ] Optional: Browser-based validation with Chromedp (for DOM XSS) — still not built; DOM-XSS-via-Chromedp remains Parked in [follow-up.md](follow-up.md)'s Template Engine & Detection Backlog
- [ ] Create 25+ XSS templates (reflected, stored, DOM) — **not met**: 2 real live-verified findings against DVWA; doc03's ≥20 breadth target explicitly left open, see Milestone 2

**Note:** Focus on API-based XSS; DOM-based requires browser (out of scope for v1)

**Deliverable:** XSS detector with <10% false positives

#### Week 15-16: SQL Injection Detection — 🟡 built, live-verified, breadth target not met (honest miss, not padded)
- [x] Implement error-based SQLi detection (common error messages)
- [x] Implement boolean-based SQLi (time-based if time allows)
- [x] Template-based approach (use existing SQLi payloads)
- [ ] Create 20+ SQLi templates — **not met**: 2 real live-verified findings against DVWA (error-based + boolean-blind); doc03's ≥10 breadth target explicitly left open, see Milestone 2. (First-party, corpus-independent `sqli`/`xss`/`lfi`/`uploadbypass` detectors are separately scheduled — [Phase 9](18-implementation-plan-ph9.md) Step 4.)

**Note:** Not a replacement for SQLmap; focus on obvious cases

**Deliverable:** SQL injection detector integrated into template engine

#### Week 17: Information Disclosure — ✅ done
- [x] Implement API response field analysis
- [x] Detect verbose error messages
- [x] Detect internal IPs, hostnames, stack traces
- [x] Create 15+ info disclosure templates — folded into `misconfig`'s existing rule tables plus a new `checkCommentLeaks`/`CommentLeakPatterns` check, rather than a separate 15-template set; live-verified 0 findings against DVWA/Juice Shop root (no false positive; a true positive was never separately demonstrated live, since neither target's real comments happened to match)

**Deliverable:** Info disclosure module

#### Week 18: Testing & Release — ✅ done — `v0.2.0`
- [x] Full integration testing against Phase 2 targets
- [ ] Performance optimization (target: scan 1000 targets in <5 min) — not separately re-measured at this scale; the 100-target/<2min benchmark (Phase 1b) is the measured figure on record
- [x] Release v0.2.0 with Phase 2 features

**Phase 2 Success Metrics:**
- [x] Detects 10+ API auth issues — 16 achieved
- [ ] Detects 20+ XSS issues across test targets — **not met**, 2 achieved (real, live-verified; breadth is the gap, not the mechanism — see Week 13-14)
- [ ] Detects 10+ SQL injection issues — **not met**, 2 achieved (same "capability proven, breadth still open" status — see Week 15-16)

---

### Phase 3: Web UI & Upgradeable Templates (Weeks 19-24) — v0.3.0

**Goal:** Ship the local-only web UI and fix template-sync's biggest usability gap (synced templates lost on every binary upgrade). Swapped ahead of the Specialization phase (now Phase 4) at the user's request, since a UI makes `v0.2.0`'s existing detectors easier to exercise day-to-day; neither phase depends on the other. Full design in [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md); this section is the roadmap-level schedule, not a re-derivation of the design.

#### Week 19: Template Sync CLI + Engine Streaming Hooks — ✅ done (2026-08-28)
- [x] `pkg/templatesync`: Go port of `scripts/sync-nuclei-templates.sh`, writing into a persistent OS user-config directory (`os.UserConfigDir()`) instead of inside the release folder — matches upstream Nuclei's own `~/.config/nuclei-templates` convention (see doc12's "Template sync command")
- [x] `hackerfive templates sync` / `templates list` subcommands — cross-platform, no WSL/bash dependency (fixes the Windows gap the current shell script has)
- [x] `--templates` flag becomes repeatable, defaulting to both `./templates/` (bundled) and the persistent synced directory
- [x] `scanner.Engine` gains optional `WithFindingCallback`/`WithLogCallback` hooks — additive, CLI batch behavior unchanged (see doc12's "Live findings and logs: a real engine gap")

**Deliverable:** template sync runs natively on Windows/macOS/Linux; synced templates survive a binary upgrade with zero manual copying

#### Week 20-22: Local Web Server (`pkg/webui`) — ✅ done (2026-08-28)
- [x] `hackerfive serve` subcommand (`--port`, `--host`, loopback-only by default)
- [x] `pkg/webui` core: `http.Server`, routing, CSRF middleware, `go:embed`-ed templates/static assets (htmx + htmx SSE extension, vendored)
- [x] New Scan page + async job model (in-memory job store) + SSE-based live progress/findings/logs
- [x] Scan Status/Results page

**Deliverable:** `hackerfive serve` opens a browser, runs a scan against a target, and shows findings and warnings/errors live as they're detected — not just a final batch

#### Week 23: Templates Page + Dashboard/History — ✅ done (2026-08-28)
- [x] Templates page: active-template table (bundled vs. synced) + sync panel (pinned commit, category counts, "Sync now")
- [x] Dashboard + Scan History pages

**Deliverable:** full 5-page UI (Dashboard, New Scan, Scan Status, Scan History, Templates) working end-to-end

#### Week 24: Hardening & Release — ✅ done (2026-08-28)
- [x] CSRF protection verified; loopback-bind-by-default verified; token-required-on-non-loopback-bind implemented — re-verified live against a native Windows binary (not just WSL): forged `POST /scans` rejected (403), `--host 0.0.0.0` required the printed token once then worked via cookie alone
- [x] Manual cross-platform verification (Windows/Linux — see Milestone 3's macOS note above): download-shaped release folders (binary + `templates/`), `hackerfive serve`, sync templates, replace with a differently-versioned binary, confirm templates still listed with no copying
- [x] README/docs updated with a Web UI quick-start
- [x] Release v0.3.0

**Phase 3 Success Metrics (v0.3.0 release):**
- [x] `hackerfive serve` runs on all three released platforms with no separate install step — Windows and Linux manually verified against release-shaped binaries; macOS via CI only (see Milestone 3 note)
- [x] Live findings and logs stream during a scan (verified by hand against a lab target)
- [x] Synced templates confirmed to persist across a binary upgrade (sync → swap binary → templates still listed, no manual file copy)
- [x] doc12 reconciled with the actual implementation — any deviations documented there, not left silently stale

---

### Phase 4: Specialization (Weeks 25-32) — Prompt Injection + SSRF + Logic Flaws

**Goal:** Differentiate by targeting emerging and high-value vulnerabilities with minimal automation elsewhere. Full design in [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md).

#### Week 25-26: Prompt Injection Detector — done (2026-08-29)
- [x] Implement prompt breaking detection (instruction override) — `templates/nuclei-samples/promptinjection/system-prompt-leak.yaml`
- [x] Detect data exfiltration attempts (LLM-based) — `seeded-secret-exfil.yaml` (lab-only, per doc13's design split)
- [ ] ~~Create templates for common LLM apps (ChatGPT API, Anthropic, Hugging Face)~~ — superseded by doc13's actual design decision: one generic, structural-heuristic template that works against any chat-shaped endpoint (live-verified against AIGoat), not per-vendor-API templates. Revisit only if the generic template proves to have a real, measured accuracy ceiling against a specific provider's API shape.
- [x] Test against AI vulnerable labs — [AIGoat](https://github.com/AISecurityConsortium/AIGoat), see [20-setup-testing-targets.md](20-setup-testing-targets.md)

**Deliverable:** Prompt injection detector with specialized templates — done, see [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 1

#### Week 27-28: SSRF Detector — ✅ done, live-verified
- [x] Implement blind SSRF detection (DNS/HTTP callbacks)
- [x] Implement internal network detection (127.0.0.1, 10.0.0.0/8)
- [x] Create templates for common SSRF vectors — later widened well beyond query-param-only detection (`checkBodyParamTargets`, LT-96, 2026-09-09, see Phase 8)
- [x] Integration with Interactsh or similar callback service — first-party `pkg/oob` (own OAST client), not a vendored Interactsh dependency — a `checkTimingDifferential` fourth signal was deliberately descoped (2026-08-29), not built

**Deliverable:** SSRF detector with callback-based validation

#### Week 29-30: Business Logic Flaw Templates — ✅ done; generalized beyond crAPI 2026-09-10 (LT-135)
- [x] Create templates for common logic flaws:
  - Price manipulation (e-commerce)
  - Race conditions (payment processing) — the shipped coupon-mint/apply race-probe technique (last-byte-sync) is genuinely sophisticated
  - Workflow bypass (approval steps)
  - Token/coupon reuse
- [x] Hardcode patterns for known apps — literally hardcoded to crAPI's `DefaultCouponMintPath`/`DefaultCouponApplyPath`
- [x] Create extensible framework for custom logic templates — **✅ done 2026-09-10 (LT-135, not a phase step)**: paths, and request-body field names, and the success-response check are now all recon-derivable/overridable rather than hardcoded to crAPI — a spec-documented coupon/promo mint+apply pair (`ReconResult.CouponEndpoint`) auto-fills `businesslogic`'s config end-to-end (`--recon-file` → decision engine → `planexec`), or `--coupon-mint-path`/`--coupon-apply-path`/`--coupon-code-field`/`--coupon-amount-field` override manually; still crAPI-shaped by default when neither is available

**Deliverable:** 10+ business logic templates

#### Week 31: Advanced Features — 🟡 mostly done; HackerOne API integration built but never live-verified against a real account
- [x] Multi-target scanning orchestration — already done since Phase 1a (`Config.Targets` + worker pool); this step didn't need to re-build it
- [x] Finding deduplication across targets — `pkg/reporter.Dedup`
- [ ] Integration with HackerOne API (report submission automation) — `pkg/hackerone` is built and unit-tested against a mock server (including a "create never calls submit" test — see CLAUDE.md's permanent human-in-the-loop invariant), but **has never made a real API call**; needs the user's real `HACKERONE_API_USERNAME`/`HACKERONE_API_TOKEN` + a program handle to close, tracked in [follow-up.md](follow-up.md)'s "Reporting & Integrations"
- [x] Markdown/HTML/HackerOne-JSON-schema `Exporter` implementations (doc 02 §5) — deferred here from Phase 1b's v0.1.0 (see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) Step 5); built together with the HackerOne API integration since it's the first point three concrete output formats are actually needed at once

**Note on HackerOne API integration:** treat this as report-drafting assistance, not unattended submission. It needs its own auth handling (API token or OAuth2, depending on endpoint), is subject to H1's per-endpoint rate limits, and requires a hand-authored mapping from `Finding` fields to H1's report schema (title, severity/CVSS, weakness/CWE) — none of which is a quick wrapper around the API. The exporters above feed that mapping directly, and should apply the same default-redact-sensitive-evidence policy `follow-up.md` calls for on HTML/Markdown output.

#### Week 32: Release — 🟡 features done, tag never cut
- [ ] Release **v0.4.0** with all Phase 4 features — **no `v0.4.0` tag exists**: `git tag --list` jumps `v0.3.0` → `v0.5.0` directly. Phase 4's actual detector/template work is done (above), but Phase 5 started before a dedicated release checkpoint was cut, and by the time this was noticed the project had already moved to "tag on batch-readiness, not step number" (see [Versioning note](#versioning-note)) — leaving unchecked rather than backfilling a tag retroactively (not v1.0.0 — v1.0.0 is gated on real-world validation, not a fixed week)
- [ ] Write blog posts on Prompt Injection detection — not done, no blog exists in this repo

**Phase 4 Success Metrics:**
- [x] Prompt injection detector working against test LLM labs
- [x] SSRF detector working (blind SSRF via callback service)
- [x] 10+ business logic templates delivered — see the "scoped to crAPI's exact routes" caveat at Week 29-30

---

### Phase 5: Recon & Orchestration Foundations (Weeks 33-40)

**Goal:** Build the pieces every later agent-integration phase needs that don't depend on an MCP server actually working — a recon phase (`pkg/recon/`), a frozen `Finding` schema, a `Job.PlanTree` data model, **and a deterministic decision engine (`pkg/fingerprint` + a capability registry, doc90 Decision 6/Group I) that populates real `PlanTree` leaves from a plain `hackerfive scan`/`recon` run, with zero LLM or agent involvement** — plus read-only Web UI views. Full design in [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md), which schedules [90-research-hackerbot.md](90-research-hackerbot.md)'s recon-independent backlog items (Groups R and I1-I3) and all of [91-research-recon-phase.md](91-research-recon-phase.md)'s Group R that doesn't need the MCP server. Comes after Phase 4, not swapped ahead of it — the `findings.export` MCP tool (Phase 6) needs Phase 4's `Exporter`/HackerOne-JSON work. **Split out from what was originally a single "Phase 5" specifically so the MCP Go SDK's unverified `elicitation`/`tasks` support (Phase 6's real risk) can't stall this phase's independently-shippable work** — and the decision engine belongs here for the same reason: it's deterministic, testable, and useful standalone, with no MCP dependency at all.

#### Week 33: Foundations — ✅ done 2026-08-30
- [x] Ratify Decisions 1-6 (single coordinator, no shell/exec tool — including for recon — MCP `elicitation`/`tasks`, task-tree-leaf `Confidence` distinct from `Finding.Confidence`, stateless/tiered LLM invocation, deterministic-first dispatch)
- [x] Eval harness stub against lab targets (crAPI, DVWA, vAPI, Juice Shop) — detector-only baseline, no agent yet

**Deliverable:** committed design decisions; a working baseline benchmark with zero agent involvement

#### Week 34-35: Finding Schema Freeze + Task-Tree Data Model — ✅ done 2026-08-30
- [x] Freeze/publish `docs/schema/finding.schema.json`, `Severity`/`Confidence` documented as detector-set, never agent-writable
- [x] `Job.PlanTree` (`pkg/agenttask`): leaf-only-mutation task tree, leaf-level `Confidence` bands (High/Medium/Low)

**Deliverable:** a versioned wire schema and a task-tree data model with a tested mutation guard

#### Week 36-37: Recon Package + Decision Engine — ✅ done 2026-08-31
- [x] `pkg/recon/`: Waves 0-4 (zero-touch, passive, active-low-noise, application-layer mapping, aggregation), `--scope` cross-check running immediately after Wave 1, before any active probe
- [x] `ReconResult` schema, frozen and versioned — now well past its original freeze, at v1.11 as of 2026-09-10 (`--auto-provision-account`'s `SignupEndpoint`)
- [x] `hackerfive recon` CLI subcommand, usable standalone
- [x] `pkg/fingerprint`: tech-signature detection (header/body/favicon/port) enriching `ReconResult.TechStack` — doc90 I2
- [x] Capability registry (`pkg/registry`) + deterministic decision engine: matches a `TechFact` against the registry to populate real `PlanTree` leaves, no LLM/agent required — doc90 I1/I3
- [x] Generated `templates/index.json` — doc14 R9, pulled forward from what was originally Phase 7 Week 55, since the decision engine needs it now

**Note:** this week's scope grew after the 2026-08-30 hybrid-architecture direction (deterministic decision engine now, LLM only as a later fallback) — full design in doc14 R7-R9; revisit the 2-week estimate at implementation time rather than assume it still fits, same "revise down with reasoning, don't pad" discipline this project already applies elsewhere.

**Deliverable:** `hackerfive recon` runs against a lab target and produces a schema-valid `ReconResult`; `--recon-depth passive` confirmed to never send an active probe; the decision engine resolves a real target's fingerprint to matched detectors/templates as actual `PlanTree` leaves, live-verified with zero LLM calls

#### Week 38: Recon + Plan-Preview Web UI — ✅ done 2026-08-31
- [x] Recon results page (`pkg/webui`) — browse a `ReconResult`, independent of any agent
- [x] Plan-preview page — read-only render of a `PlanTree`; no approve/reject yet (approve/reject/edit landed later, Phase 6 Week 46)

**Deliverable:** both pages render real data end-to-end in a browser, read-only

#### Week 39-40: Integration Testing + Release — ✅ done 2026-08-31 — `v0.5.0`
- [x] Full integration testing across Weeks 33-38's work
- [x] Release **v0.5.0**

**Phase 5 Success Metrics:**
- [x] `hackerfive recon` live-verified against a lab target, producing a schema-valid, correctly-labeled `ReconResult`
- [x] `Job.PlanTree` mutation guard confirmed to reject shape-changing updates
- [x] Both new Web UI pages confirmed live in a browser
- [x] The decision engine (`pkg/fingerprint` + registry) resolves at least one real lab target's fingerprint to matched `PlanTree` leaves with zero LLM calls, live-verified

---

### Phase 6: MCP Server & Approval Gate (Weeks 41-48) — Hacker-in-the-Loop, Part 1

**Goal:** Make HackerFive addressable by an LLM agent, safely — an MCP server (including a `recon` tool wrapping Phase 5's package, plus `tools.search`/`templates.search` over Phase 5's capability registry), an `elicitation`-based human-approval gate seeded from a real `ReconResult`, the tiered LLM fallback (doc90 I4) for the cases Phase 5's deterministic decision engine can't resolve, the hard safety blockers (program-policy pre-flight, hard-fail scope, scope-creep gate), and an actionable Web UI approval surface (approve/reject/edit, a budget gauge, a kill switch) on top of Phase 5's read-only plan preview. Full design in [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md). Depends on Phase 5, not the reverse.

#### Week 41-42: MCP Server — ✅ done 2026-09-02
- [x] Verify an MCP Go SDK supports `elicitation`/`tasks` (new dependency, confirm via pkg.go.dev before adding)
- [x] `pkg/mcpserver`: `scan`, `templates.list`, `templates.sync`, `findings.export`, `recon`, `tools.search`, `templates.search` tools — no shell/exec-shaped tool anywhere in the server; the last two expose Phase 5's registry via search, not one MCP tool per detector/recon-tool/template (doc90 I1)

**Deliverable:** a real MCP client can list and call these tools against a lab target, live-verified

#### Week 43: Approval Gate + Spend Ceiling + Tiered LLM Fallback — ✅ done 2026-09-02
- [x] `plan` MCP tool built on native `elicitation`/`tasks`, seeded from a real `ReconResult` — no request sent without human approval
- [x] Per-job spend ceiling, hard-enforced (not just logged)
- [x] Tiered LLM fallback (local small model + frontier via OpenRouter, doc90 Decision 5/I4): invoked only when Phase 5's decision engine has no registry match for a `PlanTree` leaf; one stateless, schema-validated input/output call per leaf, never a persistent session

**Deliverable:** a plan proposal — grounded in real recon facts, not an empty tree — only proceeds after a real client's own approval UI grants it; a leaf the decision engine couldn't resolve is confirmed, live, to trigger exactly one tiered LLM call, not a fallback path available at any time

#### Week 44-45: Hard Safety Blockers + Scope-Creep Gate + Prioritization — ✅ done 2026-09-05 (D2 + B4 + Retry-After; H4 moved to Phase 7 Step 4)
- [x] Program-policy pre-flight check — hard blocker, not a warning
- [x] Hard-fail (not warn) on missing scope for agent-initiated `scan`/`recon` calls
- [x] Scope-creep gate: `ReconResult.OutOfScope` triggers fresh elicitation before an out-of-scope host is touched (first implementation — compliance rounding comes in Phase 7)
- [x] Cost/attempt-aware prioritization (MAPTA's measured spend/success correlation) drives a stop-and-escalate signal per task-tree leaf — shipped as H4, moved to and delivered in Phase 7 Week 53 (`ph7-step4c`)

**Deliverable:** an agent-driven run against a disallowed, unscoped, or scope-creeping target refuses outright or re-prompts for approval

#### Week 46: Approval UI — ✅ done 2026-09-04, deliberately narrower than "resolves the same elicitation response" below
- [x] Plan-preview page (Phase 5) gains Approve/Reject/Edit controls resolving a real `elicitation` response — shipped as the Web UI's own **complete, self-contained** approval surface (`pkg/planexec` shared dispatcher + `POST /plan-preview/execute`), not literally the *same* pending-approval object an out-of-process MCP session is waiting on — `hackerfive mcpserve`/`hackerfive serve` are two separate, unconnected OS processes with no shared approval store; named as a deliberate scope limitation, not a bug, revisit only if a real workflow needs cross-process interop
- [x] Budget/spend gauge against the per-job ceiling — `<progress>` against `Tree.SpendSoFar()`/`SpendCeilingUSD`
- [x] Always-reachable kill switch/pause, confirmed to actually stop a running job — `Job.Cancel()`, live-verified and then UX-fixed twice (LT-1, LT-27) after real Web UI use surfaced issues

**Deliverable:** a human can approve a plan and pause/kill a running agent session from HackerFive's own Web UI, not only via an external MCP client's UI

#### Week 47-48: Session Log + Release — ✅ done 2026-09-06 — `v0.6.0`
- [x] Structured, persisted agent session log (queryable, not yet the live Web UI view) — the live Web UI Agent tab followed later, Phase 7 Week 51-52
- [x] Full recon → plan → approve → scan → export round trip live-verified against a lab target
- [x] Release **v0.6.0**

**Phase 6 Success Metrics:**
- [x] MCP server live-verified against a real client with no shell/exec-shaped tool present
- [x] Human approval via `elicitation` (or the Web UI's own approval controls) confirmed to gate every plan before traffic goes out
- [x] Program-policy pre-flight, missing-scope, and scope-creep hard blockers all confirmed live
- [x] The tiered LLM fallback triggers only on a confirmed decision-engine miss, live-verified, with every call logged as a single input/output pair tied to one `PlanTree` leaf

---

### Phase 7: Agent Hardening, Ecosystem & Trust (Weeks 49-56) — Hacker-in-the-Loop, Part 2

**Goal:** Round the Phase 6 backbone out to doc90's full "Hacker-in-the-Loop Ready" Definition of Done — full `AllowWrites` attestation, a live Web UI Agent tab (now visualizing a real approval flow, not built any earlier since there was nothing to show), the OWASP Agentic Top 10 mapping against real shipped code, template-ecosystem staging, and a real agent-driven benchmark run. Full design in [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md). Depends on Phase 6, not the reverse.

#### Week 49: Tool Surface Completion — ✅ done 2026-09-06
- [x] `hackerfive templates list --json`
- [x] `hackerfive triage --findings <file> --llm-assist` (LT-41 CLI entry point)
- [x] Recon-derived field self-suggest wired into `plan --llm-assist` and `scan --recon-file` (new `pkg/fieldsuggest`)
- [x] MCP tool-list scoping by launch-time agency level: `mcp-serve --agency readonly` omits `scan`/`plan`/`templates.sync` from `tools/list`

#### Week 50: Approval & Compliance Rounding — ✅ done 2026-09-06
- [x] `AllowWrites` only honored via a two-round elicitation attestation (`scan`: `approve` + `acknowledge_writes`; `plan`: per-plan `acknowledge_writes` when a businesslogic leaf exists) — never from the request body; CLI `--allow-writes` unchanged
- [x] HackerOne submission documented as a permanent human-in-the-loop invariant (docs/05-hackerone-and-legal.md, B3)
- [x] Scope-creep gate: compliance-rounding pass — out-of-scope observations now in the MCP `plan` session log and the Web UI job audit trail

#### Week 51-52: Observability Upgrade — ✅ done 2026-09-07 — C1/C2/C3/C5 (`ph7-step3a`), C7 (`ph7-step3b`)
- [x] Web UI "Agent" tab streams agent activity live over SSE (C1) — 2026-09-07. In-process/job-scoped: it renders the webui process's own agent-like actions (plan resolve, plan approve/reject, plan-execution dispatch) as structured `agenttask.SessionLogEntry` rows on `/scans/{id}/events`, the same record type `pkg/mcpserver`'s `session.log` uses. An out-of-process MCP session's tool calls are not streamed here (the two are separate processes with no shared store) — noted, not silently dropped.
- [x] Audit trail extended with agent-specific facts (C2) — 2026-09-07: the `plan.execute` agent entry's params carry approved-leaf count, `allow_writes` posture, scope-enforced/wildcard, and out-of-scope count; the MCP `plan`/`scan` round-2 session-log entry records the elicitation grant reference (`RequestState`).
- [x] Evidence-linked claims: `findings.export` rejects a draft citing a nonexistent `Finding.ID` (C3) — 2026-09-07, `reporter.ValidateCitations` + `cited_finding_ids` on the export tool.
- [x] Sequence-gated `#logs`/`#findings`/`#agent` catchup replay (C5 / follow-up.md LT-5) — 2026-09-07: a monotonic per-Job event sequence + a client last-seen marker per list, so a late/reconnecting client recovers the connect-gap with no duplication.
- [x] PlanTree structural upgrade + plausibility veto (C7 / follow-up.md LT-44 + LT-49) — 2026-09-07, `ph7-step3b`. `agenttask.PlanNode` gains `Priority`/`Class` + `StatusVetoed`; `registry.Resolve` now nests leaves under per-vuln-class intermediate nodes (`GroupIntoClassNodes`, `LeafClass`) and stamps a confidence-derived dispatch priority `planexec.RunPlan` honours (start order). A structural `ExecOptions.SeedFn` hook with one built-in (`EndpointSeedFromFindings` — a same-host finding's URL seeds a later idor/ssrf leaf's blank endpoint/param, logged, blank-only) is wired at the MCP + webui execute paths; a full `DependsOn` graph is out of scope (follow-up.md LT-56). New `llmfallback.VetoImplausibleLeaves` (opt-in behind `--llm-assist`, ceiling-respecting, no-op without an LLM tier) runs one classify call over the confident `StatusPending` leaves and can only demote (one confidence band) or drop (→ `StatusVetoed`, never dispatched) with a logged reason.

#### Week 53: Live Log Injection + Concurrency Ceilings + Redundant-Request Elimination — ✅ done 2026-09-07 (`ph7-step4a/b/c`)
- [x] Live log injection on the Agent tab (stretch) — shipped as C4, an operator-note form streamed over the existing agent-event SSE channel (`ph7-step4c`)
- [x] Aggregate per-target concurrency ceiling across concurrent `scan` calls in one session — D1, `pkg/mcpserver/scangate.go` (`ph7-step4c`)
- [x] Executor response cache + recon-404 `path:` skip (D5 / follow-up.md LT-54 + LT-55) — `ph7-step4b`

#### Week 54: OWASP Agentic Top 10 Mapping — moved to [Phase 9](18-implementation-plan-ph9.md) Step 5 (2026-09-10)
- This was a dedicated Phase 7 step doing an "interim" pass against shipped Phase 5-7 code, ahead of a full re-walk already deferred to Phase 9 (which needs the agent-enumeration + active-injection surface Phase 9 Steps 3-4 add). Since Phase 9 was always going to re-walk the same ASI01-10 table in full shortly after, the interim pass was dropped rather than duplicating the work — this week's item and its whole step were removed from [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md); Phase 9 Step 5 is now the only OWASP pass. `v0.7.0` no longer carries this as a gate.

#### Week 55: Template Ecosystem & Triage Support — ✅ done 2026-09-07 (renumbered Step 5)
- [ ] ~~Generated `templates/index.json`~~ — moved to Phase 5 Week 36-37 (doc14 R9); the decision engine needs it several phases earlier than this week
- [ ] `templates/proposed/` staging directory, confirmed never auto-loaded — deferred to [Phase 9](18-implementation-plan-ph9.md) Step 5
- [ ] Triage-assist mode on `Exporter` output (annotation only, never mutates `Finding`) — deferred to [Phase 9](18-implementation-plan-ph9.md) Step 5
- [ ] Structured feedback capture on human override/dismissal of agent triage notes — deferred to [Phase 9](18-implementation-plan-ph9.md) Step 5
- [x] F3: gate response-grep secret/exposure templates on a real-app-content signal before emitting them (LT-67); F4: narrow corpus load for a small explicit template-ID/tag set (LT-71) — ✅ done 2026-09-07 (`ph7-step4` batch, [Phase 7](16-implementation-plan-ph7.md) Step 5 — renumbered 2026-09-10 from "Step 6a")

#### Week 56: Eval Maturity + Release — ⬜ not started (renumbered Step 6)
- [ ] Real agent-driven benchmark run against all four lab targets, fp/fn rate tracked separately from detector-level rate, full cost accounting recorded honestly
- [ ] Release **v0.7.0**

**Phase 7 Success Metrics:**
- [ ] `AllowWrites` attestation and scope-creep compliance rounding both live-verified
- [ ] Agent tab live-verified streaming real tool calls/reasoning in a browser
- [ ] OWASP Agentic Top 10 mapping recorded against real code, not restated intentions
- [ ] Agent-driven fp/fn rate measured and reported honestly, with its delta from Phase 5's detector-only baseline

---

### Phase 8: Detection Coverage — Breadth & Precision (Weeks 57-64) — v0.8.0

**Goal:** Widen *what HackerFive can detect*, against the agent pipeline Phases 5-7
built and hardened (both of which explicitly scoped detector expansion out). Schedules
[follow-up.md](follow-up.md)'s already-approved "Detection Coverage" table and its LT-7 /
LT-8 / LT-23 live-testing findings. Full design in
[17-implementation-plan-ph8.md](17-implementation-plan-ph8.md). Read/enumerate-only
throughout — banner-grab and passive inspection, never command execution.

**Split 2026-09-07.** Originally one 10-step phase. This phase keeps the
**breadth + precision** work (TCP/TLS, JS-static, semver gating, richer crawl —
each near self-contained). The **depth + active** work — OOB blind-RCE,
template-format gaps, AI-agent surface, WAF-aware + native injection detectors —
moved to **[Phase 9](18-implementation-plan-ph9.md)** (each needs its own design
pass, several want this phase's surface-widening first). The single cross-phase
ordered backlog lives in
[17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) § "Execution order".
Version tags are cut on batch-readiness, not step number.

#### Weeks 57-58: TCP protocol support + network-service exposure detector — ⬜ not started
- [ ] `tcp:` templates load and run (bounded connect/probe/banner-match); `code:`-carrying `tcp:` still rejected
- [ ] `netservice` detector: anonymous-FTP / unauth-DB / open-Elasticsearch, read-only, `--scope`-gated; `resolvePortFacts` dispatches it (closes LT-23's structural gap)

#### Week 59: TLS/SSL passive checks — ✅ done 2026-09-12
- [x] `tls` detector: expired/weak/mismatched certs, sub-1.2 protocols, weak ciphers, via stdlib `crypto/tls`, no new dependency — see [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) Step 2

#### Weeks 60-61: JS static analysis — ✅ done 2026-09-09
- [x] Served-JS endpoint extraction folded into `ReconResult.Endpoints` (`Source: "js-static"`), widening the idor/ssrf candidate surface
- [x] High-signal hardcoded-secret detection as `misconfig` findings, decoy-set false-positive rate measured

#### Week 63: Version gating + richer crawl — 🟡 Step 6 partly landed 2026-09-07
- [x] `templates/index.json` carries `AffectedRange`; out-of-range CVE templates dropped when the tech version is known (closes LT-7 / P0-1b) — done 2026-09-11, see [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) Step 4
- [x] Configurable crawl depth (default unchanged) + opt-in JS-rendered crawl with a per-host timeout (closes LT-8) — `--crawl-depth` done; opt-in headless crawl done 2026-09-09 (`--headless-crawl`, LT-99); content-discovery done 2026-09-12 (`--content-discovery`)
- [x] Bounded name-ranked probe of unprobed `robots.txt`/`sitemap.xml` endpoints → `resolveEndpointFacts` (LT-76); redirect-flow rule for `*/bounce`/OAuth/SSO/logout paths (LT-77 partial); redirect-chain fidelity + per-host tech-fact attribution (LT-64/LT-65/LT-84b); numeric-query-param ID candidates (LT-83); per-path-timeout vs host-down breaker (LT-86); OpenAPI-JSON spec walker (LT-40); known-CDN-ASN naabu skip (LT-61) — 2026-09-07
- [x] Opt-in first-party hidden-parameter mining (`--param-mining`, LT-100) — done 2026-09-09
- [x] LT-40 tail (b)/(c) — widen spec-probe paths + YAML request bodies — done 2026-09-07 (`Phase 7` Step 6a batch); LT-40 (a) GraphQL SDL/introspection stays open, trigger-gated
- [x] Bounded content-discovery + embedded wordlist (`--content-discovery`, SecLists' MIT-licensed `common.txt`, 4,751 entries) — done 2026-09-12, see [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) Step 5
- [ ] CT-log sibling-API discovery (LT-63) — still open, separate from the content-discovery item above

#### Week 64: Eval + release — ⬜ not started
- [ ] New-detector yield + any new false-positive mode measured against all lab targets, tracked against the <5% target
- [ ] Release **v0.8.0** (cut on batch-readiness; does not wait on Phase 9)

**Phase 8 Success Metrics:**
- [ ] TCP/TLS/JS-static detectors all live-verified against lab targets, read-only confirmed
- [ ] LT-7 closed: real multi-version Nginx hosts get different template lists
- [ ] Detection Coverage table's "Add" rows for this phase moved to "✅ shipped" with measured yield, still within the <5% false-positive target

---

### Phase 9: Detection Coverage — Depth & Active (Weeks 65-70) — v0.9.0

**Goal:** The depth half of the detection-coverage expansion — the areas that each
need their own design pass and want Phase 8's surface-widening first. Full design in
[18-implementation-plan-ph9.md](18-implementation-plan-ph9.md). Same read/enumerate-only
boundary: an OOB, injection, or WAF-bypass payload's only effect is to reach the app.

#### Week 65: OOB blind-RCE verification — ⬜ not started
- [ ] Callback-only RCE proof via `pkg/oob`, never an attacker-meaningful command; no real public OOB server in code/tests

#### Weeks 66-67: Remaining template-format gaps — ⬜ not started
- [ ] `xpath` matcher/extractor (dependency footprint verified first) or explicitly descoped; `flow:` cross-block `_N` indexing or explicitly descoped; `substr`/`date_time`/`generate_jwt` DSL; `flow:` script constructs or explicitly descoped

#### Week 68: AI-agent surface modeling — ⬜ not started
- [ ] `llms.txt`/`SKILL.md`/MCP: passive recon fact + read-only detector (manifest injection-marker scan, unauthenticated MCP `tools/list`, never `tools/call`) (closes LT-78)

#### Weeks 69-70: WAF-aware probing + active injection / upload-bypass detectors + trust hardening + release — ⬜ not started
- [ ] WAF-detect recon fact + `403`-is-signal mutation retry + first-party `sqli`/`xss`/`lfi`/`uploadbypass` detectors, parameter-aware & read-only, decoy FP rate measured (closes LT-87)
- [ ] Full OWASP Agentic Top 10 re-walk against shipped Phase 5-9 code (Ph7 D4); `templates/proposed/` isolation (Ph7 E2); triage-assist annotations + structured feedback capture (Ph7 F1/F2)
- [ ] New-detector yield + any new false-positive mode measured against all lab targets, tracked against the <5% target
- [ ] Release **v0.9.0**

**Phase 9 Success Metrics:**
- [ ] OOB-RCE + native `sqli`/`xss`/`lfi`/`uploadbypass` detectors live-verified against lab targets, read-only confirmed
- [ ] LT-78 / LT-87 closed; all ASI rows re-walked against real Phase 5-9 code
- [ ] Detection Coverage table's remaining "Add" rows moved to "✅ shipped" with measured yield, still within the <5% false-positive target

---

## Versioning note

`v0.1.0` → … → `v0.6.0` → `v0.7.0` → `v0.8.0` → `v0.9.0` track feature phases (1 through 9) in order — with the caveat that a phase is a planning bucket, not a release contract: since 2026-09-07 the `v0.x.0` tags are cut when a coherent batch of work is done and green, not when a numbered step count is reached (Phase 8's split into breadth/precision + [Phase 9](18-implementation-plan-ph9.md) depth/active is the first case). **`v1.0.0` is deliberately not tied to a phase or a week** — it marks real-world trust, not feature completeness, and is gated on actually using the tool against real, authorized targets and finding real issues with it, not on shipping a checklist of detectors. See [Milestone 8](#milestone-8-v100--real-world-validation-no-fixed-week) below. This mirrors doc05's "Tool Maturity" prerequisites (which already gate HackerOne program eligibility on validated false-positive rate and documentation, not a version number) and is consistent with how mature scanners in this space (e.g. Nuclei) treat 1.0 as a stability/trust signal rather than a feature-count milestone.

## Timeline & Milestones

### High-Level Timeline

Kept as a table rather than a hand-drawn Gantt chart — a table only needs one cell changed when a phase's weeks shift, instead of recounting characters across an ASCII diagram (a repeated source of drift in earlier revisions of this doc).

| Phase | Weeks | Duration | Focus | Ships as | Status (2026-09-10) |
|---|---|---|---|---|---|
| 1a | 1-4 | 4 wks | Core engine + IDOR MVP | (internal checkpoint) | ✅ done |
| 1b | 5-10 | 6 wks | Misconfiguration + template engines (Nuclei-compatible + native) + validation + packaging | v0.1.0 | ✅ released |
| 2 | 11-18 | 8 wks | Auth bypass, XSS, SQLi, information disclosure | v0.2.0 | ✅ released (XSS/SQLi breadth targets honestly unmet, see Milestone 2) |
| 3 | 19-24 | 6 wks | Web UI + upgradeable template sync | v0.3.0 | ✅ released |
| 4 | 25-32 | 8 wks | Prompt injection, SSRF, business logic | v0.4.0 | 🟡 work done, tag never cut (see Milestone 4) |
| 5 | 33-40 | 8 wks | Recon & orchestration foundations (`pkg/recon`, `Finding` schema freeze, `PlanTree` data model, deterministic decision engine + capability registry, read-only recon/plan-preview UI) | v0.5.0 | ✅ released |
| 6 | 41-48 | 8 wks | MCP server & approval gate (elicitation-based approval seeded from recon, `tools.search`/`templates.search`, tiered LLM fallback, hard safety blockers, actionable approval UI) | v0.6.0 | ✅ released |
| 7 | 49-56 | 8 wks | Agent hardening, ecosystem & trust (AllowWrites attestation, live Agent tab, OWASP Agentic Top 10 mapping, eval maturity) | v0.7.0 | 🟡 Weeks 49-53/55 done; Weeks 54/56 (OWASP mapping, eval+release) open |
| 8 | 57-64 | 8 wks | Detection coverage — breadth & precision (TCP + network-service detector, TLS/SSL passive checks, JS static analysis, affected-version gating, richer crawl) — split 2026-09-07, depth/active work moved to Phase 9 | v0.8.0 | 🟡 JS static (Steps 3) done; TCP/TLS (Steps 1-2) and eval/release (Step 10) open |
| 9 | 65-70 | 6 wks | Detection coverage — depth & active (OOB blind-RCE, remaining template-format gaps, AI-agent surface modeling, WAF-aware probing + native `sqli`/`xss`/`lfi`/`uploadbypass` detectors) | v0.9.0 | ⬜ not started |
| — | not scheduled | usage-gated | Real-world validation (see [Versioning note](#versioning-note)) | v1.0.0 | ⬜ not started |

**Parallel tracks** (start weeks are approximate targets, not hard dependencies):

| Track | Starts | Notes |
|---|---|---|
| HackerOne profile/program setup | ~Week 15 | Runs alongside late Phase 2 |
| Active bug bounty hunting | ~Week 19 | Ongoing once v0.2.0 ships |
| GitHub Action (`scan-action`) | ~Week 11 | Post-v0.1.0, once the CLI output schema is stable. **Not started as of this doc's last update** — no blocker on Phases 2-4, pick up whenever there's spare time |

### Milestone Checklist

Trimmed to things the project actually controls (built/shipped/verified). Removed external-validation numbers this team can't directly move (star counts, contributor counts, "featured in" mentions, press coverage) — those are outcomes to hope for, not deliverables to plan around.

#### **Internal Checkpoint: Phase 1a (Week 4)**
- [x] IDOR-only scanner working end-to-end (see Phase 1a Success Metrics above)
- [x] Not a public release — this is the internal go/no-go before starting Phase 1b

#### **Milestone 1: MVP Release (Week 10) — v0.1.0**
- [x] v0.1.0 released on GitHub (2026-08-26)
- [x] IDOR detector working (crAPI: 8+ findings) — 9 findings, 100% accuracy
- [ ] Misconfiguration detector working (DVWA: 15+ findings) — **not met, honest miss**: 11 real findings; see Phase 1b Week 8-9 for why the target was revised down rather than padded
- [x] Documentation complete

#### **Milestone 2: Expanded Coverage (Week 18) — v0.2.0**
- [x] v0.2.0 released (2026-08-28) — see [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) for the full, honest results
- [x] API auth detector added — 16 live-verified findings against crAPI/vAPI, doc03's ≥10 target met
- [x] XSS detector added — working, live-verified (2 real findings against DVWA); doc03's ≥20 breadth target not met, see doc11
- [x] SQLi detector added — working, live-verified (2 real findings against DVWA, error-based + boolean-blind); doc03's ≥10 breadth target not met, see doc11
- [ ] 100+ templates in repository — **not met, real gap**: only 27 first-party/curated templates are actually checked into `templates/`. The ~2,500-template upstream corpus (`scripts/sync-nuclei-templates.sh`) is deliberately *synced from a pinned commit at scan time, not vendored/committed* (see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) Step 2) — a real design choice (avoids redistributing upstream content, stays current with a pinned upgrade path) that this milestone item's literal wording didn't anticipate. Worth a future decision: revise this milestone's wording, or treat it as intentionally unmet
- [ ] HackerOne profile set up, first programs joined — a business/account task outside this project's code, not something a coding session tracks or actions

#### **Milestone 3: Web UI & Upgradeable Templates (Week 24) — v0.3.0**
- [x] v0.3.0 released
- [x] `hackerfive serve` working end-to-end on Linux/Windows — manually verified against goreleaser-shaped release binaries (native Windows .exe, and a cross-compiled linux/amd64 binary run under WSL); macOS relies on CI's `macos-latest` build/test/lint pass (already green), not a manual download-and-run — no Mac hardware available in this environment, stated rather than assumed
- [x] Live findings/logs streaming during a scan
- [x] Template sync survives a binary upgrade with no manual file copying — verified directly: synced templates via one binary (`v0.3.0-verify-a`), then listed correctly by a second, differently-versioned binary (`v0.3.0-verify-b`) pointed at the same persistent `%AppData%\hackerfive\nuclei-templates`, with zero re-sync or copying
- [x] `hackerfive templates sync`/`list` working natively on Windows (no WSL/bash required) — git itself is still a stated prerequisite for `templates sync` specifically (see doc12's "Template sync command" §1)

#### **Milestone 4: Specialization (Week 32) — v0.4.0**
- [ ] v0.4.0 released — **no tag exists** (`git tag --list` jumps `v0.3.0` → `v0.5.0`); the underlying work is done (below), see Week 32's note
- [x] Prompt injection detector added
- [x] SSRF detector added
- [x] Business logic templates added — generalized beyond crAPI's exact routes/fields 2026-09-10 (LT-135), see Week 29-30

#### **Milestone 5: Recon & Orchestration Foundations (Week 40) — v0.5.0**
- [x] v0.5.0 released (2026-08-31)
- [x] `hackerfive recon` live-verified against a lab target, producing a schema-valid, correctly-labeled `ReconResult`
- [x] `--recon-depth passive` confirmed, live, to never send an active probe
- [x] `Job.PlanTree` mutation guard confirmed to reject shape-changing updates
- [x] Recon-results and Plan-preview Web UI pages both confirmed live in a browser, read-only
- [x] Deterministic decision engine (`pkg/fingerprint` + registry) populates real `PlanTree` leaves from a plain, non-agent `hackerfive scan`/`recon` run, zero LLM calls, live-verified

#### **Milestone 6: MCP Server & Approval Gate (Week 48) — v0.6.0**
- [x] v0.6.0 released (2026-09-06)
- [x] MCP server (`scan`/`templates.list`/`templates.sync`/`findings.export`/`recon`) live-verified against a real MCP client, no shell/exec-shaped tool present
- [x] `plan`/`elicitation`-based human approval gate — seeded from a real `ReconResult` — confirmed to block traffic until a human approves
- [x] Program-policy pre-flight, missing-scope, and scope-creep hard blockers all live-verified
- [x] Web UI approval controls (approve/reject/edit, budget gauge, kill switch) confirmed live — approve/reject/edit is the Web UI's own self-contained surface, not literally interoperable with an out-of-process MCP session's pending elicitation (Week 46's named limitation)
- [x] Tiered LLM fallback (local + OpenRouter) confirmed to trigger only on a decision-engine miss, never as a standing parallel path

#### **Milestone 7: Agent Hardening, Ecosystem & Trust (Week 56) — v0.7.0**
- [ ] v0.7.0 released
- [ ] `AllowWrites` attestation and scope-creep compliance rounding both live-verified
- [ ] Web UI Agent tab live-verified streaming real tool calls/reasoning
- [ ] OWASP Agentic Top 10 mapping recorded against real shipped code
- [ ] Agent-driven false-positive/false-negative rate measured against lab targets, tracked separately from detector-level rate

#### **Milestone 8: v1.0.0 — Real-World Validation (no fixed week)**
Gated on actual usage, not a calendar date — see [Versioning note](#versioning-note):
- [ ] HackerFive run against at least one real, authorized target from [22-authorized-targets.md](22-authorized-targets.md) (not a lab container)
- [ ] At least 3 genuine, previously-unknown findings confirmed against real authorized targets — leads triaged and reported, not lab-only results
- [ ] False-positive rate holds under the <5% target in practice against real targets, not just the lab benchmark suite
- [ ] v1.0.0 released once the above hold

Community growth (contributors, stars, template submissions, bounty income) is a hoped-for outcome of shipping a genuinely useful tool — not something tracked as a dated milestone here, since none of it is directly controllable by the maintainer's own effort.

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — vulnerability classes referenced above
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — modules being built each phase
- [04-environment-and-testing.md](04-environment-and-testing.md) — how each week's deliverables get validated
- [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) — file-by-file build plan and verification steps for Phase 1a (Weeks 1-4)
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — file-by-file build plan for Phase 1b (Weeks 5-10)
- [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) — file-by-file build plan for Phase 2 (Weeks 11-18)
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — design + implementation plan for Phase 3's Web UI + template-sync work (Weeks 19-24)
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — file-by-file build plan for Phase 4 (Weeks 25-32)
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — file-by-file build plan for Phase 5 (Weeks 33-40, recon & orchestration foundations)
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — file-by-file build plan for Phase 6 (Weeks 41-48, MCP server & approval gate)
- [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — file-by-file build plan for Phase 7 (Weeks 49-56, agent hardening/ecosystem/trust)
- [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) — file-by-file build plan for Phase 8 (Weeks 57-64, detection coverage — breadth & precision); its § "Execution order" is the single cross-phase backlog
- [18-implementation-plan-ph9.md](18-implementation-plan-ph9.md) — file-by-file build plan for Phase 9 (Weeks 65-70, detection coverage — depth & active: OOB blind-RCE, template-format gaps, AI-agent surface, WAF + native injection detectors)
- [90-research-hackerbot.md](90-research-hackerbot.md) — the research and backlog Phases 6-7 schedule
- [91-research-recon-phase.md](91-research-recon-phase.md) — the recon research Phase 5 schedules
- [22-authorized-targets.md](22-authorized-targets.md) — the vetted real-target registry Milestone 8's real-world validation draws from
