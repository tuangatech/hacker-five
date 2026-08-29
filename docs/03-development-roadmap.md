# Development Roadmap

> Part of the [HackerFive documentation set](../README.md).

## Phased Development Plan

### Phase 1: Foundation (Weeks 1-10) — Core Engine + IDOR + Misconfiguration

**Goal:** Deliver a working MVP that detects IDOR and misconfiguration issues with low false positives.

Split into two sub-phases so there's a real, working deliverable at the halfway point rather than one all-or-nothing 10-week push — see [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) for the file-by-file build plan behind Phase 1a.

---

### Phase 1a: Foundation Kickoff (Weeks 1-4) — Core Engine + IDOR Detector

**Goal:** A working, IDOR-only scanner — CLI, HTTP engine, and detector all functioning end-to-end against a live target — before misconfiguration and the template engine are added.

#### Week 1-2: Project Setup & Architecture
- [ ] Initialize Go project structure
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
- [ ] Set up GitHub repository and CI/CD (GitHub Actions)
- [ ] Define YAML template schema
- [ ] Create basic CLI structure (Cobra)

**Deliverable:** Project skeleton with working CLI that parses arguments

#### Week 2-3: HTTP Client & Request Engine
- [ ] Implement custom HTTP client with middleware
  - Request/response logging
  - Rate limiting (configurable QPS)
  - Proxy support (SOCKS5, HTTP)
  - Custom headers (User-Agent, API keys)
  - Retry logic with exponential backoff
- [ ] Implement worker pool for concurrent scanning
- [ ] Add request templating ({{BaseURL}}, {{RangeInt}}, variables)

**Deliverable:** HTTP engine can fire 150+ requests/sec with configurable concurrency

#### Week 3-4: IDOR Detector (Module 1)
- [ ] Implement ID enumeration strategies:
  - Sequential integers (1-100, 1-1000)
  - UUID variants (sequential, hash-based)
  - String patterns (user1, user2, alice, bob)
- [ ] Implement response comparison algorithm:
  - HTTP status code
  - Response size (byte count)
  - Content hash (MD5/SHA256 to detect duplicates)
  - Keyword presence (email, name, user_id)
- [ ] Implement **baseline mode** (primary, high-confidence): two unrelated account tokens, establish the "denied" signature from one account's sampled responses, flag IDs where that account's response deviates from denied — this is the actual authorization test, not just a content diff
- [ ] Keep single-token signature-diff as a **heuristic fallback only** (low-confidence, flagged for manual triage) when a second test account isn't available — it cannot distinguish an IDOR from an endpoint that legitimately returns different public content per ID
- [ ] Add JWT/Bearer token handling
- [ ] Create test cases against crAPI "vehicle access" endpoint

**Test Target:** crAPI `/dashboard` and `/mechanic/receive_report` (known IDOR vulns)

**Deliverable:** Standalone IDOR detector, baseline mode finds real cross-account access issues on crAPI

**Phase 1a Success Metrics (Week 4 checkpoint):**
- [ ] IDOR detector (baseline mode) finds ≥1 real cross-account issue in crAPI, using two distinct test accounts
- [ ] HTTP engine sustains 150+ req/sec against a local benchmark target
- [ ] `go build`/`go vet`/`golangci-lint` clean and CI green, verified on both macOS and Windows/WSL2 checkouts
- [ ] Full verification detail in [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)'s Definition of Done

---

### Phase 1b: Coverage Expansion (Weeks 5-10) — Misconfiguration + Template Engines (Nuclei-Compatible + Native) + Validation + Packaging

**Goal:** Extend the Phase 1a foundation with misconfiguration detection, a Nuclei-compatible template parser for static checks, the native YAML template engine for stateful checks, validate against all Phase 1 test targets, and ship the v0.1.0 release.

#### Week 5: Misconfiguration Detector (Module 2)
- [ ] Implement path-based checks
  ```go
  paths := []string{"/admin", "/.env", "/.git", "/debug", "/swagger", "/graphql"}
  keywords := []string{"admin", "api_key", "password", "secret"}
  ```
- [ ] Implement security header checks
  - CSP, X-Frame-Options, HSTS, etc.
- [ ] Implement HTTP method testing (PUT, DELETE, PATCH on read-only endpoints)
- [ ] Create 50+ built-in detection rules

**Test Targets:** OWASP Juice Shop, DVWA

**Deliverable:** Misconfiguration detector runs 200+ checks in <30 seconds per target

#### Week 6-7: Nuclei-Compatible Template Parser
- [ ] Implement a parser supporting the Nuclei template schema: `http` requests, matchers (word/regex/status/size/binary/dsl), extractors (regex/kval/json/dsl), the `part` field, `matchers-condition`, and `req-condition` request chaining
- [ ] Point at the upstream [`nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) repo (MIT-licensed) as the template source directly — no local fork or redistribution — **pinned to a specific tagged release/commit**, not `HEAD`, so an upstream compromise can't silently inject a malicious template into a scan run
- [ ] Validate against a curated subset of upstream templates — target 50+ templates from the `exposed-panels`, `misconfiguration`, and `technologies` categories relevant to Phase 1 vuln classes
- [ ] **Reject at load time** (not just "document as unsupported") any template containing `code:`, `javascript:`, `headless:`, or `file:` protocol blocks — these enable arbitrary code execution or local file access and are out of scope for a template source we don't hand-review; parser should error loudly rather than silently skip them
- [ ] Document remaining unsupported Nuclei features (e.g. network/DNS protocols) as explicitly out of scope for v0.1.0

**Deliverable:** Misconfiguration/panel checks run against real upstream Nuclei templates with matching results, with non-HTTP protocol templates rejected rather than silently ignored

#### Week 7-8: Native YAML Template Engine
- [ ] Implement YAML parser for the HackerFive-native format (gopkg.in/yaml.v3), reserved for stateful/authorization-aware checks (IDOR, later business logic) that Nuclei's format has no equivalent for
- [ ] Support matchers:
  - Status code matching
  - Word/regex matching
  - Content-length comparison
  - JSON path extraction
- [ ] Support request chaining, including baseline-mode two-account comparison (use output of request 1 in request 2)
- [ ] Create 20+ native templates for Phase 1 stateful vulns (IDOR)

**Deliverable:** Template runner executes custom native YAML templates with full matcher support

#### Week 8-9: Testing & Validation
- [ ] Set up automated tests
  - Unit tests for detector modules (80%+ coverage)
  - Integration tests against crAPI, vAPI, DVWA
  - Benchmark tests for performance (req/sec, memory usage)
  - Fuzz targets for the HTTP client and template/response parsers (seeded in Phase 1a, expanded here)
- [ ] Run against practice targets:
  - crAPI: 8+ IDOR findings
  - DVWA: 15+ misconfiguration findings
  - Juice Shop: 20+ findings (XSS, auth, etc.)
- [ ] Measure false positive rate (<5% target), covering both the Nuclei-compatible and native template paths

**Deliverable:** Passing test suite with documented results

#### Week 9-10: Packaging & Documentation
- [ ] Create Docker image (multi-stage build)
- [ ] Write README with:
  - Installation instructions (go install, docker, source)
  - Quick-start examples
  - Template writing guide, covering both the Nuclei-compatible template path and the native format
- [ ] Write installation guide for common platforms (Linux, macOS, Windows), built via `goreleaser` for cross-compiled binaries
- [ ] Create issue/PR templates for GitHub, plus `CONTRIBUTING.md` (PR process, code style, required checks before submitting)

**Deliverable:** v0.1.0 release with clean documentation

**Phase 1b Success Metrics (Week 10 / v0.1.0 release):**
- [ ] Detects 8+ IDOR issues in crAPI (100% accuracy)
- [ ] Detects 15+ misconfiguration issues in DVWA (<5% false positives)
- [ ] Scans 100 targets in <2 minutes
- [ ] Documentation complete and clear

---

### Phase 2: Expansion (Weeks 11-18) — API Auth + XSS + SQL Injection

**Goal:** Add stateful detection (authentication, session management) and improve coverage of common web vulnerabilities.

**Note on GitHub Action:** once the CLI output schema is stable (post v0.1.0), build `hackerfive/scan-action` as a thin wrapper around the existing Docker image. Treated as a parallel/stretch item, not a blocking Phase 2 deliverable. **Status: not started** — no `scan-action` repository exists yet; still open, and not a blocker for Phase 2, 3, or 4 work.

#### Week 11-12: API Auth Bypass Detector
- [ ] Implement JWT testing:
  - None algorithm attack
  - Signature bypass (key injection)
  - Weak secrets (dictionary check)
- [ ] Implement rate limiting bypass detection
- [ ] Implement token reuse detection across accounts
- [ ] Create 15+ auth-focused templates

**Test Target:** vAPI, crAPI authentication endpoints

**Deliverable:** Auth bypass detector with stateful request support

#### Week 13-14: XSS Detection
- [ ] Implement payload injection across common parameters
- [ ] Add passive XSS detection (HTML parsing, dangerous tags)
- [ ] Optional: Browser-based validation with Chromedp (for DOM XSS)
- [ ] Create 25+ XSS templates (reflected, stored, DOM)

**Note:** Focus on API-based XSS; DOM-based requires browser (out of scope for v1)

**Deliverable:** XSS detector with <10% false positives

#### Week 15-16: SQL Injection Detection
- [ ] Implement error-based SQLi detection (common error messages)
- [ ] Implement boolean-based SQLi (time-based if time allows)
- [ ] Template-based approach (use existing SQLi payloads)
- [ ] Create 20+ SQLi templates

**Note:** Not a replacement for SQLmap; focus on obvious cases

**Deliverable:** SQL injection detector integrated into template engine

#### Week 17: Information Disclosure
- [ ] Implement API response field analysis
- [ ] Detect verbose error messages
- [ ] Detect internal IPs, hostnames, stack traces
- [ ] Create 15+ info disclosure templates

**Deliverable:** Info disclosure module

#### Week 18: Testing & Release
- [ ] Full integration testing against Phase 2 targets
- [ ] Performance optimization (target: scan 1000 targets in <5 min)
- [ ] Release v0.2.0 with Phase 2 features

**Phase 2 Success Metrics:**
- [ ] Detects 10+ API auth issues
- [ ] Detects 20+ XSS issues across test targets
- [ ] Detects 10+ SQL injection issues

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

#### Week 27-28: SSRF Detector
- [ ] Implement blind SSRF detection (DNS/HTTP callbacks)
- [ ] Implement internal network detection (127.0.0.1, 10.0.0.0/8)
- [ ] Create templates for common SSRF vectors
- [ ] Integration with Interactsh or similar callback service

**Deliverable:** SSRF detector with callback-based validation

#### Week 29-30: Business Logic Flaw Templates
- [ ] Create templates for common logic flaws:
  - Price manipulation (e-commerce)
  - Race conditions (payment processing)
  - Workflow bypass (approval steps)
  - Token/coupon reuse
- [ ] Hardcode patterns for known apps
- [ ] Create extensible framework for custom logic templates

**Deliverable:** 10+ business logic templates

#### Week 31: Advanced Features
- [ ] Multi-target scanning orchestration
- [ ] Finding deduplication across targets
- [ ] Integration with HackerOne API (report submission automation)
- [ ] Markdown/HTML/HackerOne-JSON-schema `Exporter` implementations (doc 02 §5) — deferred here from Phase 1b's v0.1.0 (see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) Step 5); built together with the HackerOne API integration since it's the first point three concrete output formats are actually needed at once

**Note on HackerOne API integration:** treat this as report-drafting assistance, not unattended submission. It needs its own auth handling (API token or OAuth2, depending on endpoint), is subject to H1's per-endpoint rate limits, and requires a hand-authored mapping from `Finding` fields to H1's report schema (title, severity/CVSS, weakness/CWE) — none of which is a quick wrapper around the API. The exporters above feed that mapping directly, and should apply the same default-redact-sensitive-evidence policy `follow-up.md` calls for on HTML/Markdown output.

#### Week 32: Release
- [ ] Release **v0.4.0** with all Phase 4 features (not v1.0.0 — see [Versioning note](#versioning-note) below: v1.0.0 is gated on real-world validation, not a fixed week)
- [ ] Write blog posts on Prompt Injection detection

**Phase 4 Success Metrics:**
- [ ] Prompt injection detector working against test LLM labs
- [ ] SSRF detector working (blind SSRF via callback service)
- [ ] 10+ business logic templates delivered

---

### Phase 5: Agent Interface & Approval Backbone (Weeks 33-40) — Hacker-in-the-Loop, Part 1

**Goal:** Make HackerFive addressable by an LLM agent, safely — an MCP server, an `elicitation`-based human-approval gate, a task tree, and the hard safety blockers (program-policy pre-flight, hard-fail scope) that a human-at-a-terminal workflow could get away with only warning about. Full design in [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md), which schedules the research and backlog captured in [90-research-hackerbot.md](90-research-hackerbot.md). Comes after Phase 4, not swapped ahead of it — real dependency, not just scheduling preference: the `findings.export` MCP tool needs Phase 4's `Exporter`/HackerOne-JSON work.

#### Week 33: Foundations — ⬜ not started
- [ ] Ratify Decisions 1-4 (single coordinator, no shell/exec tool, MCP `elicitation`/`tasks`, task-tree-leaf `Confidence` distinct from `Finding.Confidence`)
- [ ] Eval harness stub against lab targets (crAPI, DVWA, vAPI, Juice Shop) — detector-only baseline, no agent yet

**Deliverable:** committed design decisions; a working baseline benchmark with zero agent involvement

#### Week 34-35: Finding Schema Freeze + Task-Tree Data Model — ⬜ not started
- [ ] Freeze/publish `docs/schema/finding.schema.json`, `Severity`/`Confidence` documented as detector-set, never agent-writable
- [ ] `Job.PlanTree`: leaf-only-mutation task tree, leaf-level `Confidence` bands (High/Medium/Low)

**Deliverable:** a versioned wire schema and a task-tree data model with a tested mutation guard

#### Week 36-37: MCP Server — ⬜ not started
- [ ] Verify an MCP Go SDK supports `elicitation`/`tasks` (new dependency, confirm via pkg.go.dev before adding)
- [ ] `pkg/mcpserver`: `scan`, `templates.list`, `templates.sync`, `findings.export` tools — no shell/exec-shaped tool anywhere in the server

**Deliverable:** a real MCP client can list and call these tools against a lab target, live-verified

#### Week 38: Approval Gate + Spend Ceiling — ⬜ not started
- [ ] `plan` MCP tool built on native `elicitation`/`tasks` — no request sent without human approval
- [ ] Per-job spend ceiling, hard-enforced (not just logged)

**Deliverable:** a plan proposal only proceeds after a real client's own approval UI grants it

#### Week 39: Hard Safety Blockers + Prioritization — ⬜ not started
- [ ] Program-policy pre-flight check — hard blocker, not a warning
- [ ] Hard-fail (not warn) on missing scope for agent-initiated runs
- [ ] Cost/attempt-aware prioritization (MAPTA's measured spend/success correlation) drives a stop-and-escalate signal per task-tree leaf

**Deliverable:** an agent-driven run against a disallowed or unscoped target refuses outright

#### Week 40: Session Log + Release — ⬜ not started
- [ ] Structured, persisted agent session log (queryable, not yet the live Web UI view)
- [ ] Full plan → approve → scan → export round trip live-verified against a lab target
- [ ] Release **v0.5.0**

**Phase 5 Success Metrics:**
- [ ] MCP server live-verified against a real client with no shell/exec-shaped tool present
- [ ] Human approval via `elicitation` confirmed to gate every plan before traffic goes out
- [ ] Program-policy pre-flight and missing-scope hard blockers both confirmed live

---

### Phase 6: Agent Hardening, Ecosystem & Trust (Weeks 41-48) — Hacker-in-the-Loop, Part 2

**Goal:** Round the Phase 5 backbone out to doc90's full "Hacker-in-the-Loop Ready" Definition of Done — full `AllowWrites` attestation, a live Web UI Agent tab, the OWASP Agentic Top 10 mapping against real shipped code, template-ecosystem staging, and a real agent-driven benchmark run. Full design in [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md). Depends on Phase 5, not the reverse.

#### Week 41: Tool Surface Completion — ⬜ not started
- [ ] `hackerfive templates list --json`
- [ ] MCP tool-list scoping by session agency level (read-only vs. full)

#### Week 42: Approval & Compliance Rounding — ⬜ not started
- [ ] `AllowWrites` only honored with an attested elicitation grant tied to an approved plan
- [ ] HackerOne submission documented as a permanent human-in-the-loop invariant
- [ ] Scope-creep gate: fresh approval required when recon surfaces out-of-scope hosts/paths

#### Week 43-44: Observability Upgrade — ⬜ not started
- [ ] Web UI "Agent" tab streams every MCP tool call and its reasoning live, over SSE
- [ ] Audit trail extended with agent-specific facts (session, approved plan, grant references)
- [ ] Evidence-linked claims: a report draft citing a nonexistent `Finding.ID` is rejected

#### Week 45: Live Log Injection + Concurrency Ceilings — ⬜ not started
- [ ] Live log injection on the Agent tab (stretch)
- [ ] Aggregate per-target concurrency ceiling across concurrent `scan` calls in one session

#### Week 46: OWASP Agentic Top 10 Mapping — ⬜ not started
- [ ] All ten ASI01-10 risks checked against real shipped code (file/line cited), each mitigated or accepted as residual risk with a stated reason

#### Week 47: Template Ecosystem & Triage Support — ⬜ not started
- [ ] Generated `templates/index.json`
- [ ] `templates/proposed/` staging directory, confirmed never auto-loaded
- [ ] Triage-assist mode on `Exporter` output (annotation only, never mutates `Finding`)
- [ ] Structured feedback capture on human override/dismissal of agent triage notes

#### Week 48: Eval Maturity + Release — ⬜ not started
- [ ] Real agent-driven benchmark run against all four lab targets, fp/fn rate tracked separately from detector-level rate, full cost accounting recorded honestly
- [ ] Release **v0.6.0**

**Phase 6 Success Metrics:**
- [ ] `AllowWrites` attestation and scope-creep gate both live-verified
- [ ] Agent tab live-verified streaming real tool calls/reasoning in a browser
- [ ] OWASP Agentic Top 10 mapping recorded against real code, not restated intentions
- [ ] Agent-driven fp/fn rate measured and reported honestly, with its delta from Phase 5's detector-only baseline

---

## Versioning note

`v0.1.0` → `v0.2.0` → `v0.3.0` → `v0.4.0` → `v0.5.0` → `v0.6.0` track feature phases (1 through 6) in order. **`v1.0.0` is deliberately not tied to a phase or a week** — it marks real-world trust, not feature completeness, and is gated on actually using the tool against real, authorized targets and finding real issues with it, not on shipping a checklist of detectors. See [Milestone 7](#milestone-7-v100--real-world-validation-no-fixed-week) below. This mirrors doc05's "Tool Maturity" prerequisites (which already gate HackerOne program eligibility on validated false-positive rate and documentation, not a version number) and is consistent with how mature scanners in this space (e.g. Nuclei) treat 1.0 as a stability/trust signal rather than a feature-count milestone.

## Timeline & Milestones

### High-Level Timeline

Kept as a table rather than a hand-drawn Gantt chart — a table only needs one cell changed when a phase's weeks shift, instead of recounting characters across an ASCII diagram (a repeated source of drift in earlier revisions of this doc).

| Phase | Weeks | Duration | Focus | Ships as |
|---|---|---|---|---|
| 1a | 1-4 | 4 wks | Core engine + IDOR MVP | (internal checkpoint) |
| 1b | 5-10 | 6 wks | Misconfiguration + template engines (Nuclei-compatible + native) + validation + packaging | v0.1.0 |
| 2 | 11-18 | 8 wks | Auth bypass, XSS, SQLi, information disclosure | v0.2.0 |
| 3 | 19-24 | 6 wks | Web UI + upgradeable template sync | v0.3.0 |
| 4 | 25-32 | 8 wks | Prompt injection, SSRF, business logic | v0.4.0 |
| 5 | 33-40 | 8 wks | Agent interface & approval backbone (MCP server, elicitation-based approval, task tree, hard safety blockers) | v0.5.0 |
| 6 | 41-48 | 8 wks | Agent hardening, ecosystem & trust (AllowWrites attestation, live Agent tab, OWASP Agentic Top 10 mapping, eval maturity) | v0.6.0 |
| — | not scheduled | usage-gated | Real-world validation (see [Versioning note](#versioning-note)) | v1.0.0 |

**Parallel tracks** (start weeks are approximate targets, not hard dependencies):

| Track | Starts | Notes |
|---|---|---|
| HackerOne profile/program setup | ~Week 15 | Runs alongside late Phase 2 |
| Active bug bounty hunting | ~Week 19 | Ongoing once v0.2.0 ships |
| GitHub Action (`scan-action`) | ~Week 11 | Post-v0.1.0, once the CLI output schema is stable. **Not started as of this doc's last update** — no blocker on Phases 2-4, pick up whenever there's spare time |

### Milestone Checklist

Trimmed to things the project actually controls (built/shipped/verified). Removed external-validation numbers this team can't directly move (star counts, contributor counts, "featured in" mentions, press coverage) — those are outcomes to hope for, not deliverables to plan around.

#### **Internal Checkpoint: Phase 1a (Week 4)**
- [ ] IDOR-only scanner working end-to-end (see Phase 1a Success Metrics above)
- [ ] Not a public release — this is the internal go/no-go before starting Phase 1b

#### **Milestone 1: MVP Release (Week 10) — v0.1.0**
- [ ] v0.1.0 released on GitHub
- [ ] IDOR detector working (crAPI: 8+ findings)
- [ ] Misconfiguration detector working (DVWA: 15+ findings)
- [ ] Documentation complete

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
- [ ] v0.4.0 released
- [ ] Prompt injection detector added
- [ ] SSRF detector added
- [ ] Business logic templates added

#### **Milestone 5: Agent Interface & Approval Backbone (Week 40) — v0.5.0**
- [ ] v0.5.0 released
- [ ] MCP server (`scan`/`templates.list`/`templates.sync`/`findings.export`) live-verified against a real MCP client, no shell/exec-shaped tool present
- [ ] `plan`/`elicitation`-based human approval gate confirmed to block traffic until a human approves
- [ ] Program-policy pre-flight and missing-scope hard blockers both live-verified

#### **Milestone 6: Agent Hardening, Ecosystem & Trust (Week 48) — v0.6.0**
- [ ] v0.6.0 released
- [ ] `AllowWrites` attestation and scope-creep gate both live-verified
- [ ] Web UI Agent tab live-verified streaming real tool calls/reasoning
- [ ] OWASP Agentic Top 10 mapping recorded against real shipped code
- [ ] Agent-driven false-positive/false-negative rate measured against lab targets, tracked separately from detector-level rate

#### **Milestone 7: v1.0.0 — Real-World Validation (no fixed week)**
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
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — file-by-file build plan for Phase 5 (Weeks 33-40)
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — file-by-file build plan for Phase 6 (Weeks 41-48)
- [90-research-hackerbot.md](90-research-hackerbot.md) — the research and backlog Phases 5-6 schedule
- [22-authorized-targets.md](22-authorized-targets.md) — the vetted real-target registry Milestone 7's real-world validation draws from
