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
- [ ] GitHub repo with 50+ stars
- [ ] Documentation complete and clear

---

### Phase 2: Expansion (Weeks 11-18) — API Auth + XSS + SQL Injection

**Goal:** Add stateful detection (authentication, session management) and improve coverage of common web vulnerabilities.

**Note on GitHub Action:** once the CLI output schema is stable (post v0.1.0), build `hackerfive/scan-action` as a thin wrapper around the existing Docker image. Treated as a parallel/stretch item, not a blocking Phase 2 deliverable.

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
- [ ] GitHub repo with 200+ stars
- [ ] Published in awesome-security lists

---

### Phase 3: Specialization (Weeks 19-26) — Prompt Injection + SSRF + Logic Flaws

**Goal:** Differentiate by targeting emerging and high-value vulnerabilities with minimal automation elsewhere.

#### Week 19-20: Prompt Injection Detector
- [ ] Implement prompt breaking detection (instruction override)
- [ ] Detect data exfiltration attempts (LLM-based)
- [ ] Create templates for common LLM apps (ChatGPT API, Anthropic, Hugging Face)
- [ ] Test against AI vulnerable labs

**Deliverable:** Prompt injection detector with specialized templates

#### Week 21-22: SSRF Detector
- [ ] Implement blind SSRF detection (DNS/HTTP callbacks)
- [ ] Implement internal network detection (127.0.0.1, 10.0.0.0/8)
- [ ] Create templates for common SSRF vectors
- [ ] Integration with Interactsh or similar callback service

**Deliverable:** SSRF detector with callback-based validation

#### Week 23-24: Business Logic Flaw Templates
- [ ] Create templates for common logic flaws:
  - Price manipulation (e-commerce)
  - Race conditions (payment processing)
  - Workflow bypass (approval steps)
  - Token/coupon reuse
- [ ] Hardcode patterns for known apps
- [ ] Create extensible framework for custom logic templates

**Deliverable:** 10+ business logic templates

#### Week 25: Advanced Features
- [ ] Multi-target scanning orchestration
- [ ] Finding deduplication across targets
- [ ] Integration with HackerOne API (report submission automation)
- [ ] Dashboard/web UI (optional, nice-to-have)

**Note on HackerOne API integration:** treat this as report-drafting assistance, not unattended submission. It needs its own auth handling (API token or OAuth2, depending on endpoint), is subject to H1's per-endpoint rate limits, and requires a hand-authored mapping from `Finding` fields to H1's report schema (title, severity/CVSS, weakness/CWE) — none of which is a quick wrapper around the API.

#### Week 26: Release & Community Building
- [ ] Release v1.0.0 with all Phase 3 features
- [ ] Write blog posts on Prompt Injection detection
- [ ] Launch community template repository
- [ ] Evaluate template signing now that third-party submissions are actually accepted (see "Future Considerations" in [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — premature before this point)
- [ ] Organize first community contribution

**Phase 3 Success Metrics:**
- [ ] 500+ GitHub stars
- [ ] 50+ community-contributed templates
- [ ] First bug bounties reported using the tool
- [ ] Featured in HackerOne tool ecosystem (if applicable)
- [ ] 100+ active users

---

## Timeline & Milestones

### High-Level Timeline

Kept as a table rather than a hand-drawn Gantt chart — a table only needs one cell changed when a phase's weeks shift, instead of recounting characters across an ASCII diagram (a repeated source of drift in earlier revisions of this doc).

| Phase | Weeks | Duration | Focus |
|---|---|---|---|
| 1a | 1-4 | 4 wks | Core engine + IDOR MVP |
| 1b | 5-10 | 6 wks | Misconfiguration + template engines (Nuclei-compatible + native) + validation + packaging |
| 2 | 11-18 | 8 wks | Auth bypass, XSS, SQLi, information disclosure |
| 3 | 19-26 | 8 wks | Prompt injection, SSRF, business logic |

**Parallel tracks** (start weeks are approximate targets, not hard dependencies):

| Track | Starts | Notes |
|---|---|---|
| HackerOne profile/program setup | ~Week 15 | Runs alongside late Phase 2 |
| Active bug bounty hunting | ~Week 19 | Ongoing once v0.2.0 ships |
| GitHub Action (`scan-action`) | ~Week 11 | Post-v0.1.0, once the CLI output schema is stable |

### Milestone Checklist

#### **Internal Checkpoint: Phase 1a (Week 4)**
- [ ] IDOR-only scanner working end-to-end (see Phase 1a Success Metrics above)
- [ ] Not a public release — this is the internal go/no-go before starting Phase 1b

#### **Milestone 1: MVP Release (Week 10)**
- [ ] v0.1.0 released on GitHub
- [ ] IDOR detector working (crAPI: 8+ findings)
- [ ] Misconfiguration detector working (DVWA: 15+ findings)
- [ ] Documentation complete
- [ ] 50+ GitHub stars

#### **Milestone 2: Expanded Coverage (Week 18)**
- [ ] v0.2.0 released
- [ ] API auth detector added
- [ ] XSS detector added
- [ ] SQLi detector added
- [ ] 100+ templates in repository
- [ ] 200+ GitHub stars
- [ ] HackerOne profile set up, first programs joined

#### **Milestone 3: Specialization (Week 26)**
- [ ] v1.0.0 released (stable API)
- [ ] Prompt injection detector added
- [ ] SSRF detector added
- [ ] Business logic templates added
- [ ] 500+ GitHub stars
- [ ] First bounties earned ($500+)
- [ ] Featured in security tool lists

#### **Milestone 4: Community (Month 6+)**
- [ ] 50+ community contributors
- [ ] 1000+ GitHub stars
- [ ] $1000+ monthly bounties
- [ ] Published CVEs using the tool
- [ ] Speaking engagement or blog post
- [ ] Sustainable contributor base

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — vulnerability classes referenced above
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — modules being built each phase
- [04-environment-and-testing.md](04-environment-and-testing.md) — how each week's deliverables get validated
- [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) — file-by-file build plan and verification steps for Phase 1a (Weeks 1-4)
