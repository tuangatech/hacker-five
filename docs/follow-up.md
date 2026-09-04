# Follow-Up: Enhancement Backlog

> Part of the [HackerFive documentation set](../README.md).

Open enhancement items and unresolved review findings, organized by category rather than by when they were raised. Direction: HackerFive is expanding beyond HackerOne-program scanning, so categories here stay useful for detection/reporting work generally. Narrative-style research and decision write-ups (architecture discussions, live-testing investigations) live in [discussions.md](discussions.md) instead of here — this doc is the open-items backlog.

## Security & Scope Hardening

Resolved, kept for traceability:
- ✅ Scope allow-list (`--scope`), evidence redaction by default, IDOR normalization, JWT weak-secret offline check, rate-limiting-signal probe (not real brute force), Business Logic Flaw detector (coupon/race checks, `--allow-writes`-gated) — see [10](10-implementation-plan-ph1b.md)/[11](11-implementation-plan-ph2.md)/[13](13-implementation-plan-ph4.md).
- ✅ OOB public-server leak risk — the mechanism was always user-controlled; the *default* changed 2026-09-02 (2 public servers, `--no-oob` opt-out) — see [discussions.md](discussions.md).

Open:
- **`--rate-limit` default (50 req/sec) is too aggressive as a default** — recommended conservative default is 5-10 req/sec. Set in Phase 1a, not revisited since.
- **No `--include-raw-evidence` opt-out** — evidence redaction is always-on, not togglable. Minor, not yet needed.
- **Baseline-mode account provisioning** has no general guidance for a real bounty/VDP target — only lab-target-specific steps exist ([20-setup-testing-targets.md](20-setup-testing-targets.md)).
- **Self-hosted `interactsh-server` still not stood up.** The public-server default (retry-hardened, `pkg/oob`) covers scanning your own sites; a private server is still the right choice for a real third-party engagement — the server operator sees the target's IP/timing either way.

## Detection Coverage — Protocol/Capability Expansion

Assessed against [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)'s `code:`/`javascript:`/`headless:`/`file:` template-rejection boundary and the read/enumerate-only rule.

| Capability | Verdict | Why |
|---|---|---|
| TCP | Add | Already a Nuclei protocol type, deferred (not rejected) from the HTTP-only parser. Banner grab / port ID, read-only. |
| TLS/SSL | Add | Passive checks (expired/weak certs, deprecated protocols, weak ciphers) via stdlib `crypto/tls`, no new dependency. |
| JS static analysis | Add | Crawl served JS for hardcoded secrets/endpoints (LinkFinder/SecretFinder-style) — read-only, feeds IDOR/misconfig. |
| Headless/DOM (Chromedp) | Keep scoped | Already planned for DOM XSS validation, sandboxed, first-party-only — doesn't relax the `headless:` template rejection for community templates. |
| OOB blind RCE verification | Add | Extend the SSRF Interactsh/OOB pattern to RCE: prove execution via callback, never run attacker-meaningful commands. |
| Literal command execution on target | Reject | Crosses into exploit; conflicts with read/enumerate-only and most program authorization. OOB verification gets the same detection value without it. |

TCP/TLS/JS-static are natural next additions — same architecture, no new dependency, no policy conflict. The command-execution boundary is worth stating explicitly in doc02 alongside the existing template rejections.

## Template Engine & Detection Backlog

| Item | Why deferred |
|---|---|
| File-based (wordlist) `payloads:` | 240 templates use it, but 237 are one WordPress-version-detection category that also needs `compare_versions()`/`concat()` DSL + extractor-to-sibling-matcher correlation — payloads alone wouldn't unlock the value. |
| Multi-key `payloads:` (sniper/pitchfork/clusterbomb) | 2 templates only — not worth the added complexity. |
| Remaining DSL/`part:` gaps (`server`/`set_cookie`/`title`/`os_info`/`location`, `+` concat, `date_time()`/`hex_to_dec()`/`substr()`, `xpath` matcher) | 1-10 templates each; some format conventions are genuinely ambiguous from the sampled templates, not just low priority. |
| Template signing | Premature while templates are project-authored/pinned-upstream, not community-submitted. Trigger: the community template repo actually accepting outside submissions. |
| DOM-based XSS via Chromedp | Passive/reflected template-driven XSS already covers the bulk of realistically findable XSS at lower cost; Chromedp adds a dependency plus a sandboxing requirement. Revisit once current coverage's real yield is measured live. |

## Recon Enhancements

- **Playwright/Caido-style richer recon signal** — Strix uses Playwright (JS-rendered DOM crawling) and Caido (traffic analysis) to feed its agent. Used purely as passive recon-wave input, this fits `pkg/recon`'s existing fixed-library wave shape (same as subfinder/naabu/httpx/katana) and doesn't touch doc90's Decision 2 boundary. Not sized — needs a real evaluation of what it adds over katana's `-jc` flag first.

## Decision Engine & Recon→Plan Signal Use

Surfaced by a 2026-09-04 live review against `andertone.com` (a real WordPress/WooCommerce/LiteSpeed target). Recon was strong (5 hosts, 31 tech facts, 196 endpoints, `staging.andertone.com` with ports 21/3306 open, 7 WordPress plugin slugs + versions in crawl URLs, 0 warnings); `registry.Resolve` then produced 134 leaves that were mostly noise or duplicates, and `idor`/`authbypass`/`ssrf`/`businesslogic` never activated despite textbook surface. Root cause: the decision engine reasons **only** over `ReconResult.TechStack`, never `Endpoints` or `Hosts[].Ports`, and `matchTemplateTags` selects by first-5-in-file-order after a too-broad any-word tag match.

### P0 — precision & correctness (in progress; tracked as [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Step 2 addenda)

Batch 1 (**P0-3, P0-5, P0-4**) landed 2026-09-04 — see [15](15-implementation-plan-ph6.md) Step 2's "Batch 1" addendum. Batch 2 (**P0-2**, incl. **P0-1a**) landed 2026-09-04 — see the "Batch 2" addendum. **P0-1b** (true semver gating) remains open, folded into P1-4.

- **P0-1a Version-aware CVE ranking.** ✅ done 2026-09-04 (Batch 2). `matchTemplateTags` parses the `:version` suffix off `fact.Name` and scores CVE-tagged templates by CVE recency + severity; a pre-2016 CVE against a known current-looking version gets a −20 rank penalty (deprioritized, not dropped). **P0-1b** — true affected-version (semver) gating — still needs an index schema carrying version ranges; deferred to **P1-4**. `pkg/registry/decisionengine.go`.
- **P0-2 Ranked template-tag selection + canonical tech→tag map.** ✅ done 2026-09-04 (Batch 2). `matchTemplateTags` rewritten: relevance score (primary-product tag 100 > other tag hit 50 > no product tag = dropped) + severity + CVE-recency, sorted, cap 5→8. `canonicalTechTags` (6 entries, exclude values verified against the real corpus) pins `nginx`/`jquery`/`mysql`/`wordpress`/`woocommerce`/`litespeed`; `genericTechWords` stops `block`/`editor`/`cloud`/`google`/… matching alone. Real-index measurement: 107 template leaves → 74, all observed false friends gone (`nginx-proxy-manager-default-login`, `exposed-jquery-file-upload`, `esafenet-mysql-fileread`, …). `pkg/registry/decisionengine.go`.
- **P0-3 `Finding.Target` double-slash.** ✅ done 2026-09-04. `pkg/detectors/misconfig/detector.go`'s five `target + path` finding fields now use `req.URL.String()`; `pkg/template/nuclei/executor.go`'s `Executor.Run` trims a trailing slash from `target` once, covering both path: and raw:. Same bug class as [15](15-implementation-plan-ph6.md) Step 2 addendum #5's authbypass fix, which missed these call sites.
- **P0-4 Dedup PlanTree leaves by `(target, detector)`.** ✅ done 2026-09-04. `Resolve` keys every leaf via `leafDedupKey` (pending: `(target, detector)`; unresolved: `(target, NormalizeTechName(fact.Name))`), keeps first in recon order, and skips a now-empty host node. Real `andertone.com` stack: 31 leaves → 8 (with P0-5, template index omitted). Confidence-merge across duplicates left as P1 polish.
- **P0-5 Non-actionable-tech denylist.** ✅ done 2026-09-04. `nonActionableTech` in `pkg/registry/decisionengine.go` (`http/2`, `http/3`, `hsts`, `wordpress block editor`, `hostinger`, `hostinger cdn`, `google cloud`, `google cloud cdn`), checked at the top of `resolveTechFact` — a denylisted fact yields no leaf, not even `unresolved`. Removed 12 of 31 fact instances on the real target.

### P1 — coverage (turn recon signal into leaves)

Batches landed 2026-09-04 — see [15](15-implementation-plan-ph6.md) Step 2's P1 addendum for detail. P1-2 and P1-4 remain open.

- **P1-1 Endpoint-driven resolution pass.** ✅ done 2026-09-04. `resolveEndpointFacts` alongside `resolveTechFact` (`pkg/registry/decisionengine.go`): reuses the exact `recon.Suggest*FromRecon` functions that already fill `scanner.Config.EndpointTemplate`/`ProtectedPaths`/`SSRFParams` elsewhere in the plan pipeline — Resolve simply never emitted a leaf to use them, so idor/authbypass/ssrf could go fully unresolved on a target with real surface but no TechFact matching `techRules`' small table. `xmlrpc.php`/`wp-json/wp/v2/users` → specific template IDs via a new `endpointSignals` map; a cart/checkout/coupon-shaped path → `businesslogic` leaf (gated at execution time on `--allow-writes`+auth-token, real path auto-derivation deliberately out of scope — see doc15). `Resolve`'s host set now unions `TechStack` and `Endpoints` hosts, not TechStack alone. Real data: idor/ssrf/businesslogic went from structurally-unreachable (0) to active on andertone.com.
- **P1-2 Port-driven resolution pass.** Open — scoped, not started. Decision (2026-09-04): ship the cheap interim first — a visible `unresolved` leaf naming the open port (naabu's 21/23/3306/5432/6379/9200/27017 set) with an honest "no automated check yet" rationale, no new detector required. The real network-service-exposure detector (anonymous-FTP, unauth-DB, open-Elasticsearch — a new `KindDetector` capability, currently zero exist for TCP) stays a separate, larger follow-up; `registry.Capabilities`/`Resolve` need `result.Hosts[].Ports` wired in either way.
- **P1-3 WordPress plugin/theme enumeration in recon.** ✅ done 2026-09-04, narrower than originally scoped. `pkg/recon/wpplugins.go`'s `wordPressPluginFacts` parses `/wp-content/plugins|themes/<slug>/` + `?ver=` from already-crawled `ReconResult.Endpoints` (Wave 3, no new network round trip) into `TechFact{Name:"<slug>[:<ver>]"}` — flat single-colon shape, not `"wp-plugin:<slug>:<ver>"`. Paired with a `matchTemplateTags` fix (`fullSlug` tier) that makes a hyphenated slug actually hit its real corpus tag (`contact-form-7`, `litespeed-cache`, etc. — word-decomposition alone never could). **readme.txt/style.css version *probes* are still open** — a new active fetch, not a parse of already-collected data, deliberately deferred rather than bundled into this pass. Real data: 9 real plugin/theme slugs extracted from a saved crawl, 79→87 leaves once folded in.
- **P1-4 nuclei loader `body_N` / `content_type_N` / `duration` DSL gaps.** Open, deliberately not folded into the 2026-09-04 P1 batches — template-engine work in a different package (`pkg/template/nuclei`) with its own real design questions, not decision-engine/registry wiring. ~1,966 of 9,652 templates (20%) permanently rejected at load; a large slice are WordPress-plugin SQLi/XSS (`advanced-booking-calendar-sqli`, `3d-print-lite-xss` observed dropped) — directly costing coverage on this exact target class, now more visible given P1-3's plugin enumeration. Partially overlaps the "Template Engine & Detection Backlog" table above; the multi-request matcher-ref (`_2`/`_3`) support is the high-value piece. Also the natural place to add an index field carrying affected-version constraints for P0-1b.
- **P1-5 `techRules` coverage.** Partially done 2026-09-04: `woocommerce` → `misconfig` added. `contact-form-7` and other plugin-specific coverage come from P1-3's slug-tag matching instead (no techRules row needed — these are plugin CVEs, not a generic capability). Cloud-provider exposure tags (→ `aws`/`s3`/`gcp`) remain open, blocked the same way as P1-2: `pkg/fingerprint` doesn't yet produce a fact more specific than the already-denylisted "Google Cloud", so there's nothing for a techRule to key on yet.

### P2 — LLM leverage & ergonomics
- **P2-1 `PlanFromRecon(ReconResult)` — a 4th `pkg/llmfallback` caller** that reasons over the whole (redacted) recon result and returns ranked `{target, detector|template-tag, rationale}` proposals, merged into (not replacing) the deterministic tree, same elicitation gate. Today I4 only ever sees one `unresolved` leaf's rationale string.
- **P2-2 Feed `ResolveLeaf` structured data.** It currently regex-scrapes the tech name out of `leaf.Rationale` (`techFactNamePattern`); pass the `TechFact` struct + correlated endpoints + ports instead.
- **P2-3 Make `use_existing_tag` executable** (doc15 Open Issue #2) — run every template carrying the chosen tag, or a second narrower call to pick an ID.
- **P2-4 Wire I4 into CLI `plan`/`scan`** behind an explicit `--llm-assist` flag; today only the MCP `plan` tool and `/plan-preview/resolve` invoke it. Let `llmfallback.New()` degrade instead of hard-failing when no tier is configured.
- **P2-5 Index/corpus drift guard.** `plan`/`scan` should warn when `templates/index.json` references far more templates than are on disk (this review started with a 7,716-entry index and an empty synced dir).
- **P2-6 Enforce `--scope` (hard-fail) for CLI `plan`/`recon`**, as doc15 Step 3's D2/D3 already plan for the MCP surface; the CLI still only warns.

## Reporting & Integrations

- **`report_intents` create still unconfirmed live.** `ListWeaknesses`/`ListStructuredScopes` are live-verified (2026-08-30/09-01, real programs); the create-report request-body schema is still unexercised against the real API — a deliberately incomplete trial call's `422` error body is the fastest way to confirm it.
- **GitHub Action (`scan-action`)** — thin CI wrapper for continuous self-scanning, a different audience (CI users) than opportunistic bounty/VDP hunting. Not started; parallel track, not blocking any phase.

## Testing & Verification Gaps

- **Auth-bypass integration tests** (`authbypass_crapi_test.go`/`authbypass_vapi_test.go`) — live-verified ad hoc against real targets, not yet checked in as reproducible Go tests.
- **`--scope` live verification** against a real authorized target — unit- and engine-level tests exist, no real end-to-end run yet.
- **Upstream `waf-detect.yaml` template is overbroad** — its regex matches any `Server: Apache` header regardless of actual WAF presence; 1 confirmed FP against DVWA. Template-curation call, not urgent at the current 1.4% overall FP rate.
- **✅ done 2026-09-03 — CI coverage gate 79.0% → 77.0% → 80.0%.** Real repo-wide coverage had quietly drifted to ~77.1-77.6% across several Phase 6 commits (thin unit coverage landed alongside `pkg/mcpserver`, `cmd/hackerfive` CLI wiring, `pkg/llmfallback`), uncaught because `go test -race` was failing first on unrelated network-flakiness bugs (steps don't run after an earlier one fails); the gate was temporarily lowered to 77.0% once that masking was fixed and the real drift surfaced. Closed back up the same day with real new unit tests — `cmd/hackerfive/{root,recon,plan}_test.go` (new), `pkg/recon/whois_test.go` (new), `pkg/mcpserver/planstate_test.go` (new), plus extensions to `pkg/mcpserver/{tools_plan,tools_scan,tools_recon}_test.go` — landing at a real 83.5%; gate raised to 80.0% (margin below the real number, not pinned to it). One real hazard found and fixed along the way: this dev machine has the real `subfinder`/`tlsx` binaries and a synced template corpus installed at its real `os.UserConfigDir()`, so a naively-written "happy path against a local httptest target" test silently shelled out to them / loaded the full corpus for real — same bug class as the WHOIS/ASN loopback fix (doc15 addendum item 7), just two more places it can hide. Fixed via `t.Setenv("PATH", ""); t.Setenv("HOME", t.TempDir()); t.Setenv("XDG_CONFIG_HOME", "")` (`isolateFromInstalledReconBinaries` in both `cmd/hackerfive` and `pkg/mcpserver` test helpers). Remaining lower-coverage files (not urgent — total is comfortably above the gate): `pkg/mcpserver/tools_plan.go` (44.4%, `handlePlan`/`handlePlanApproval`'s deep bodies still need a real elicitation-capable client per doc15 Step 2's own call, not a unit test), `cmd/hackerfive/{scan,templates,report}.go` (45-69%), `pkg/llmfallback/resolve.go` (46.8%).

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — protocol scope and template-security boundaries referenced above
- [03-development-roadmap.md](03-development-roadmap.md) / [09](09-implementation-plan-ph1a.md) / [10](10-implementation-plan-ph1b.md) / [11](11-implementation-plan-ph2.md) / [13](13-implementation-plan-ph4.md) — implementation detail behind the items above
- [discussions.md](discussions.md) — narrative decision/research write-ups (OOB defaults, Go-vs-Python architecture, XBOW research)
