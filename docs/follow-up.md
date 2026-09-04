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
