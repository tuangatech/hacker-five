# Follow-Up: Security Review, Expansion Strategy & Protocol Scope

> Part of the [HackerFive documentation set](../README.md).

Working notes from an August 2026 planning session: a senior-security-engineer review of the Phase 1 plan, the decision to expand distribution (open-source) and target scope (VDP/bounty programs beyond HackerOne), background research on XBOW as a comparable, and an assessment of extending detection beyond HTTP.

## 1. Senior Security Engineer Review of Phase 1 Plan

Findings against [01-overview-and-strategy.md](01-overview-and-strategy.md), [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md), and [03-development-roadmap.md](03-development-roadmap.md).

### Critical — legal & scope risk
- ✅ **Done (2026-08-28), partially — the rate-limiting-bypass half.** "Contradiction between 'read/enumerate only' and two planned detectors": the literal "Rate Limiting Bypass" (rapid credential brute force, Week 11-12) is **not built as described** — replaced with a bounded, non-destructive rate-limit-*signal* probe (fixed 10 requests, one known-invalid credential, never a real guessing sequence). See [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) Step 1. **"Business Logic Flaws" (Week 23-24) is still open** — Phase 3, not yet reached, so that half of this finding stays unresolved until then.
- ✅ **Done (2026-08-28), with a stated deviation.** "No technical scope-enforcement mechanism": a `--scope` allow-list (domain/`*.domain`/CIDR, `#` comments) is implemented and enforced when given. **Deviation from this recommendation, stated explicitly, not silently**: it's **optional**, not mandatory/on-by-default — every existing documented lab-target command would otherwise break. Omitting it prints a stderr warning instead of blocking the scan. See [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) Step 0 for the full tradeoff reasoning.
- **Public OOB callback services leak target info to a third party.** Still open — Interactsh/self-hosted OOB is Phase 3 (Week 21-22), not yet reached.

### High — architecture & tool security
- **Default rate limit too aggressive as a *default*.** Still open — `--rate-limit` defaults to 50 req/sec (set in Phase 1a), not the recommended conservative 5-10; not revisited since.
- ✅ **Done (Phase 1b, 2026-08-27).** "No evidence trail captured for reports": `Finding.Evidence` now carries formatted raw request/response pairs via `detectors.FormatRequest`/`FormatResponse` (`pkg/detectors/evidence.go`). See doc10's Future Enhancement #7.
- ✅ **Done (Phase 1b, 2026-08-27), same change as above.** "Sensitive data in exported reports — redact by default": `pkg/detectors/evidence.go`'s `redactedHeaders` map (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `X-Api-Key`) redacts by default in every `Finding.Evidence` this project produces — confirmed live throughout this session's own scan output (e.g. `"Cookie: [REDACTED]"`). No separate `--include-raw-evidence` opt-out flag exists (redaction isn't currently toggleable) — a smaller, deliberate gap from the literal recommendation, not yet flagged as its own backlog item.

### Medium — detection methodology
- ✅ **Done (Phase 1a).** "IDOR response comparison needs normalization, not just hashing": `idor.Signature.DiffersFrom` (`pkg/detectors/idor/compare.go`) uses status+hash-or-size-tolerance-and-keyword-set comparison, not a raw byte hash — tolerant of exactly the volatile-field noise (timestamps, nonces) this item flagged. (Note: this same tolerance was later found *too* coarse for a different, higher-precision use case — `authbypass`'s token-reuse check deliberately uses exact byte comparison instead, see doc11 Step 1's dated note — the two checks have opposite precision/recall needs, both handled correctly for their own purpose.)
- ✅ **Done (2026-08-28).** "JWT weak-secret dictionary check is offline, not live guessing": stated explicitly in code (`pkg/detectors/authbypass/detector.go`'s `checkJWTWeakSecret` doc comment) and locked in by a unit test that asserts zero extra network requests, not just a design note. See [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) Step 1.
- **Baseline-mode account provisioning isn't addressed.** Still open as a general policy statement, though in practice [20-setup-testing-targets.md](20-setup-testing-targets.md) documents exactly this process per lab target (crAPI's `crapi_setup.sh`, vAPI's manual signup) — no equivalent guidance yet for a real bounty/VDP target.

### Low — process
- Weeks 6-9 (Nuclei-compatible parser + native engine + full validation) is tight for a small team; budget slack before Week 10 packaging.
- Keep the calls already made in the docs: RE2-only regex (ReDoS-safe), pinned upstream `nuclei-templates` commit (supply chain), rejecting `code:`/`javascript:`/`headless:`/`file:` template blocks at load time (RCE/LFI), fuzzing the HTTP client/parsers, env-var-only credentials, HackerOne integration as report-drafting not auto-submit.

## 2. Expansion Direction: Open-Source + VDP/Bounty-Policy Scope

Decision: pursue **open-sourcing the engine** (Nuclei's model) and **broaden target scope from HackerOne-paid programs to any organization with a published Vulnerability Disclosure Policy (VDP) or bounty policy** — not unauthorized scanning of arbitrary websites.

### Why open-source
- Nuclei's playbook is proven: MIT license, community templates, fast CVE-to-template turnaround. 28,000+ stars, 12,000+ community templates.
- Community contributions scale detection coverage faster than a solo/small team can alone.
- Precedent for monetizing without closing the core: ProjectDiscovery layers a paid cloud platform on top of free Nuclei; XBOW went fully closed/service instead (§3). Either is viable later — open-sourcing the engine doesn't foreclose it.
- Reputation compounds toward the roadmap's own milestones (stars, awesome-lists, conference talks — Milestones 3/4 in doc 03).

### Costs to plan for
- Maintainer burden: triaging community template submissions for false positives and for security bugs in the engine itself (Nuclei has had to patch its own scanner vulnerabilities).
- A distributed scanner will be pointed at unauthorized targets by *someone*, regardless of your own conduct. Mitigate with conservative defaults (rate limits, no auto-brute-force) and explicit acceptable-use language in the README, so the tool is safe by default even used carelessly.
- The `code:`/`javascript:`/`headless:`/`file:` template rejection (already decided) becomes a hard security boundary once templates are community-authored, not just a nice-to-have.

### Why VDP/bounty-policy scope (not open scanning)
- Authorization, not intent, determines legality under the CFAA (US) and equivalent laws elsewhere. "No damage, told the owner" does not make unauthorized access legal — it's a mitigating factor at best, not a defense.
- VDPs (no payout, but a published safe-harbor policy) are far more common than paid bounty programs and are a legitimate way to test far more targets than HackerOne bounties alone. [disclose.io](https://disclose.io) maintains a safe-harbor policy database; [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) `/.well-known/security.txt` is a standardized way for a site to declare its disclosure process.
- Practical implementation: extend the scope-file mechanism from §1 so it validates a target has either (a) an entry in an authorized bounty-program scope, or (b) a discoverable `security.txt`/published VDP with safe-harbor language, before a scan is allowed to proceed. Default-deny anything unmatched.
- This directly extends [05-hackerone-and-legal.md](05-hackerone-and-legal.md), which currently only covers paid HackerOne programs — that doc should eventually get a VDP-target section alongside the bounty-program workflow.

## 3. XBOW Research (comparable: AI-driven autonomous pentester)

XBOW is the closest existing example of "build a scanner, run it against authorized programs at scale, turn the results into a business" — useful to study for both the technical and business-model angle, even though it's closed-source and a different tech stack (LLM-agent-driven rather than template-driven).

### Company & funding
- Founded 2024, Seattle, by **Oege de Moor** (creator of GitHub Copilot and GitHub Advanced Security) with engineers from the original Copilot team.
- Funding: ~$270M raised over 5 rounds. Series C was $120M (later extended to $155M with $35M from NVIDIA, Samsung, SentinelOne, and others), led by DFJ Growth and Northzone, valuing the company at over $1B. Earlier backers include Sequoia Capital and Altimeter.
- Went from founding to a >$1B valuation in roughly two years, driven substantially by the HackerOne leaderboard result below.

### Technical architecture
- **Multi-agent design:** a Main Agent handles pentest planning, decision-making, vulnerability analysis, and tool invocation; it autonomously spins up Sub Agents for software-engineering tasks (writing exploit/PoC scripts).
- **Recon-then-exploit phase split:** a reconnaissance phase (crawl via `curl`, collect request/response data) runs to completion *before* any exploitation is attempted — structurally similar to HackerFive's baseline-mode two-request design, just LLM-planned instead of template-defined.
- **"Reasoning over rules":** explicitly not a rule-based/if-then engine — the system teaches the agent how to reason about a target rather than encoding fixed detection logic. This is the fundamental architectural difference from Nuclei/HackerFive's template model: templates are auditable and reproducible; an LLM-reasoning agent is more adaptive but harder to make deterministic.
- **Deterministic validation layer:** despite the LLM-driven discovery, XBOW pairs it with a deterministic exploit-validation step specifically to keep false positives low before a finding is ever submitted — the same problem your <5% FP target is solving, just with a different mechanism (LLM re-verification instead of two-account baseline diffing).
- Reported ~96% success rate on XBOW's own hint-free benchmark (black-box, URL + challenge description only, no source access) — self-reported, treat as a marketing number, not an independent audit.

### HackerOne results
- Became the first AI system to reach #1 on HackerOne's US leaderboard (June 2025), submitting 1,060+ valid reports — RCE, info disclosure, cache poisoning, SQLi, XXE, path traversal, SSRF, XSS, secret exposure. In one 90-day window: 54 critical, 242 high, 524 medium severity findings.
- Critically: this was achieved **entirely inside authorized HackerOne program scope** — not by scanning arbitrary websites. That's the part of the model to copy for §2 above; the "AI hacking the whole internet" framing in press coverage is misleading.

### Business model: Pentest On-Demand
- Launched November 13, 2025 as a self-serve product: point XBOW at a target (URL + credentials), no scoping calls or kickoff meetings, get a compliance-ready report with plain-English summary, repro steps, and mitigations within **5 business days**.
- Pricing: **Lightspeed Plus $4,000**/test (brochure sites, simple apps), **Lightspeed Premium $8,000**/test (SaaS with multiple modules/integrations/workflows), **Enterprise** by quote.
- Positioned against traditional pentesting, which the company frames as 35-100 days and $10,000-$35,000+ per engagement — the pitch is speed and price, not novelty of findings.
- Relevant precedent for HackerFive: an open engine (or in XBOW's case, a novel agent) plus authorized-scope bounty results as a public credibility/leaderboard proof point, later packaged into a paid, fixed-scope, fast-turnaround product. If HackerFive open-sources the CLI, an analogous later step would be a hosted/managed scanning or report service — not a required next step, just a viable path once the open tool has traction.

## 4. Protocol/Capability Expansion Beyond HTTP

Assessed against the existing architecture decisions in doc 02, specifically the load-time rejection of Nuclei's `code:`/`javascript:`/`headless:`/`file:` template blocks and CLAUDE.md's read/enumerate-only rule.

| Capability | Verdict | Notes |
|---|---|---|
| **TCP** | Yes | Already a Nuclei protocol type; the Phase 1b Nuclei-compatible parser (doc 03, Week 6-7) currently scopes to `http` only and explicitly defers "network/DNS protocols" as out-of-scope for v0.1.0 — that's a deferral, not a rejection. Natural candidate for a Phase 2/1c slot: banner grabbing, open-port service identification. Read-only, low risk. |
| **SSL/TLS** | Yes | High value, low risk: expired/weak certs, deprecated protocol versions, weak cipher suites, hostname mismatch — all passive checks via Go's stdlib `crypto/tls`, no third-party dependency needed. Standard practice (testssl.sh, sslyze do the same). Caveat: many bounty programs explicitly mark "weak TLS config" low-severity or out-of-scope — useful for VDP-target reporting and completeness, less likely to be a paid finding. |
| **JavaScript — static analysis** | Yes | Crawl and scan served JS bundles for hardcoded secrets/API keys, exposed endpoints, and parameters (the LinkFinder/SecretFinder/JSluice category of tool). Fully read-only, directly expands the attack surface the IDOR/misconfig detectors can act on. Straightforward to add as a recon-phase step. |
| **JavaScript — headless/DOM execution** | Yes, but scoped narrowly | Already planned as optional (Chromedp) for DOM XSS validation (doc 03, Week 13-14) — keep it there, but sandbox it (isolated container, no filesystem/network egress beyond the target, resource limits) since a headless browser rendering attacker-influenced pages is itself attack surface. Important distinction: this is a **first-party, code-reviewed HackerFive feature**, not a channel for executing arbitrary community-submitted templates — the existing rejection of Nuclei's `headless:` protocol block for *imported* templates should stay in place regardless; the two aren't in tension. |
| **Code execution — blind/OOB verification** | Yes | Extend the Phase 3 SSRF interactsh integration (doc 03, Week 21-22) to also cover RCE verification: trigger a callback (DNS/HTTP ping to a self-hosted OOB server) to prove code execution capability without running attacker-meaningful commands on the target — the same technique the industry uses for safe Log4Shell-style detection, and structurally consistent with the existing baseline-mode "prove it without exploiting it" philosophy. |
| **Code execution — actually running commands on the target** | **No** | This crosses from enumerate/verify into exploit, directly conflicting with CLAUDE.md's read/enumerate-only rule and with what most bounty/VDP programs authorize (typically: prove RCE via a benign signal like `sleep()` or an OOB callback, never actually run `whoami`/dump data/modify state). Recommend explicitly *not* building a "run PoC command on compromised target" feature — the OOB-verification approach above gets the same detection value without the exploitation step. |

**Net recommendation:** TCP, SSL/TLS, and static JS analysis are straightforward, low-risk additions that fit the existing architecture and should be scheduled (likely folded into Phase 2, alongside or after the Nuclei-compatible parser gains non-HTTP protocol support). Headless DOM validation stays as already scoped (optional, sandboxed, first-party only). "Code execution" as a detection capability should mean OOB blind verification, not literal command execution against a target — that boundary is worth stating explicitly in doc 02 alongside the existing `code:`/`headless:` template rejection, so a future contributor doesn't conflate "detect RCE" with "run code on the target."

## 5. Backlog: Genuinely Open Items (from doc03/09/10/11)

Distilled from a full read of [03-development-roadmap.md](03-development-roadmap.md), [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md), [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md), and [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) — the point of this section is that a future reader can scan this table instead of re-reading all four docs to find out what's still worth picking up. Only genuinely open items are listed (something was measured/considered and deliberately not built *yet*, not ruled out on principle) — permanently rejected items (absolute-URI `raw:` proxy templates, `javascript()`-based `flow:`, interactsh/OAST, literal command execution on a target) are architectural/security boundaries, not backlog, and stay out of this list. doc10's own "Future Enhancements" tracker is fully closed (8/8 done) as of this writing — everything below is either newly surfaced from inside that doc's prose, or carried from doc11/doc03.

| Item | Size / impact (measured, not guessed) | Why deferred | Source |
|---|---|---|---|
| **File-based (wordlist) `payloads:`** | 240 templates real-corpus count; 237 of them one uniform WordPress-plugin-version-detection category | Needs `compare_versions()`/`concat()` DSL functions **and** a same-request extractor-to-sibling-matcher correlation mechanism first — the payload mechanism alone wouldn't unlock the category, so building it now wouldn't deliver the value the count suggests | doc10, "`raw:`/`payloads:` support" §, "File-based payloads — measured, and deliberately still excluded" |
| **Multi-key `payloads:`/attack modes** (sniper/pitchfork/clusterbomb) | 2 templates | Genuinely rare in the curated corpus — not worth the added complexity for 2 templates | doc10, "`raw:`/`payloads:` support" § |
| **Remaining DSL/`part:` gaps** — `server`/`set_cookie`/`title`/`os_info`/`location` identifiers, `+` string-concat operator, `date_time()`/`hex_to_dec()`/`substr()` functions, `xpath` matcher type | 1-10 templates each | Each individually too small to justify a dedicated pass; `date_time()`/`hex_to_dec()` specifically have two conflicting real format-string conventions in the sampled templates and `substr()`'s 3rd-argument semantics are ambiguous from a single sample — genuinely underspecified, not just low-priority | doc10, "Post-v0.1.0 DSL/part expansion" § and "Extractor -> DSL binding" § |
| **DOM-based XSS via Chromedp** | — | Passive/reflected template-driven XSS (doc11 Step 2) covers the bulk of realistically findable XSS at much lower cost; Chromedp adds a new dependency plus the sandboxing requirement this doc's own §4 calls for (isolated container, no filesystem/network egress beyond the target, resource limits). Revisit once Step 2's real yield is measured live | doc03 Week 13-14 ("Optional"), doc11 Scope |
| **Boolean-based (time-based blind) SQLi** | — | Error-based detection (doc11 Step 3) is the primary deliverable; doc03 itself marks this "if time allows." Revisit only if error-based detection's real yield against lab targets turns out too low to be useful alone | doc03 Week 15-16, doc11 Step 3 |
| **GitHub Action (`scan-action`)** | — (thin wrapper — small effort, per doc03's own estimate) | Serves a different audience than local/web-UI scanning — continuous self-scanning in CI (doc01's "Secondary" user segment), not opportunistic bug-bounty hunting. Not started as of this doc's last update; correctly a parallel/stretch track, not blocking any phase | doc03, "Note on GitHub Action" (Phase 2) and Parallel Tracks table |
| **Template signing** | — | Premature while templates are project-authored or pulled from a pinned upstream commit, not third-party-submitted. Trigger condition: the community template repository (doc03 Week 26) actually accepting outside submissions | doc02 "Future Considerations," referenced from doc03 Week 26 |
| ~~**Phase 2 auth-bypass recon breadth**~~ ✅ Done (2026-08-28) | ≥10 target **met**: **16** high-confidence findings — crAPI (2 original + 7 breadth `alg:none` spanning `identity`/`community`/`workshop` + 1 signature-stripped + 1 missing-auth), vAPI (2 `api1` token-reuse + 2 `jwt/user` `alg:none`/signature-stripped + 1 `jwt/user` broken-session); 4 independently re-confirmed via hand-built `curl`. Closed via crAPI's own OpenAPI spec (not guessed paths) plus resolving vAPI `jwt/user`'s earlier `500` (a reused-username DB constraint, not a bug). One dead end, not chased further: `api9/v2/user/login` looked like a good rate-limit positive control but its backing table doesn't exist in this vAPI image at all | doc11 Step 5 |
| **Phase 2 XSS/SQLi recon breadth** | ≥20/≥10 targets, real count as of 2026-08-28: 1 XSS + 1 SQLi, both DVWA only | Same shape as above — the structural blocker (reachability via `--header`, wrong-shaped generic templates) is fixed; what's left is covering more of DVWA's pages/params (stored XSS, blind SQLi) and finding whether Juice Shop has *any* server-reflected equivalent at all (none found yet — its known XSS surface is DOM-based/JSON, out of this technique's reach as currently scoped) | doc11 Step 5 |
| **False-positive rate re-measurement for Phase 2** | — | `scripts/measure-fp-rate.sh` (Phase 1b) was never extended to cover `authbypass`, the Phase 2 XSS/SQLi templates, or the comment-leak check — the <5% target is unverified for anything Phase 2 added | doc11 Step 5, Definition of Done |
| **Auth-bypass integration tests** | 2 files (`authbypass_crapi_test.go`/`authbypass_vapi_test.go`) | Live verification this session used ad-hoc `./hackerfive scan` runs (real, reproducible — commands documented in doc20) rather than a checked-in Go test, same gap doc11 Step 1 originally flagged before any recon had happened; now that real protected-paths/login-paths are known, writing these is unblocked | doc11 Step 1/5 |
| **`--scope` live verification against a real target** | — | Unit tests and `Engine`-level tests prove the matching logic; no run has actually pointed `--scope` at a real authorized target end-to-end yet | doc11 Step 0/5 |

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — vulnerability classes this expansion builds on
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — existing protocol scope and template-security decisions referenced in §4
- [03-development-roadmap.md](03-development-roadmap.md) — phase/week references throughout, and the source of most of §5's backlog items
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — current bounty-only legal/workflow doc; candidate for a VDP-target section per §2
- [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) / [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) / [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) — implementation plans §5's backlog items are distilled from; read these for the full measurement/reasoning behind each entry
