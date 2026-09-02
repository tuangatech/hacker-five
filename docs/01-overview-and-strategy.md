# Overview & Strategy

> Part of the [HackerFive documentation set](../README.md).

**Project Name:** HackerFive
**Goal:** Build an open-source, high-performance vulnerability scanner to participate in HackerOne bug bounty programs and VDP-scoped targets (see [Strategy](#strategy) below)
**Phase 1 Launch:** ~10 weeks (IDOR + Misconfiguration)
**Full Product Launch:** see [03-development-roadmap.md](03-development-roadmap.md) for the authoritative phase/week schedule — deliberately not restated as a total week count here, since it has already grown twice as scope expanded (Web UI became its own phase, then agent integration added two more) and a number copied here would just drift again
**Last Updated:** 2026-08-29

## Project Overview

### Mission
Build a **fast, extensible, open-source vulnerability detection engine** to automate security testing across APIs, web applications, and network services. The tool supports bug bounty hunting on platforms like HackerOne, BugCrowd, and Intigriti — and, per the [Strategy](#strategy) section below, any organization with a published Vulnerability Disclosure Policy (VDP) or bounty policy, not paid programs exclusively.

### Why Now?
- **Market Opportunity:** HackerOne paid out $81M in bug bounties (2024-2025), a 13% increase year-over-year
- **Tool Gap:** Most existing scanners (Burp, ZAP) are either too slow, too complex, or too expensive for distributed bug hunters
- **Community:** Nuclei (27,000+ GitHub stars) proved that open-source, template-driven detection works; opportunity to build specialized tool for APIs and authorization flaws
- **Emerging Vulnerabilities:** Prompt injection grew 540% YoY; fewer specialized tools available → less competition
- **The AI-agent trend has a name and a leaderboard entry.** 67% of researchers now use AI/automation, and hackbots (autonomous agents) have submitted 560+ valid HackerOne reports — XBOW is the clearest example, the first AI system to reach #1 on HackerOne's US leaderboard. See [Strategy](#strategy) below for how HackerFive positions against that model rather than copies it.

### Target Users
- **Primary:** Independent bug bounty hunters and small security teams
- **Secondary:** Startups needing affordable continuous security scanning
- **Tertiary:** Pentesting firms needing modular, customizable detection engine

## Market Analysis & Goals

### HackerOne Data (2024-2025 Report)

#### Most-Reported Vulnerabilities
| Rank | Vulnerability | Volume | Reward Trend | Notes |
|------|---------------|--------|--------------|-------|
| 1 | **Broken Access Control / IDOR** | 42% of all | ↑ +23% | Highest impact, growing focus |
| 2 | **Misconfiguration** | High | Stable | Easier to detect, lower false positives |
| 3 | **XSS (Cross-Site Scripting)** | Declining | ↓ Declining | Most tools find these; lower unique rewards |
| 4 | **Information Disclosure** | High | Stable | Medium effort, consistent bounties |
| 5 | **Prompt Injection (AI/ML)** | Rare | ↑↑ +540% | Emerging, least competition |
| 6 | **SSRF** | Medium | ↑ High reward | Complex, few automated tools |
| 7 | **SQL Injection** | Declining | ↓ Low | Mostly automated away by WAFs |
| 8 | **Authentication Bypass** | Medium | ↑ Growing | Multi-step exploits, high value |

#### Key Insights
- **For automation:** IDOR, misconfiguration, and prompt injection have highest reward-to-detection-effort ratio
- **For hunters using AI:** see the AI-agent bullet under [Why Now?](#why-now) and [Strategy](#strategy) below — this is now a real, scheduled part of HackerFive's own roadmap (Phases 5-6), not just an observed market trend
- **For depth:** Business logic flaws and multi-step exploits still require human analysis but earn highest bounties

## Strategy

The decisions below are what actually make this an "Overview & Strategy" doc rather than just an overview — each was made deliberately, with reasoning captured in more depth elsewhere; this section states the decision and its one-line reason, and links out for the full case.

### Distribution & scope: open-source engine, VDP + bounty-policy targets

**Decision: open-source the engine, and scope authorized targets to any organization with a published VDP or bounty policy — not paid HackerOne programs exclusively.** Nuclei's playbook (MIT license, community templates, fast turnaround) is proven at scale (28,000+ stars, 12,000+ community templates), and reputation compounds toward this project's own milestones faster than a closed tool's would. Scope, not intent, is what makes scanning legal — VDPs (no payout, but a published safe-harbor policy, discoverable via `security.txt`/[disclose.io](https://disclose.io)) are far more common than paid bounty programs and let HackerFive be pointed at meaningfully more targets while staying strictly authorized. Costs to plan for: community-template triage burden, and a distributed tool inevitably getting pointed at unauthorized targets by *someone* regardless of this project's own conduct — mitigated by conservative defaults (rate limits, no auto-brute-force) and explicit acceptable-use language, not by hoping for the best. See [21-scanning-real-targets.md](21-scanning-real-targets.md) for how the VDP-target workflow this scope decision implies actually works in practice.

### Competitive positioning: the XBOW comparison

**Closest comparable: XBOW** — an LLM-agent-driven, closed-source pentesting product that became the first AI system to reach #1 on HackerOne's US leaderboard (1,060+ valid reports, entirely within authorized program scope) and reached a >$1B valuation within about two years. XBOW validates that this market segment is real and lucrative, but its architecture is the opposite bet from HackerFive's: an LLM reasons freely about a target with a deterministic validation layer bolted on afterward, versus HackerFive's template-driven detection where the deterministic condition *is* the detector, not an after-the-fact check on one. Full research (technical architecture, business model): [discussions.md](discussions.md), "XBOW research."

### Differentiation: hacker-in-the-loop, not fully autonomous

HackerFive's own answer to the AI-agent trend cited under [Why Now?](#why-now) is **"hacker-in-the-loop," not "fully autonomous."** [90-research-hackerbot.md](90-research-hackerbot.md) researched how the field's serious agent-driven pentesting tools structure themselves and resolved this project's own approach — a single coordinator, MCP-based tool access with no shell/exec surface, human approval via MCP `elicitation` before anything consequential happens — now scheduled as [Phase 5](14-implementation-plan-ph5.md) (recon & orchestration foundations), [Phase 6](15-implementation-plan-ph6.md) (the MCP server itself), and [Phase 7](16-implementation-plan-ph7.md) (hardening). The bet: keep the deterministic, auditable detection core (the same "PoC required" property every credible 2026 agentic pentesting tool converged on independently) something an agent reasons *over*, rather than replacing it with an agent's own free-form judgment the way a fully autonomous tool does.

**Concretely, this makes HackerFive a hybrid, not an LLM-first design.** Most of what a scan does — matching a fingerprinted technology to the right detector/tool/template — is a deterministic decision-engine registry ([90-research-hackerbot.md](90-research-hackerbot.md) Decision 6), the same dispatch pattern HexStrike AI's own internal code already uses (confirmed by reading its source, not just its docs), just built first-party in Go rather than pulled in as a dependency. An LLM — tiered: a small local model for cheap, frequent judgment calls, a frontier model via OpenRouter for the rare case nothing else covers, principally authoring a genuinely new template — is invoked only when that deterministic layer comes up empty, and never as a persistent session driving the scan (doc90 Decision 5). Most of a scan's actual traffic and decisions never touch an LLM at all; see the [Capabilities at a Glance](#capabilities-at-a-glance) section below for what's dispatched deterministically today versus planned.

## Prioritization Rationale

*(Formerly "Target Vulnerability Classes," with phase/week numbers removed — that duplication had already drifted out of sync with reality once, see the note below.)*

Why these vulnerability classes, in this order — reward-to-detection-effort ratio and competitive gap (see [Market Analysis](#market-analysis--goals) above), not a re-derivation of the schedule. Current build status and detection approach live in [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) (shipped detectors) and [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) (Phase 4 detectors); current phase/week assignment lives in [03-development-roadmap.md](03-development-roadmap.md). None of that is restated here — this list previously carried its own phase headers and week estimates, which fell out of sync with doc03 the first time a phase got reordered (Web UI's insertion as Phase 3 pushed Prompt Injection/SSRF/Business Logic from "Phase 3" to Phase 4) and were a stale, uncorrected copy of that reordering until this revision.

1. **IDOR** — ✅ built. 42% of all reported vulnerabilities, 49% of critical/high-severity issues, +23% YoY growth; the highest-impact, most automatable class available.
2. **Misconfiguration** — ✅ built. Consistent discovery, very low false positives, no payload complexity — the natural low-risk second bet, and the class where pulling in the existing `nuclei-templates` corpus directly (rather than authoring detection knowledge from scratch) pays off most.
3. **API Auth Bypass** — ✅ built. APIs are a growing attack surface where traditional scanners are weak; medium-high automation difficulty, but no existing generalist tool specializes here the way HackerFive can.
4. **XSS** — ✅ built (breadth still growing — see doc11). Historically the #1 reported class, but declining in unique-bounty value as most tools already catch it: worth having, not worth over-investing in.
5. **SQL Injection** — ✅ built (breadth still growing — see doc11). Declining due to WAFs/parameterized queries, but still real value in niche cases; explicitly not a SQLmap replacement.
6. **Information Disclosure** — ✅ built (folded into the misconfig detector, see doc13's Objective). Medium effort, consistent bounties.
7. **Prompt Injection** — ✅ built ([13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 1). 540% YoY growth in reports and the least competition of any class in this list — the strategic bet this project is currently most differentiated on.
8. **SSRF** — ⬜ planned ([13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 2). Complex to automate and few existing tools do it well; high reward when found.
9. **Business Logic Flaws** — ⬜ planned ([13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 3). Requires the deepest understanding of application flow and the most human judgment of any class here; highest bounties, deliberately scheduled last.

## Capabilities at a Glance

A single place naming every dispatchable capability by category, added 2026-08-30 so "which detectors/tools/templates exist" isn't scattered across doc02/doc13/doc14. Status reflects what's actually shipped per doc03 — recon tools and the decision-engine registry (doc90 Group I) don't exist yet, listed here as the planned target, not current capability. This list is also I1's own justification: once the registry exists, this becomes generated/machine-searchable (`tools.search`/`templates.search`, doc15) instead of hand-maintained prose — treat this section as the seed data for that, not a permanent hand-written list.

**Detectors** (`pkg/detectors/`, one Go package each except where noted, wired into `scanner.Engine`):
| Detector | Status | Shape |
|---|---|---|
| `idor` | ✅ shipped (Phase 1a) | Two-account baseline comparison |
| `misconfig` | ✅ shipped (Phase 1b) | Fixed-path + keyword/header match, mostly synced `nuclei-templates` |
| `authbypass` | ✅ shipped (Phase 2) | JWT tampering, token reuse, rate-limit signal |
| `promptinjection` | ✅ shipped (Phase 4) | Template-driven (no Go package) — marker match in a chat-shaped response |
| `ssrf` | ⬜ planned (Phase 4, doc13 Step 2) | Non-blind + scheme-based + OOB-blind (interactsh) |
| `businesslogic` | ⬜ planned (Phase 4, doc13 Step 3) | `--allow-writes`-gated; coupon reuse, price manipulation, payment race conditions |

**Recon tools** (`pkg/recon/`, shelled out via fixed, named-binary subprocess calls — doc14 Step 3, none shipped yet):
| Tool | Wave | Role |
|---|---|---|
| subfinder | 1 (passive) | Subdomain/DNS enumeration |
| tlsx | 1 (passive) | TLS/cert inspection |
| dnsx | 2 (active-low-noise) | DNS resolution |
| naabu | 2 | Port scan (Go-native substitute for nmap) |
| httpx | 2 | HTTP probe/fingerprint — feeds `pkg/fingerprint`'s tech-signature detection (doc90 I2) |
| katana | 3 (application-layer) | Crawl |
| interactsh (first-party protocol client, not the upstream library — see doc02 §8's dependency-footprint lesson) | cross-cutting | OOB callback correlation, shared by SSRF and later blind XSS/SQLi checks |

**Template categories** (YAML, two engines per doc02 §2 — `nuclei`-compatible and HackerFive-native):
| Category | Engine | Status |
|---|---|---|
| IDOR baseline, prompt injection, business logic | Native | Request-chaining/stateful — no Nuclei equivalent |
| Misconfiguration, exposed-panels, technologies | Nuclei-compatible, synced from upstream `nuclei-templates` | ✅ shipped |
| SSTI, XXE, path traversal, open redirect, CVE-tagged | Nuclei-compatible, same synced corpus | ⬜ planned — enabling existing upstream tags via the decision engine (doc90 I3), not authoring new templates |
| Subdomain takeover | Native, recon-derived (dangling CNAME) | ⬜ planned (Phase 5, recon Wave 1 byproduct) |

Full detail: [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) (the architecture each category is built on), [03-development-roadmap.md](03-development-roadmap.md) (phase/week schedule), [90-research-hackerbot.md](90-research-hackerbot.md) Group I (the registry and decision engine these three lists feed).

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — how the shipped detectors above are implemented
- [03-development-roadmap.md](03-development-roadmap.md) — authoritative phase/week schedule
- [follow-up.md](follow-up.md) — open enhancement backlog by category (security hardening, protocol expansion, detection/template gaps)
- [discussions.md](discussions.md) — XBOW research behind the Competitive positioning subsection above, plus other dated architecture/research write-ups
- [90-research-hackerbot.md](90-research-hackerbot.md) — the hacker-in-the-loop research behind this doc's Differentiation subsection, scheduled as [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)/[15-implementation-plan-ph6.md](15-implementation-plan-ph6.md)/[16-implementation-plan-ph7.md](16-implementation-plan-ph7.md)
