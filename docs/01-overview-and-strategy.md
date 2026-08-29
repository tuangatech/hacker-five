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

**Decision: open-source the engine, and scope authorized targets to any organization with a published VDP or bounty policy — not paid HackerOne programs exclusively.** Nuclei's playbook (MIT license, community templates, fast turnaround) is proven at scale (28,000+ stars, 12,000+ community templates), and reputation compounds toward this project's own milestones faster than a closed tool's would. Scope, not intent, is what makes scanning legal — VDPs (no payout, but a published safe-harbor policy, discoverable via `security.txt`/[disclose.io](https://disclose.io)) are far more common than paid bounty programs and let HackerFive be pointed at meaningfully more targets while staying strictly authorized. Full reasoning, the costs this incurs (community-template triage burden, a distributed tool inevitably getting pointed at unauthorized targets by *someone* regardless of this project's own conduct, mitigated by conservative defaults), and the scope-file extension this implies: [follow-up.md §2](follow-up.md#2-expansion-direction-open-source--vdpbounty-policy-scope).

### Competitive positioning: the XBOW comparison

**Closest comparable: XBOW** — an LLM-agent-driven, closed-source pentesting product that became the first AI system to reach #1 on HackerOne's US leaderboard (1,060+ valid reports, entirely within authorized program scope) and reached a >$1B valuation within about two years. XBOW validates that this market segment is real and lucrative, but its architecture is the opposite bet from HackerFive's: an LLM reasons freely about a target with a deterministic validation layer bolted on afterward, versus HackerFive's template-driven detection where the deterministic condition *is* the detector, not an after-the-fact check on one. Full research (funding, technical architecture, business model): [follow-up.md §3](follow-up.md#3-xbow-research-comparable-ai-driven-autonomous-pentester).

### Differentiation: hacker-in-the-loop, not fully autonomous

HackerFive's own answer to the AI-agent trend cited under [Why Now?](#why-now) is **"hacker-in-the-loop," not "fully autonomous."** [90-research-hackerbot.md](90-research-hackerbot.md) researched how the field's serious agent-driven pentesting tools structure themselves and resolved this project's own approach — a single coordinator, MCP-based tool access with no shell/exec surface, human approval via MCP `elicitation` before anything consequential happens — now scheduled as [Phase 5](14-implementation-plan-ph5.md)/[Phase 6](15-implementation-plan-ph6.md). The bet: keep the deterministic, auditable detection core (the same "PoC required" property every credible 2026 agentic pentesting tool converged on independently) something an agent reasons *over*, rather than replacing it with an agent's own free-form judgment the way a fully autonomous tool does.

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

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — how the shipped detectors above are implemented
- [03-development-roadmap.md](03-development-roadmap.md) — authoritative phase/week schedule
- [follow-up.md](follow-up.md) — full reasoning behind the Strategy section's open-source/VDP-scope decision (§2) and XBOW research (§3)
- [90-research-hackerbot.md](90-research-hackerbot.md) — the hacker-in-the-loop research behind this doc's Differentiation subsection, scheduled as [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)/[15-implementation-plan-ph6.md](15-implementation-plan-ph6.md)
