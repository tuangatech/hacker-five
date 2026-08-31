# Recon Phase for HackerFive — Research & Design

> Part of the [HackerFive documentation set](../README.md).

**Status:** Scheduled. Extends [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)'s existing "Recon Phase (Optional, delegated to external tools)" sketch — which names Subfinder/Nmap/header-fingerprinting but was never assigned a week in any phase — into a concrete design for the agent-driven flow [90-research-hackerbot.md](90-research-hackerbot.md) describes. Captured here ahead of a roadmap slot, the same way doc90 was. [Section 7](#7-scheduling-question--resolved) below originally posed two options for where this work lands; **the user chose option 2** — recon gets its own phase, ahead of the MCP-server/approval-gate work. This doc's Group R backlog is now scheduled: R1-R3 in [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) (Phase 5, Weeks 33-40, no MCP dependency), R4-R6 in [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) (Phase 6, Weeks 41-48, once the MCP server/`plan` tool exist to wire them into).

**Last Updated:** 2026-08-29 — revised with a cited research pass (Sources under Section 1) directly against each comparable tool's own docs/code/papers, replacing this doc's first-draft uncited claims. Fixed a real ordering bug the first draft had (Waves 2-3's active probes ran before Wave 4's `--scope` cross-check, contradicting Wave 1's own stated reason for its WHOIS/ASN check) and a mislabeled `HostFact.Confidence` comment (it claimed to mirror `Finding.Confidence`, which is a different, two-value field). A same-day follow-on restructured the roadmap per Section 7's resolution (below) — Phase 5 is now recon + task-tree/schema foundations, Phase 6 is the MCP server/approval gate, and the original Phase 6 (hardening) became Phase 7.

## Why this doc exists

Doc90's proposed agent flow (plan → approve → scan → triage) has no step that produces the facts a coordinator would actually reason from before proposing a plan. This doc closes that gap: (1) why a dedicated recon phase is needed — not as an AI-specific idea, but as the same first phase every professional pentest methodology already puts first, for a documented reason; (2) the specific gap in HackerFive's current docs; (3) a concrete, ordered list of what the recon phase should actually do; (4) where it sits in the complete recon → reasoning → decision → human-review flow; and (5) the design constraints that keep it consistent with everything doc90/doc02 already committed to (no shell tool, read/enumerate-only, structured output).

---

## 1. Why a dedicated recon phase

### It's the first phase in every professional methodology, for a stated reason

PTES, NIST SP 800-115, and the OWASP Testing Guide all put reconnaissance / intelligence-gathering immediately after scoping and before anything else. The reasoning is explicit in the methodology literature, not just convention: the intelligence gathered here drives all subsequent phases, and the quality of the reconnaissance directly determines the quality of the findings — testers who rush this phase invariably miss critical assets and attack vectors. PTES names a distinct phase between intelligence-gathering and exploitation — threat modeling and vulnerability analysis — where testers use the fresh intelligence to model likely attack paths, prioritize high-value targets, and produce a structured plan that gets coordinated and approved before anything disruptive launches.

That's the recon → reasoning → plan → approval → execute shape doc90 is reaching for. It isn't a new idea an LLM introduces; it's the standard shape of a human engagement, and HackerFive's agent should follow it for the same reason a human tester does.

### Why it matters more, not less, for an LLM specifically

An LLM reasoning about a target it hasn't looked at yet reasons from priors, not facts — it will guess at a tech stack, guess at which of the ~3,500 synced templates apply, and spend budget on hypotheses that don't fit the actual target. This subsection was re-researched directly against each tool's own docs/code/papers rather than restated from doc90's summary table — see Sources below.

- **XBOW** maps the asset, identifies endpoints/inputs/attack surfaces, and searches for hidden parameters, JS files, and injection points — dynamically writing and executing code to do so — *before* forming hypotheses about where vulnerabilities might exist. Discovery is a distinct phase that terminates once suspicious vectors are found and handed to exploitation, though XBOW's own material notes AI-driven recon/exploit phases show "more overlap" than a traditional human pentest has.
- **CAI**'s tool taxonomy is literally "grouped in 6 major categories inspired by the security kill chain," with "reconnaissance and weaponization" as the first category.
- **PentestGPT**'s 2026 autonomous rebuild states its pipeline explicitly as staged phases — "recon → exploit → walkthrough" for CTF, "asset discovery → vulnerability identification → report" for a real pentest — confirming recon as a distinct, sequential first stage, not merged with exploitation.

**A finding worth naming directly, not glossed over: every one of these tools hands its agent a general shell/terminal for reconnaissance, not a narrow recon-specific tool — doc90's Decision 2 undercounts this.** Doc90's own text names only "HexStrike, CAI, and PentestAgent" as giving the model a shell tool; this research found the pattern is close to universal. Strix's own docs list a bare "Terminal (Bash shell)" alongside sandboxed Nuclei/ffuf; CAI's recon category's actual tool is `LinuxCmd` — general command execution; MAPTA's Sandbox agents get exactly two tools, `run_command` (shell) and `run_python`, with curl dominating real measured usage; PentestAgent's built-ins are `terminal`/`browser`/`notes`/`web_search`; Cyber-AutoAgent "automatically chooses" nmap/sqlmap/nikto through a "unified tool-selection API" that is, functionally, the same pattern with extra steps; HexStrike is the *one* project with genuinely scoped per-binary MCP wrappers (`nmap_scan()`, `amass_enum()`, `httpx_probe()`, etc. — see Wave 1-3 below, whose tool choices are drawn directly from HexStrike's real catalog) but ships a raw `POST /api/command` endpoint right alongside them anyway. **This means HackerFive's recon design below is a genuinely conservative outlier relative to the field, not a "catch up to everyone else" proposal** — see the design-tension callout in Section 5, and doc90's corrected Decision 2 text.

For HackerFive specifically, a recon phase does three concrete jobs, each independently worth having:

1. **Narrows the template search space before the coordinator picks anything.** Deciding which of thousands of synced templates applies to a target is either "run everything" (slow, noisy, defeats the point of having an LLM select) or a guess. Recon output is what a tag match should run against.
2. **Grounds the `PlanTree`'s initial leaves in facts, not hallucination.** A leaf proposing "check for GraphQL introspection exposure" is only a reasonable candidate if recon actually saw a `/graphql` endpoint.
3. **Is the mechanism that triggers the scope-creep gate that already exists on paper.** Doc90's B4 requires fresh approval when a scan's own recon surfaces hosts/paths outside `--targets`/`--scope` — but nothing in the current design *produces* newly discovered hosts/paths for B4 to react to. Recon is the missing half of an already-written guardrail.

**Sources consulted (this revision):** unlike this doc's first draft, every claim above about a *specific* tool's recon mechanics is now sourced directly, matching doc90's own citation discipline.
- XBOW — [Core Components of an AI Pentesting Framework](https://xbow.com/blog/core-components-ai-pentesting-framework)
- Strix — [docs.strix.ai](https://docs.strix.ai/), [tools overview](https://docs.strix.ai/tools/overview)
- CAI — [architecture docs](https://aliasrobotics.github.io/cai/cai_architecture/)
- MAPTA — [arXiv:2508.20816](https://arxiv.org/html/2508.20816v1)
- PentestAgent — [GH05TCREW/pentestagent on GitHub](https://github.com/GH05TCREW/pentestagent)
- HexStrike AI — [GitHub](https://github.com/0x4m4/hexstrike-ai)
- Cyber-AutoAgent — [GitHub](https://github.com/westonbrown/Cyber-AutoAgent)
- PentestGPT — [GitHub](https://github.com/GreyDGL/PentestGPT)

**One more contrast worth naming: Cyber-AutoAgent persists recon/exploit findings via Mem0 cross-session memory (`category="finding"`)** — an open-ended conversational memory that survives across separate runs. This is exactly the pattern doc90's OWASP ASI06 mitigation (Section 5 of doc90) argues against in favor of per-job state refreshed each run. HackerFive's `ReconResult`/`PlanTree` design (Section 5 below) already follows doc90's stated position, not Cyber-AutoAgent's — worth stating as a deliberate divergence now that there's a concrete example to diverge from, not just an abstract principle.

---

## 2. The gap in HackerFive's current docs, stated precisely (as it stood before this doc's Group R was scheduled — see Section 7)

- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) lists a Recon Phase (Module 2) — subdomain enumeration via Subfinder, port discovery via Nmap/Masscan, tech-stack fingerprinting via HTTP headers — but marked it "Optional, delegated to external tools" and it had never been assigned to a week in [03-development-roadmap.md](03-development-roadmap.md) across Phases 1-6 (now 1-7).
- [90-research-hackerbot.md](90-research-hackerbot.md)'s MCP tool list (`scan`, `templates.list`, `templates.sync`, `findings.export`, `plan`) had no recon tool, and its `Job.PlanTree` (Group H) had no named source for its initial leaves.
- The scope-creep gate (doc90's B4) was written to react to recon surfacing out-of-scope hosts/paths, but nothing in the design produced that signal.

None of this blocked the CLI-only tool — a human operator can run Subfinder themselves and pass multiple `--targets` — but it did block the agent flow, since the coordinator had nothing concrete to reason over until something produced a structured picture of the target. This is the gap Group R (Section 6) closes, and Section 7 records where it landed on the roadmap.

---

## 3. What the recon phase should actually do

Ordered the same way PTES orders passive-before-active reconnaissance: cheapest and lowest-footprint first, escalating only as needed. A run doesn't have to reach the later waves — a `--recon-depth passive|active|full` style flag (mirroring Strix's `--scan-mode quick|deep`) should let an operator or the coordinator stop early.

### Wave 0 — Zero-touch: use what's already provided or already known

Costs nothing and touches nothing beyond what the operator already gave HackerFive.

- **Parse any user-supplied API spec first.** OpenAPI/Swagger, GraphQL SDL, or a Postman collection, if provided, turns directly into an endpoint/parameter inventory — this is strictly better ground truth than anything inferred later, and it's the exact pattern [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 3 already uses for crAPI's own spec, generalized to any target.
- **Read the `--scope` file and the [22-authorized-targets.md](22-authorized-targets.md) registry entry**, if one exists, for previously recorded notes, policy links, and the declared host/CIDR set. This is the baseline everything else gets checked against.
- **Fetch `/.well-known/security.txt`.** Zero-risk (one GET to a well-known path), and doubles as input to the D2 program-policy pre-flight check ([15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Step 3, once the MCP server exists to enforce it as a hard block) — no reason to fetch it twice.

### Wave 1 — Passive: no direct interaction with target infrastructure

- **Passive subdomain/DNS enumeration** (Amass/Subfinder-style, passive sources only: certificate-transparency logs, public DNS aggregators, search-engine-indexed subdomains; TheHarvester-style email/subdomain harvesting) — no active DNS brute-forcing yet. Tool names drawn from HexStrike's real catalog (Section 1's Sources), not invented.
- **WHOIS / ASN lookup** on the primary domain, to sanity-check that anything discovered later actually belongs to the authorized organization — catches "same company, unrelated product" scope drift before it becomes a live request.
- **TLS certificate inspection** of the primary target's certificate SANs — a common, free source of sibling environments (`staging.`, `api.`, `admin.`) that a subdomain wordlist alone would miss.
- **Cross-check every host discovered above against `--scope`/the [22-authorized-targets.md](22-authorized-targets.md) registry immediately, before Wave 2 fires a single active probe.** This is a fix to this doc's own first-draft ordering: an earlier version deferred this check to Wave 4 (aggregation), *after* Waves 2-3's active port scans/HTTP probes/crawls had already touched every discovered host — directly contradicting this Wave's own stated reason for the WHOIS/ASN check above ("before it becomes a live request"). Anything outside scope is set aside into `ReconResult.OutOfScope` (Section 5) and excluded from every wave below; it's flagged now, not merely reported after the fact.

### Wave 2 — Active but low-noise: the standard first live-touch step, run only against Wave 1's scope-filtered host list

- **Resolve the scope-filtered subdomain list to a live-host set** (httpx-style DNS resolution) — filters "used to exist" from "actually resolves today" before anything more expensive runs against it.
- **Port scan live hosts** (Nmap/Rustscan/Masscan-style, top-N common ports by default — not a full 65535 sweep unless explicitly requested), same tools doc02 already named.
- **Service/version fingerprinting on open ports** (banner grab / `-sV`-style) — what's actually listening, not just that a port is open.
- **HTTP(S) probe every live host:port** (httpx/Whatweb-style): status code, page title, redirect chain, server header, and CMS/framework signatures from headers or response body — this is the "tech-stack detection" doc02 already sketched.

### Wave 3 — Application-layer mapping: what actually feeds template/detector selection

- **Bounded crawl of discovered web hosts** (Katana/Hakrawler-style) to enumerate reachable pages, forms, JS bundles, and linked API calls — capped by `--scope` and an explicit depth/page limit so this can't become an uncontrolled spider. A link to a genuinely new external domain found mid-crawl (e.g. a third-party asset host never seen in Wave 1's passive enumeration) is the one category of out-of-scope discovery that legitimately surfaces this late — set aside into `OutOfScope` same as Wave 1's check, not silently followed.
- **Parse crawled JavaScript bundles for embedded API paths.** A cheap, high-value source of API surface a plain HTML crawl misses — worth calling out specifically since HackerFive's stated audience (doc01) is API-focused.
- **Probe common framework/API conventions** (`/api`, `/graphql`, `/swagger.json`, `/.well-known/openapi.json`, `/robots.txt`, `/sitemap.xml`). This is *discovery*, distinct from the misconfig detector's exposed-path checks (which look for bad exposure like `/.env`) — it's mapping the shape of the app, not itself producing a `Finding`.
- **Auto-discover and parse an API schema** if Wave 3's probing finds one (`swagger.json`, `openapi.yaml`, GraphQL introspection) — same treatment as Wave 0's user-supplied spec. When this succeeds it often makes the crawl/JS-parsing steps above redundant, since a real spec beats an inferred one.
- **Mine hidden parameters** (Arjun/ParamSpider/X8-style) on discovered endpoints — a cheap, high-value complement to the crawl above; this is the step HexStrike's own catalog treats as its own tool family, distinct from crawling.
- **Tag the presence of an auth boundary** (login form, OAuth redirect, JWT-shaped cookie) without attempting to break it — this doesn't produce a finding, it answers "are the IDOR/authbypass detectors even applicable here."

### Wave 4 — Aggregation: turn raw facts into the structured `ReconResult` the coordinator reasons over

- **Tag every discovered host/endpoint against HackerFive's own template vocabulary** (`idor`, `misconfig`, `authbypass`, technology names) so the reasoning step has something to match against directly, not free text.
- **Attach a source and confidence label to every fact** — e.g. `tech=Express — source: header fingerprint, confidence: high` vs. `endpoint=/internal/debug — source: JS bundle string, confidence: low, unconfirmed live` — the same discipline `Finding.Confidence` already applies, one step earlier.
- **Finalize `ReconResult.OutOfScope`** from the filtering Wave 1 already performed on every host before Wave 2's active touches, plus anything Wave 3's crawl flagged as newly discovered mid-crawl. This wave doesn't perform the scope check for the first time — that would repeat the ordering bug this doc's own first draft had — it aggregates what earlier waves already excluded into the one list that feeds B4's scope-creep gate.

---

## 4. Where recon fits in the complete agent-driven flow

```
 0. Scope intake
    Human specifies target(s); checked against --scope / 22-authorized-targets.md
    (D2/D3 hard blockers apply from here on, not just at execution time)
                              │
                              ▼
 1. Recon phase  (new: pkg/recon/ + `recon` MCP tool — read-only throughout, no --allow-writes)
    Waves 0-4 above, escalating only as far as --recon-depth allows
    Output: a fixed, structured ReconResult — never raw tool stdout in the agent's context
                              │
                              ▼
 2. LLM reasoning / threat modeling  (Coordinator; no request sent to the target yet)
    Matches ReconResult against template tags + doc01's reward-to-effort priors
    → proposes PlanTree leaves: (target, detector/template, rationale, Confidence)
                              │
                              ▼
 3. Plan proposal  (`plan` MCP tool → MCP elicitation, per doc90 Decision 3)
    Human sees the proposed leaves and rationale, approves / edits / rejects
    before anything beyond recon touches the target
                              │
                              ▼
 4. Scoped execution  (`scan` MCP tool → existing deterministic engine)
    Only approved leaves run; PoC-required matchers unchanged (IDOR baseline
    comparison, misconfig fixed-path match, etc.) — the agent still never
    crafts a raw request outside the engine's guardrails
    Findings/Logs stream live via WithFindingCallback/WithLogCallback (doc90 A2)
                              │
                              ▼
 5. Result interpretation
    Coordinator updates leaf Confidence/Status; may propose new leaves
                              │
              new surface discovered? ──yes──▶ back to step 3 (B4 scope-creep re-approval)
                              │ no
                              ▼
 6. Human final review  (Web UI Agent tab, live reasoning trace + kill switch)
    Nothing reaches findings.export / a HackerOne draft without this step (B3)
```

The loop between steps 3 and 5 matters as much as the linear part: a single approved plan runs and produces evidence, and that evidence is allowed to *propose* the next round, but never to silently expand what it's already allowed to touch.

---

## 5. Design constraints worth locking in before this gets built

- **Named tradeoff: this design deliberately swims against the field's revealed practice, for a stated reason.** Section 1's research found that Strix, CAI, MAPTA, PentestAgent, and (functionally) Cyber-AutoAgent all give their agents a general shell/terminal for recon specifically — even HexStrike, the one project with real per-binary MCP wrappers, ships a raw command endpoint alongside them. The likely reason: recon genuinely benefits from ad-hoc flexibility (a target's specific structure suggests a follow-up probe no fixed wave anticipated) in a way exploitation's PoC-required matchers don't need to. HackerFive's wave-based, schema-scoped `recon` tool (R1/R4 below) gives up that flexibility on purpose, to keep Decision 2's "no shell tool, anywhere in the server" boundary intact without a carved-out exception for "just this one phase." The cost is real and worth stating plainly: a target whose interesting recon signal doesn't fit Waves 0-4's fixed shape won't be caught until a human operator notices and extends the wave list — HackerFive is trading some recon completeness for keeping its one hard architectural boundary genuinely absolute.
- **Recon stays a scoped tool, not a door back into "run arbitrary command."** Subfinder/Nmap/httpx are external binaries; calling them via `os/exec` looks superficially like the shell-tool pattern doc90's Decision 2 already rejected. What keeps it safe: fixed, schema-validated arguments (target, port range, timeout) the same way `scanner.Config` already is — the agent picks a target, not a command string. This is the same precedent the project already accepted for `git` in `pkg/templatesync` (a scoped subprocess call with a stated prerequisite, not a general shell).
- **`ReconResult` needs its own frozen schema, same discipline as `Finding`.** If it's "whatever Nmap printed," the raw-chat problem doc90 already warns against comes right back in one layer earlier. A minimal sketch:

  ```go
  type ReconResult struct {
      Target      string
      Hosts       []HostFact
      Endpoints   []EndpointFact
      TechStack   []TechFact
      APISpec     *APISpecFact // parsed OpenAPI/GraphQL SDL, if found
      OutOfScope  []string     // discovered but excluded per --scope — feeds B4
      GeneratedAt time.Time
  }

  type HostFact struct {
      Host       string
      Ports      []PortFact
      Source     string // "passive-subdomain" | "dns-resolve" | "user-supplied" | ...
      Confidence string // "high" | "medium" | "low" — mirrors the task-tree-leaf Confidence banding
                          // (doc14 Step 2 / H3's Cyber-AutoAgent-derived convention), NOT Finding.Confidence,
                          // which is a distinct two-value field ("high"|"low") a detector sets after a
                          // Finding already exists — doc14's Objective already caught this exact conflation
                          // once; this comment previously repeated the mistake it was warning against
  }
  ```

- **No `--allow-writes` needed.** Every wave above is read/enumerate-only, consistent with CLAUDE.md's existing rule — recon doesn't need the CLAUDE.md addendum doc13's business-logic writes required.
- **Recon requests still go through the existing rate-limit/concurrency middleware and host-error-cache circuit breaker** (doc02 §3) — an active port scan or crawl is not exempt from the same guardrails a template-driven scan already respects.
- **Passive-first is the default, not a suggestion.** An operator (or the coordinator, for a real bug-bounty target) should be able to cap a run at Wave 1 for zero-footprint reconnaissance before deciding whether to go further — the natural implementation is a `--recon-depth passive|active|full` flag.

---

## 6. Concrete backlog (new group R)

Same convention as doc90's Groups A-H: ⬜ = not yet designed in detail.

Scheduled per Section 7's resolution: R1-R3 land in [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) Step 3 (no MCP dependency); R4-R6 land in [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Steps 1-3 (each needs the MCP server or the `plan` tool to exist first).

- ✅ **R1 — `pkg/recon/` package.** Done 2026-08-31. `Detector`-style construction (`New(client, opts...)`, `Option` funcs), one file per wave family (`passive.go`, `active.go`, `crawl.go`, `aggregate.go`), producing a single `ReconResult`. → doc14 Step 3.
- ✅ **R2 — `ReconResult` schema, frozen and versioned** alongside `Finding`'s (doc14 A3) — same "publish before an external client depends on the shape" discipline. Done 2026-08-31 (`docs/schema/recon-result.schema.json`). → doc14 Step 3.
- ✅ **R3 — `hackerfive recon` CLI subcommand**, usable standalone (no agent required) — `--recon-depth passive|active|full`, `-o recon.json`. Useful on its own for a human operator, not just as agent infrastructure. Done 2026-08-31, live-verified against real crAPI/DVWA. → doc14 Step 3.
- ⬜ **R4 — `recon` MCP tool**, schema-validated the same way `scan` already is; wraps R1, excluded from Decision 2's "no shell tool" boundary via fixed argument shape, not free-form command text. → doc15 Step 1.
- ⬜ **R5 — Wire `ReconResult` into `PlanTree` seeding.** The coordinator's first `plan` proposal (doc90 B1) is generated from a `ReconResult`, not from an empty tree — this is the concrete fix for Group H having no named source for its initial leaves. → doc15 Step 2.
- ⬜ **R6 — Wire `ReconResult.OutOfScope` into B4's scope-creep gate.** Currently B4 has no producer; this is it. → doc15 Step 3 (first implementation), doc16 Step 2 (compliance rounding).

### Anticipated files (confirm at implementation time, same caveat every other implementation-plan doc states)
- `pkg/recon/{detector,passive,active,crawl,aggregate}.go`
- `cmd/hackerfive/recon.go`
- `docs/schema/recon-result.schema.json`
- `tests/unit/recon_*_test.go` — including a test confirming Wave-2+ steps never fire when `--recon-depth passive` is set

---

## 7. Scheduling question — resolved

This section originally posed the question unresolved; recorded below with the decision, matching this project's own "resolved tension" discipline (doc13's format) rather than silently deleting the history once decided. Two live options were on the table:
1. Compress recon into Phase 5's existing 8 weeks by cutting something else out to Phase 6, accepting a tighter Phase 5.
2. **Chosen: give recon a dedicated phase of its own**, ahead of the MCP-server/approval-gate work — a new Phase 5 scoped to recon + the task-tree/`PlanTree` data model + `Finding`-schema freeze (the pieces buildable and testable via CLI alone, with no dependency on an MCP SDK actually working), pushing the original doc14 content (MCP server, `plan`/elicitation approval, hard safety blockers) to a renumbered Phase 6 and the original doc15 hardening content to a new Phase 7. The deciding technical argument, beyond sizing: the MCP Go SDK's `elicitation`/`tasks` support is unverified (now doc15 Step 1's first task), so building recon/`PlanTree` first means that risk doesn't block or get entangled with work that has nothing to do with it.

Executed the same day across doc03 (roadmap week ranges/milestones), doc14 (rewritten for recon + foundations), doc15 (renumbered from the original doc14, re-sequenced to build on doc14 instead of building the foundations itself), doc16 (renumbered from the original doc15), and doc90 (status line, Decision 2 citation, backlog cross-references) — not left to drift the way doc01's phase references drifted once before (see doc01's own "Prioritization Rationale" section for that history).

---

## Definition of Done

- [x] `hackerfive recon` runs standalone against a lab target and produces a `ReconResult` matching the frozen schema, with Wave 0-4 facts each carrying a source and confidence label — done 2026-08-31, see [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) Step 3
- [x] `--recon-depth passive` is confirmed, live, to never send a single active probe (DNS resolution, port scan, HTTP request) to the target — done 2026-08-31
- [ ] The `recon` MCP tool is schema-validated and excluded from anything shell/exec-shaped, consistent with doc90 Decision 2 — Phase 6 (needs the MCP server)
- [ ] A coordinator's first `plan` proposal is demonstrably seeded from a real `ReconResult`, not an empty or hand-authored tree — Phase 6 (needs the decision engine, R8, and the `plan` tool)
- [ ] A discovered out-of-scope host actually populates `ReconResult.OutOfScope` and is confirmed to trigger doc90 B4's re-approval path, live-verified, not just unit-tested — the `OutOfScope` population half is done 2026-08-31; the B4 re-approval trigger is Phase 6 (needs the coordinator loop)
- [x] An out-of-scope host discovered in Wave 1 is confirmed, live, to receive zero active probes in Wave 2/3 (port scan, HTTP probe, crawl) — the scope filter runs before active touch, not only reported after it — done 2026-08-31; live testing also caught and fixed a related bug where the *target itself* failing `--scope` wasn't fully honored (see doc14 Step 3)
- [x] Recon requests are confirmed to respect the existing rate-limit/concurrency defaults and host-error-cache circuit breaker — no separate, ungoverned code path for Nmap/crawl traffic — done 2026-08-31 for Wave 0/3's own HTTP calls; Wave 1-3's binary-shelled calls get the same configured numbers via each tool's own native flag instead (see doc14 Step 3's Design section for the honest reconciliation)
- [x] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean — clean as of 2026-08-31 for R1/R1b/R2/R3; R7-R9 still open

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — the original Recon Phase sketch this doc makes concrete
- [90-research-hackerbot.md](90-research-hackerbot.md) — the agent flow (plan → approve → scan → triage), `PlanTree` (Group H), and B4 scope-creep gate this doc's output feeds
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) / [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — where Group R actually landed (R1-R3 / R4-R6 respectively), per [Section 7](#7-scheduling-question--resolved)'s resolution
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the crAPI-OpenAPI-spec pattern Wave 0/3's schema auto-discovery generalizes
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — the vulnerability classes recon's tagging step (Wave 4) matches templates against
- [22-authorized-targets.md](22-authorized-targets.md) — the registry Wave 0/1 cross-check against (Wave 4 aggregates, it doesn't perform the check first — see the ordering fix in Wave 1)
