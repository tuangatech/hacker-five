# Phase 6 Implementation Plan — Weeks 41-48 (MCP Server & Approval Gate)

> Part of the [HackerFive documentation set](../README.md).

**Renumbered from "Phase 5" during the 2026-08-29 recon-phase restructuring.** This doc originally covered both the recon-independent foundations (eval harness, `Finding`-schema freeze, `PlanTree` data model) and the MCP-server/approval work together. [91-research-recon-phase.md](91-research-recon-phase.md)'s research surfaced a real reason to split them, not just a sizing one: [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)'s content (now covering recon + the data-model foundations) has zero dependency on an MCP SDK actually working, while everything in this doc depends on it directly. Bundling them meant an SDK risk outside this project's control could stall recon work that has nothing to do with it. This doc keeps the original MCP-server/approval-gate content, renumbered and re-sequenced to build on doc14 instead of building the foundations itself.

## Objective

[90-research-hackerbot.md](90-research-hackerbot.md) researched how the field's serious 2026 LLM-driven pentesting tools structure themselves and resolved four open design questions (single coordinator, no shell/exec tool, MCP `elicitation`/`tasks` for approval, `Confidence` ≠ `Severity`) plus an eight-group backlog (A-H), later extended by [91-research-recon-phase.md](91-research-recon-phase.md) into a ninth group (R, recon). Scheduled across three phases: [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) (recon + task-tree/schema foundations, no MCP dependency), this phase (the MCP server, human-approval gate, and hard safety blockers — the part that's actually unsafe to skip once an agent exists), and [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) (hardening/ecosystem polish on top of a backbone this phase builds). **Nothing in Phase 7 should ship before this phase exists.**

**Ordering relative to Phase 4:** this phase comes *after* [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) (Prompt Injection/SSRF/Business Logic Flaws), not instead of it. Confirmed as a real dependency, not just a scheduling preference: doc90's `findings.export` MCP tool (Step 1 below) needs Phase 4 Step 4's `Exporter`/HackerOne-JSON work, which doesn't exist yet as of this writing (`pkg/reporter` today only has `WriteJSON`, confirmed against the actual tree). By the time this phase starts, Phase 4 will have shipped it.

**Ordering relative to Phase 5:** this phase depends directly on doc14's `ReconResult` schema and `Job.PlanTree` data model existing — Step 2 below seeds the coordinator's first `plan` proposal from a real `ReconResult`, and Step 3 wires `ReconResult.OutOfScope` into the scope-creep gate. Neither is buildable before doc14 ships.

## Scope

1. ⬜ **MCP server** (Weeks 41-42)
2. ⬜ **Approval gate + spend ceiling** (Week 43)
3. ⬜ **Hard safety blockers + scope-creep gate + cost-aware prioritization** (Weeks 44-45)
4. ⬜ **Approval UI: make the plan preview actionable** (Week 46)
5. ⬜ **Session log + release** (Weeks 47-48) — `v0.6.0`

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step actually lands, same convention as doc09-14.)

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **A peer-agent mesh of any kind** — Decision 1 (doc90) is a permanent architectural boundary, not a v1 limitation to relax later. A "specialized recon agent" or "specialized exploit agent" is not a future item on this backlog; it's the alternative doc90 evaluated and rejected. (Doc91's research reinforces this further — see doc14's Objective.)
- **Anything shell/exec-shaped in the MCP tool surface** — Decision 2, same permanence. A future "just let the agent run curl for this one edge case" request gets the same answer every other feature request in this project already gets: add a template or detector, don't add a raw-exec tool. Doc91's research found this is a genuinely conservative position relative to the field (every comparable tool researched gives its agent a shell) — see doc14's Objective for the full finding.
- **The full Web UI "Agent" tab with live SSE streaming** — deferred to Phase 7 Step 3 (doc90's C1, full version). This phase upgrades doc14's read-only Plan-preview page into an actionable approval surface (Step 4 below) and ships a structured, queryable session log (Step 5) — real, but the live reasoning-trace tab needs an approval mechanism to visualize, which doesn't fully exist until this phase's own Step 2.
- **OWASP Agentic Top 10 mapping (D4)** — deferred to Phase 7 Step 5; it's a review-and-document pass over a design that needs to actually exist first (this phase builds most of what D4 would be checking).

## Dependencies used in this plan

**New dependency, to be verified at Step 1 kickoff, not assumed here**: an MCP Go SDK. No MCP-related package exists in `go.mod` today. Candidates to check via pkg.go.dev at implementation time (current stable version, import count, maintenance activity, and specifically whether it supports the 2026-07-28 spec's `elicitation`/`tasks` primitives Decision 3 commits to) — same discipline the Phase 2 JWT library and Phase 4's candidate Interactsh client both followed: verify before adding, don't assume a package's maturity from this doc. If no sufficiently mature Go SDK supports `elicitation`/`tasks` yet, that is itself a real finding this step should surface and report honestly (see Step 1's Design), not paper over by hand-rolling a partial MCP implementation. This is precisely the risk this phase's split from doc14 was meant to isolate — a delay here no longer blocks doc14's recon/data-model work, which will already be done.

**No new dependency for Steps 2-5** — pure Go logic and additions to types doc14 already introduced (`Job.PlanTree`, `ReconResult`); a new `pkg/mcpserver` package calls straight into `pkg/scanner`/`pkg/template`/`pkg/reporter`/`pkg/recon`, duplicating no scan logic, the same boundary doc12 already drew for `pkg/webui`.

---

## Step 1: MCP Server (Weeks 41-42) — ⬜ not yet implemented

### Design

**A1 — `pkg/mcpserver/`**, exposing `scan`, `templates.list`, `templates.sync`, `findings.export`, `recon` (doc91's R4, new), and `plan` (built out fully in Step 2) as MCP tools. Calls straight into the existing `pkg/scanner`/`pkg/template`/`pkg/reporter`/`pkg/recon` packages — no scan logic duplicated, the same boundary doc12 already drew for `pkg/webui`. Consumes the same `Engine.WithFindingCallback`/`WithLogCallback` hooks `pkg/webui` already uses (doc90's A2, already landed in Phase 3) — the MCP server is a second frontend on the unchanged core, not a second implementation of it.

`findings.export` calls into Phase 4 Step 4's `Exporter` implementations (Markdown/HTML/HackerOne-JSON), which will exist by this point per the Objective's ordering decision — if for any reason Phase 4 Step 4 hasn't actually shipped by the time this step starts, `findings.export` ships JSON-only (reusing today's `reporter.WriteJSON`) and gains the other formats once they land, rather than blocking this whole step on it.

`recon` wraps doc14's `pkg/recon` the same way `scan` wraps `pkg/scanner` — schema-validated arguments (target, `--recon-depth`), not a free-form command, per doc91 §5's design constraint.

**Deliberately excludes anything shell/exec-shaped, per Decision 2** — this is the one place in the whole plan where "don't add a tool" is as important a design choice as "add a tool." Every path to a `Finding` still runs through the existing deterministic matcher/extractor engine; the agent selects targets/templates and interprets results, it never crafts a raw request the engine's matchers didn't already validate.

**First real task of this step, not assumed**: verify the MCP Go SDK candidate (see Dependencies above) actually supports `elicitation`/`tasks` per the 2026-07-28 spec before writing `plan`'s scaffolding — Step 2 builds directly on this.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/server.go` — MCP server setup, tool registration.
- `pkg/mcpserver/tools_scan.go` — `scan` tool, wired to `Engine.WithFindingCallback`/`WithLogCallback`.
- `pkg/mcpserver/tools_templates.go` — `templates.list`, `templates.sync`, calling `pkg/templatesync`.
- `pkg/mcpserver/tools_findings.go` — `findings.export`, calling `pkg/reporter`.
- `pkg/mcpserver/tools_recon.go` — `recon` tool, calling `pkg/recon` (doc14).
- `cmd/hackerfive/mcpserve.go` — new `hackerfive mcp-serve` (or similar) subcommand.
- `tests/unit/mcpserver_*_test.go` — schema-validated request/response tests per tool, no live target needed.

### Verification
Unit tests per tool against a mock/stub scanner config. A real MCP client (e.g. Claude Desktop or Claude Code configured against this server) can list and call `scan`/`templates.list`/`templates.sync`/`findings.export`/`recon` and get back structured JSON — live-verified before this step is marked done, not just unit-tested.

---

## Step 2: Approval Gate + Spend Ceiling (Week 43) — ⬜ not yet implemented

### Design

**B1 — `plan` MCP tool, built on native `elicitation`/`tasks`.** The agent proposes a full run (targets, detectors, templates, whether writes are required) and gets back a structured plan snapshot (doc14's `PlanTree`) in `input_required` state — no request sent yet. The human's approval is an `elicitation` response, captured natively by the transport rather than a plan-ID string HackerFive has to mint, store, and trust the agent not to replay. This is doc90's single highest-leverage item: today the CLI just executes, and there is currently no point where a human sees and approves a plan before traffic goes out.

**R5 — seed the plan from a real `ReconResult`.** The coordinator's *first* `plan` proposal is generated from doc14's `ReconResult` (matched against template tags per doc01's reward-to-effort priors), not from an empty or hand-authored tree — this is the concrete fix for doc90 Group H having no named source for `PlanTree`'s initial leaves, and the reason this step couldn't land before doc14 shipped.

**H5 — per-job spend ceiling**, sequenced alongside B1 per doc90's own note (a hard budget cap has a same-day reference implementation to copy — Strix's `--max-budget-usd` — so there's no reason to treat it as a stretch goal). A hard, enforced cap on cumulative agent-attributable cost (LLM token spend the coordinator itself reports, not HackerFive's own request cost) for a `Job` — exceeding it fails the job with a clear reason, it does not just log a warning.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/tools_plan.go` — `plan` tool, `elicitation` request/response handling, seeded from `pkg/recon`'s output.
- `pkg/webui/jobs.go` (or doc14's shared package) — `Job`/`PlanTree` gains a `SpendCeiling`/`SpendSoFar` pair; the coordinator reports spend increments via a new field on the MCP tool call metadata.
- `tests/unit/plan_tool_test.go` — approve/reject/timeout paths against a mock elicitation response, including a test confirming the initial tree is seeded from a `ReconResult` fixture, not empty.
- `tests/unit/spend_ceiling_test.go` — confirms a job hard-fails once the ceiling is crossed, not just logs.

### Verification
Unit tests for the elicitation round trip (mocked), the ReconResult-seeded initial plan, and the spend-ceiling hard-fail. Live verification: a real MCP client runs `recon` then proposes a plan, a human approves or rejects it via the client's own elicitation UI, and the server only proceeds on approval — confirmed against a real client, not just a mock.

---

## Step 3: Hard Safety Blockers + Scope-Creep Gate + Cost-Aware Prioritization (Weeks 44-45) — ⬜ not yet implemented

### Design

**D2 — program-policy pre-flight check, a hard blocker.** Before any agent-driven run against a real (non-lab) target, check the target's disclosure policy (via [22-authorized-targets.md](22-authorized-targets.md)'s registry, or a fetched `security.txt`/program policy — doc14's Wave 0 already fetches this during recon) for whether automated scanners are disallowed — refuse to proceed if so. This is the one item in doc90's whole backlog with a documented real-world cost of skipping it (XBOW's own program removal, doc90 §2) — implemented as a hard block, not a warning, unlike `--scope`'s existing softer treatment.

**D3 — hard-fail, not warn, on missing `--scope` for agent-initiated runs.** The CLI's existing "warn, don't silently proceed" behavior for a missing `--scope` (doc02 §3) is the right default for a human at a terminal who typed the command themselves; it's the wrong default for an agent-initiated `scan`/`recon` MCP tool call, where nobody read the warning. Both tools reject the call outright if `--scope`-equivalent isn't set, rather than proceeding with a stderr line nobody's watching.

**B4 — scope-creep gate, first implementation.** doc90's B4 requires fresh approval when a scan's own recon surfaces hosts/paths outside `--targets`/`--scope`; doc14's `ReconResult.OutOfScope` (doc91's R6) is the producer this gate has been missing. Concretely: if `pkg/recon` (via the `recon` tool, or a re-run mid-scan) populates `OutOfScope` with anything, the coordinator cannot silently fold those hosts into the working set — a second `elicitation` round trip (reusing Step 2's `plan` mechanism) is required before anything touches them. Phase 7 Step 2 rounds this out with audit-trail/documentation coverage; this is where the gate first actually exists and blocks something.

**H4 — cost/attempt-aware prioritization.** A per-leaf attempt counter and running spend tracker on doc14's `PlanTree`, applying MAPTA's own measured finding as a concrete rule: rising tool-call count, dollar cost, token count, and elapsed time on one leaf are each independently correlated with *falling* odds of success (r = −0.66, −0.61, −0.59, −0.56 per doc90 §2) — "still grinding after N attempts with no confidence increase" surfaces as a stop-and-escalate signal to the coordinator (via the leaf's `Status`), not a reason to allocate more budget to the same leaf.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/tools_scan.go`/`tools_recon.go` — D2/D3 checks added at the top of each tool handler, before any request is fired.
- `pkg/mcpserver/tools_plan.go` — B4's out-of-scope check and re-elicitation trigger.
- `pkg/agenttask/` (doc14's `PlanTree` location) — `PlanNode` gains `Attempts`, `Spend`, and the stop-and-escalate signal derived from H4's rule.
- `tests/unit/preflight_test.go` — D2 (policy-disallowed target rejected) and D3 (missing scope rejected, not warned) cases.
- `tests/unit/scope_creep_test.go` — a `ReconResult` fixture carrying `OutOfScope` entries triggers a fresh elicitation rather than proceeding.

### Verification
Unit tests for both hard-fail paths and the scope-creep trigger. Live verification for D2 needs a real target with a documented no-automated-scanners policy (or a synthetic one for test purposes) — confirm the block actually fires, don't assume from the code alone. Live verification for B4: a recon run against a target whose crawl surfaces a genuinely out-of-scope linked domain (doc91 Wave 3's own example) triggers re-approval before that domain is ever touched.

---

## Step 4: Approval UI — Make the Plan Preview Actionable (Week 46) — ⬜ not yet implemented

### Design

Doc14 Step 4 shipped a *read-only* Plan-preview page — useful for inspecting a `PlanTree` the coordinator built, but not yet a way to act on it. This step is where that page becomes the Web UI's own approval surface, for the case where a human is driving a session through HackerFive's own Web UI rather than (or in addition to) an external MCP host like Claude Desktop that renders its own `elicitation` dialog:

- **Approve / Reject / Edit controls per leaf and for the plan as a whole** — an `hx-post` action on the Plan-preview page that resolves the same `elicitation` response Step 2's `plan` tool is waiting on, so a human can approve from either surface (the MCP client's own UI, or HackerFive's Web UI) interchangeably.
- **A budget/spend gauge** against Step 2's `SpendCeiling`/`SpendSoFar` — a simple progress bar, not a new subsystem; the numbers already exist on `Job` by this step.
- **An explicit, always-reachable kill switch/pause control** — doc90's OWASP ASI10 mitigation names this as a requirement; this step is where it's actually built, not just referenced. A single button that cancels the job's context (the same `r.Context().Done()` mechanism doc12's SSE unsubscribe path already relies on) and is visible on every page a running job's status appears on, not buried in a menu.

### Files (anticipated, confirm at implementation time)
- `pkg/webui/handlers_plan.go` (new) or extend `handlers_scan.go` — approve/reject/edit endpoints resolving an `elicitation` response.
- `pkg/webui/templates/plan_preview.html` (doc14's page, extended) — action buttons, budget gauge, kill switch.
- `tests/unit/plan_ui_test.go` — approve/reject via HTTP produces the same effect as an MCP-client-side elicitation response.

### Verification
Live-verified against a real browser: approving a plan via the Web UI unblocks a session that's waiting on `elicitation`, exactly as approving via an MCP client's own UI would. The kill switch, clicked mid-scan, is confirmed to actually stop the job (no further findings/logs after the click), not just hide the UI.

---

## Step 5: Session Log + Release (Weeks 47-48) — ⬜ not yet implemented — `v0.6.0`

### Design

**C1 (minimal) — agent session log.** A structured, append-only record of every MCP tool call, the coordinator's stated reasoning for it (if the calling agent provides one — this is a courtesy field the tool schemas accept, not something HackerFive can force an agent to fill honestly), and the raw result. Persisted per job (reusing `Job`'s existing accumulation pattern from doc12). **Not yet the Web UI's live Agent tab** — that's Phase 7 Step 3's job; this step's deliverable is that the log exists, is queryable, and is complete, even if today it's only inspectable via a CLI dump or the MCP server's own `job.log` equivalent.

Full integration testing across Steps 1-4 together (a real MCP client running a recon → plan → approve → scan → findings.export round trip against a lab target), then release.

### Files (anticipated, confirm at implementation time)
- `pkg/agenttask/sessionlog.go` (or peer to `Job`) — the append-only log type.
- `tests/integration/agent_e2e_test.go` — full round trip against a lab target via a real or scripted MCP client.

### Verification
The full round trip (recon → plan proposal → human approval via elicitation or the Web UI → scan execution with live findings/logs → findings.export) works end-to-end against at least one lab target (crAPI or DVWA), live-verified, not just unit-tested piecewise.

---

## Definition of Done (Phase 6, Weeks 41-48)

- [ ] `pkg/mcpserver` exposes `scan`/`templates.list`/`templates.sync`/`findings.export`/`recon`/`plan` and nothing shell/exec-shaped; live-verified against a real MCP client
- [ ] The `plan` tool's human approval is captured via MCP `elicitation`, not a hand-rolled plan-ID flag; live-verified against a real client's own approval UI
- [ ] A coordinator's first `plan` proposal is demonstrably seeded from a real `ReconResult`, not an empty or hand-authored tree
- [ ] A per-job spend ceiling hard-fails a job when crossed, not just logs
- [ ] A program-policy pre-flight check (D2) hard-blocks an agent-driven run against a target whose disclosure policy disallows automated scanners
- [ ] A missing `--scope`-equivalent hard-fails an agent-initiated `scan`/`recon` tool call, distinct from the CLI's existing warn-only behavior for a human-typed command
- [ ] A discovered out-of-scope host actually populates `ReconResult.OutOfScope` and triggers a fresh `elicitation` round trip before it's touched, live-verified
- [ ] Cost/attempt-aware prioritization (H4) surfaces a stop-and-escalate signal on a `PlanTree` leaf after repeated low-yield attempts
- [ ] The Web UI's Plan-preview page supports Approve/Reject/Edit, a budget gauge, and an always-reachable kill switch that actually stops a running job
- [ ] A structured, persisted agent session log exists and is queryable per job, even without a live Web UI view yet
- [ ] A full recon → plan → approve → scan → export round trip is live-verified end-to-end against at least one lab target
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.6.0` tagged and released, or explicitly held with a stated reason

## See also
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — the recon package, `Finding`-schema freeze, and `PlanTree` foundations this phase builds on
- [90-research-hackerbot.md](90-research-hackerbot.md) — the research and backlog (Groups A-H) this plan schedules the MCP-server/approval half of
- [91-research-recon-phase.md](91-research-recon-phase.md) — Group R, the recon research this phase's Steps 1-3 wire into the MCP server and approval gate
- [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — the hardening/ecosystem/trust phase that follows this one
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — `Finding`/`Exporter`/`Engine` design this plan builds on
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-7 roadmap this plan is a slice of
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — the `WithFindingCallback`/`WithLogCallback` hooks and `Job` model this plan reuses and extends
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the `Exporter`/HackerOne-JSON work `findings.export` depends on, and the `--allow-writes` flag Phase 7's B2 attests to
- [22-authorized-targets.md](22-authorized-targets.md) — the registry D2's policy pre-flight check reads from
