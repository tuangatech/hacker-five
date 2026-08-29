# Phase 5 Implementation Plan — Weeks 33-40 (Agent Interface & Approval Backbone)

> Part of the [HackerFive documentation set](../README.md).

## Objective

[90-research-hackerbot.md](90-research-hackerbot.md) researched how the field's serious 2026 LLM-driven pentesting tools structure themselves and resolved four open design questions (single coordinator, no shell/exec tool, MCP `elicitation`/`tasks` for approval, `Confidence` ≠ `Severity`) plus an eight-group backlog (A-H). That doc was deliberately written ahead of a roadmap slot — this plan and [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) are where it gets one, split into two phases because the backlog is too large for one 8-week phase and splits cleanly along a real seam: **this phase is everything unsafe to skip — the MCP server, the human-approval gate, the task tree, and the hard safety blockers. Nothing in Phase 6 should ship before this phase exists**, because Phase 6 is hardening and polish on top of a backbone that doesn't yet exist without this phase.

**Ordering relative to Phase 4:** this phase comes *after* [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) (Prompt Injection/SSRF/Business Logic Flaws), not instead of it and not swapped ahead of it the way Phase 3 swapped ahead of Phase 4 once before. Confirmed as a real dependency, not just a scheduling preference: doc90's `findings.export` MCP tool (Step 2 below) needs Phase 4 Step 4's `Exporter`/HackerOne-JSON work, which doesn't exist yet (`pkg/reporter` today only has `WriteJSON`, confirmed against the actual tree). By the time this phase starts, Phase 4 will have shipped it.

**Real architectural finding from cross-checking doc90 against the actual codebase, not transcribed blind:** doc90's Decision 4 and its Group H items (H2/H3) assumed `Finding.Confidence` doesn't exist yet and proposed adding it as "the field the agent does get to set." **It already exists** (`pkg/detectors/types.go`): `Finding.Confidence string` — `"high"` for cross-account baseline evidence, `"low"` for a single-account heuristic needing manual triage — and it's already detector-set, not agent-writable, exactly like `Severity`. Doc90's underlying goal (agent-writable confidence, distinct from deterministic severity) is still correct, but the field must not be `Finding.Confidence` — that name is taken and already carries a different, narrower meaning (evidence quality of the match, not the agent's success-probability estimate for a candidate it hasn't run yet). This plan's Step 1 puts the agent-set, Cyber-AutoAgent-banded confidence on the task-tree leaf (`PlanTree` node, not `Finding`) instead — see Step 1 below. This is, if anything, a stronger version of Decision 4 than doc90 drafted: *two* `Finding` fields (`Severity` and `Confidence`) are already deterministic and agent-proof, not one.

## Scope

1. ⬜ **Foundations: ratify design decisions + eval harness stub** (Week 33)
2. ⬜ **Finding schema freeze + task-tree data model** (Weeks 34-35)
3. ⬜ **MCP server** (Weeks 36-37)
4. ⬜ **Approval gate + spend ceiling** (Week 38)
5. ⬜ **Hard safety blockers + cost-aware prioritization** (Week 39)
6. ⬜ **Session log + release** (Week 40) — `v0.5.0`

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step actually lands, same convention as doc09-13.)

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **A peer-agent mesh of any kind** — Decision 1 (doc90) is a permanent architectural boundary, not a v1 limitation to relax later. A "specialized recon agent" or "specialized exploit agent" is not a future item on this backlog; it's the alternative doc90 evaluated and rejected.
- **Anything shell/exec-shaped in the MCP tool surface** — Decision 2, same permanence. A future "just let the agent run curl for this one edge case" request gets the same answer every other feature request in this project already gets: add a template or detector, don't add a raw-exec tool.
- **The full Web UI "Agent" tab with live SSE streaming** — deferred to Phase 6 Step 3 (doc90's C1, full version). This phase ships only a structured, queryable session log (Step 5) — real, but not yet rendered live in the browser.
- **`AllowWrites` attestation (doc90 B2), HackerOne submission policy doc (B3), scope-creep gate (B4)** — deferred to Phase 6 Step 2; B2 specifically needs Phase 4's `--allow-writes` flag to exist as something to attest *to*, which by this phase's start it will, but the attestation mechanism itself is grouped with Phase 6's other approval-rounding work, not split across two phases.
- **OWASP Agentic Top 10 mapping (D4)** — deferred to Phase 6 Step 5; it's a review-and-document pass over a design that needs to actually exist first (this phase builds most of what D4 would be checking).

## Dependencies used in this plan

**New dependency, to be verified at Step 2 kickoff, not assumed here**: an MCP Go SDK. No MCP-related package exists in `go.mod` today. Candidates to check via pkg.go.dev at implementation time (current stable version, import count, maintenance activity, and specifically whether it supports the 2026-07-28 spec's `elicitation`/`tasks` primitives Decision 3 commits to) — same discipline the Phase 2 JWT library and Phase 4's candidate Interactsh client both followed: verify before adding, don't assume a package's maturity from this doc. If no sufficiently mature Go SDK supports `elicitation`/`tasks` yet, that is itself a real finding this step should surface and report honestly (see Step 2's Design), not paper over by hand-rolling a partial MCP implementation.

**No new dependency for Steps 1, 4, 5, 6** — pure Go logic and additions to existing types (`detectors.Finding` stays unchanged per the finding above; `pkg/webui/jobs.go`'s `Job` struct gains fields; a new `pkg/mcpserver` package calls straight into `pkg/scanner`/`pkg/template`/`pkg/reporter`, duplicating no scan logic, the same boundary doc12 already drew for `pkg/webui`).

---

## Step 1: Foundations — Ratify Design Decisions + Eval Harness Stub (Week 33) — ⬜ not yet implemented

### Design

No code changes to `pkg/scanner`/`pkg/detectors` this week — this step is deliberately sequenced first per doc90's own sequencing note ("G1 first, even before A1/B1: without it, every claim this effort makes about agent quality is unfalsifiable from day one").

- **Ratify Decisions 1-4** as committed project design, recorded in this doc (not re-litigated per step): single coordinator (no peer-agent mesh), no shell/exec-shaped MCP tool, MCP `elicitation`/`tasks` for approval, and the corrected Decision 4 (task-tree-leaf `Confidence`, not `Finding.Confidence` — see Objective above).
- **G1 — eval harness stub.** A minimal, scriptable harness that runs the *existing* CLI (no agent yet — there's nothing to evaluate an agent against until Step 2 exists) against the lab targets already used throughout this project (crAPI, DVWA, vAPI, Juice Shop, per [20-setup-testing-targets.md](20-setup-testing-targets.md)) and records a fixed challenge set with a binary pass/fail per challenge — modeled on the MAPTA/Cyber-AutoAgent published discipline doc90 cites, not a bespoke rubric invented here. This stub's job in Phase 5 is narrow: prove the harness itself works and produces a baseline (today's detector-only fp/fn rate) before an agent is introduced in later steps. Phase 6 Step 7 (G1 maturity) extends this into the actual agent-driven benchmark.

### Files (anticipated, confirm at implementation time)
- `tests/eval/` — new directory: a fixed challenge manifest (target + expected finding, per lab app) and a runner script/Go test that invokes `hackerfive scan` and checks output against the manifest.
- `docs/90-research-hackerbot.md` — status line updated to point at this plan (already scheduled once this doc exists; see the doc-wide update below).

### Verification
The stub runs against all four lab targets and produces a baseline pass/fail report with zero agent involvement — this is what Phase 6 Step 7 will later run again with an agent driving the scan, to get a real before/after delta.

---

## Step 2: Finding Schema Freeze + Task-Tree Data Model (Weeks 34-35) — ⬜ not yet implemented

### Design

**A3 — freeze and version the `Finding` JSON schema.** Publish `docs/schema/finding.schema.json` reflecting the actual current struct (`ID`, `Type`, `Severity`, `Confidence`, `Target`, `Description`, `Evidence` — `pkg/detectors/types.go`), explicitly annotated in the schema's own description fields that `Severity` and `Confidence` are both detector-set and never agent-writable (the corrected Decision 4 from this doc's Objective). This must land *before* Step 3's MCP server ships, per doc90's own sequencing note — an external MCP client should never depend on a wire shape that changes after the fact.

**H2 — `Job.PlanTree`.** Extend the existing `Job` struct (`pkg/webui/jobs.go`) — or a new shared type under a package both `pkg/mcpserver` and `pkg/webui` import, if the MCP server needs it independent of a browser session — with a PTT-shaped tree: each node is a candidate `(target, detector/template)` pairing with a `Status` and a `Rationale` string (why the coordinator picked this candidate). **Mutations are restricted to leaves** — any update that changes the tree's shape (add/remove/reparent a node) is rejected, mirroring PentestGPT's own defense (doc90 §2) against a hallucinated rewrite of the overall plan. Streamed over the same SSE channel `Job.Findings`/`Job.Logs` already use once Phase 6 wires the UI — this phase only needs the data structure and its mutation-guard to exist and be tested, not the live rendering.

**H3 (corrected) — leaf-level `Confidence` bands, on `PlanTree` leaves, not on `Finding`.** Each leaf carries a `Confidence` value the coordinator sets and updates as it gathers evidence, banded per Cyber-AutoAgent's convention as a starting point: High (>80%), Medium (50-80%), Low (<50%). This is the agent's own success-probability estimate for *attempting* a candidate — it never touches a `Finding` once one is actually produced; `Finding.Confidence`/`Finding.Severity` stay exactly as they are today, both deterministic.

### Files (anticipated, confirm at implementation time)
- `docs/schema/finding.schema.json` — new, frozen/versioned schema.
- `pkg/webui/jobs.go` (or a new `pkg/agenttask/` package if MCP-server-and-webui sharing turns out to need its own home) — `PlanTree`/`PlanNode` types, `Confidence` band type, leaf-only mutation guard.
- `tests/unit/plantree_test.go` — including a test asserting a shape-changing mutation (not touching only a leaf) is rejected.

### Verification
Unit tests: schema round-trips real `Finding` values from each existing detector (`idor`/`misconfig`/`authbypass`) without loss; `PlanTree` mutation tests cover both the allowed (leaf update) and rejected (shape change) cases.

---

## Step 3: MCP Server (Weeks 36-37) — ⬜ not yet implemented

### Design

**A1 — `pkg/mcpserver/`**, exposing `scan`, `templates.list`, `templates.sync`, `findings.export`, and `plan` (the last built out fully in Step 4) as MCP tools. Calls straight into the existing `pkg/scanner`/`pkg/template`/`pkg/reporter` packages — no scan logic duplicated, the same boundary doc12 already drew for `pkg/webui`. Consumes the same `Engine.WithFindingCallback`/`WithLogCallback` hooks `pkg/webui` already uses (doc90's A2, already landed in Phase 3) — the MCP server is a second frontend on the unchanged core, not a second implementation of it.

`findings.export` calls into Phase 4 Step 4's `Exporter` implementations (Markdown/HTML/HackerOne-JSON), which will exist by this point per the Objective's ordering decision — if for any reason Phase 4 Step 4 hasn't actually shipped by the time this step starts, `findings.export` ships JSON-only (reusing today's `reporter.WriteJSON`) and gains the other formats once they land, rather than blocking this whole step on it.

**Deliberately excludes anything shell/exec-shaped, per Decision 2** — this is the one place in the whole plan where "don't add a tool" is as important a design choice as "add a tool." Every path to a `Finding` still runs through the existing deterministic matcher/extractor engine; the agent selects targets/templates and interprets results, it never crafts a raw request the engine's matchers didn't already validate.

**First real task of this step, not assumed**: verify the MCP Go SDK candidate (see Dependencies above) actually supports `elicitation`/`tasks` per the 2026-07-28 spec before writing `plan`'s scaffolding — Step 4 builds directly on this.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/server.go` — MCP server setup, tool registration.
- `pkg/mcpserver/tools_scan.go` — `scan` tool, wired to `Engine.WithFindingCallback`/`WithLogCallback`.
- `pkg/mcpserver/tools_templates.go` — `templates.list`, `templates.sync`, calling `pkg/templatesync`.
- `pkg/mcpserver/tools_findings.go` — `findings.export`, calling `pkg/reporter`.
- `cmd/hackerfive/mcpserve.go` — new `hackerfive mcp-serve` (or similar) subcommand.
- `tests/unit/mcpserver_*_test.go` — schema-validated request/response tests per tool, no live target needed.

### Verification
Unit tests per tool against a mock/stub scanner config. A real MCP client (e.g. Claude Desktop or Claude Code configured against this server) can list and call `scan`/`templates.list`/`templates.sync`/`findings.export` and get back structured JSON — live-verified before this step is marked done, not just unit-tested.

---

## Step 4: Approval Gate + Spend Ceiling (Week 38) — ⬜ not yet implemented

### Design

**B1 — `plan` MCP tool, built on native `elicitation`/`tasks`.** The agent proposes a full run (targets, detectors, templates, whether writes are required) and gets back a structured plan snapshot (Step 2's `PlanTree`) in `input_required` state — no request sent yet. The human's approval is an `elicitation` response, captured natively by the transport rather than a plan-ID string HackerFive has to mint, store, and trust the agent not to replay. This is doc90's single highest-leverage item: today the CLI just executes, and there is currently no point where a human sees and approves a plan before traffic goes out.

**H5 — per-job spend ceiling**, sequenced alongside B1 per doc90's own note (a hard budget cap has a same-day reference implementation to copy — Strix's `--max-budget-usd` — so there's no reason to treat it as a stretch goal). A hard, enforced cap on cumulative agent-attributable cost (LLM token spend the coordinator itself reports, not HackerFive's own request cost) for a `Job` — exceeding it fails the job with a clear reason, it does not just log a warning.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/tools_plan.go` — `plan` tool, `elicitation` request/response handling.
- `pkg/webui/jobs.go` (or Step 2's shared package) — `Job`/`PlanTree` gains a `SpendCeiling`/`SpendSoFar` pair; the coordinator reports spend increments via a new field on the MCP tool call metadata.
- `tests/unit/plan_tool_test.go` — approve/reject/timeout paths against a mock elicitation response.
- `tests/unit/spend_ceiling_test.go` — confirms a job hard-fails once the ceiling is crossed, not just logs.

### Verification
Unit tests for both the elicitation round trip (mocked) and the spend-ceiling hard-fail. Live verification: a real MCP client proposes a plan, a human approves or rejects it via the client's own elicitation UI, and the server only proceeds on approval — confirmed against a real client, not just a mock.

---

## Step 5: Hard Safety Blockers + Cost-Aware Prioritization (Week 39) — ⬜ not yet implemented

### Design

**D2 — program-policy pre-flight check, a hard blocker.** Before any agent-driven run against a real (non-lab) target, check the target's disclosure policy (via [22-authorized-targets.md](22-authorized-targets.md)'s registry, or a fetched `security.txt`/program policy) for whether automated scanners are disallowed — refuse to proceed if so. This is the one item in doc90's whole backlog with a documented real-world cost of skipping it (XBOW's own program removal, doc90 §2) — implemented as a hard block, not a warning, unlike `--scope`'s existing softer treatment.

**D3 — hard-fail, not warn, on missing `--scope` for agent-initiated runs.** The CLI's existing "warn, don't silently proceed" behavior for a missing `--scope` (doc02 §3) is the right default for a human at a terminal who typed the command themselves; it's the wrong default for an agent-initiated `scan` MCP tool call, where nobody read the warning. The `scan` tool (Step 3) rejects the call outright if `--scope`-equivalent isn't set, rather than proceeding with a stderr line nobody's watching.

**H4 — cost/attempt-aware prioritization.** A per-leaf attempt counter and running spend tracker on `PlanTree` (Step 2), applying MAPTA's own measured finding as a concrete rule: rising tool-call count, dollar cost, token count, and elapsed time on one leaf are each independently correlated with *falling* odds of success (r = −0.66, −0.61, −0.59, −0.56 per doc90 §2) — "still grinding after N attempts with no confidence increase" surfaces as a stop-and-escalate signal to the coordinator (via the leaf's `Status`), not a reason to allocate more budget to the same leaf.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/tools_scan.go` — D2/D3 checks added at the top of the `scan` tool handler, before any request is fired.
- `pkg/agenttask/` (or Step 2's location) — `PlanNode` gains `Attempts`, `Spend`, and the stop-and-escalate signal derived from H4's rule.
- `tests/unit/preflight_test.go` — D2 (policy-disallowed target rejected) and D3 (missing scope rejected, not warned) cases.

### Verification
Unit tests for both hard-fail paths. Live verification for D2 needs a real target with a documented no-automated-scanners policy (or a synthetic one for test purposes) — confirm the block actually fires, don't assume from the code alone.

---

## Step 6: Session Log + Release (Week 40) — ⬜ not yet implemented — `v0.5.0`

### Design

**C1 (minimal) — agent session log.** A structured, append-only record of every MCP tool call, the coordinator's stated reasoning for it (if the calling agent provides one — this is a courtesy field the tool schemas accept, not something HackerFive can force an agent to fill honestly), and the raw result. Persisted per job (reusing `Job`'s existing accumulation pattern from doc12). **Not yet the Web UI's live Agent tab** — that's Phase 6 Step 3's job; this step's deliverable is that the log exists, is queryable, and is complete, even if today it's only inspectable via a CLI dump or the MCP server's own `job.log` equivalent.

Full integration testing across Steps 1-5 together (a real MCP client running a plan → approve → scan → findings.export round trip against a lab target), then release.

### Files (anticipated, confirm at implementation time)
- `pkg/agenttask/sessionlog.go` (or peer to `Job`) — the append-only log type.
- `tests/integration/agent_e2e_test.go` — full round trip against a lab target via a real or scripted MCP client.

### Verification
The full round trip (plan proposal → human approval via elicitation → scan execution with live findings/logs → findings.export) works end-to-end against at least one lab target (crAPI or DVWA), live-verified, not just unit-tested piecewise.

---

## Definition of Done (Phase 5, Weeks 33-40)

- [ ] Design Decisions 1-4 (with the Objective's correction to Decision 4) are recorded as committed design, not open questions
- [ ] `tests/eval/` runs a fixed, MAPTA/Cyber-AutoAgent-style challenge set against the lab targets with zero agent involvement, producing a baseline pass/fail report
- [ ] `docs/schema/finding.schema.json` is published and frozen before the MCP server ships; it documents `Severity`/`Confidence` as detector-set, never agent-writable
- [ ] `Job.PlanTree` (or its dedicated package) exists, mutates only at leaves, and a shape-changing mutation is rejected and tested
- [ ] Leaf-level `Confidence` bands (High/Medium/Low) exist on `PlanTree` nodes — distinct from, and never propagated into, `Finding.Confidence`/`Finding.Severity`
- [ ] `pkg/mcpserver` exposes `scan`/`templates.list`/`templates.sync`/`findings.export`/`plan` and nothing shell/exec-shaped; live-verified against a real MCP client
- [ ] The `plan` tool's human approval is captured via MCP `elicitation`, not a hand-rolled plan-ID flag; live-verified against a real client's own approval UI
- [ ] A per-job spend ceiling hard-fails a job when crossed, not just logs
- [ ] A program-policy pre-flight check (D2) hard-blocks an agent-driven run against a target whose disclosure policy disallows automated scanners
- [ ] A missing `--scope`-equivalent hard-fails an agent-initiated `scan` tool call, distinct from the CLI's existing warn-only behavior for a human-typed command
- [ ] Cost/attempt-aware prioritization (H4) surfaces a stop-and-escalate signal on a `PlanTree` leaf after repeated low-yield attempts
- [ ] A structured, persisted agent session log exists and is queryable per job, even without a live Web UI view yet
- [ ] A full plan → approve → scan → export round trip is live-verified end-to-end against at least one lab target
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.5.0` tagged and released, or explicitly held with a stated reason

## See also
- [90-research-hackerbot.md](90-research-hackerbot.md) — the research and backlog (Groups A-H) this plan schedules the unsafe-to-skip half of
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — the hardening/ecosystem/trust half that follows this phase
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — `Finding`/`Exporter`/`Engine` design this plan builds on
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-6 roadmap this plan is a slice of
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — the `WithFindingCallback`/`WithLogCallback` hooks and `Job` model this plan reuses and extends
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the `Exporter`/HackerOne-JSON work `findings.export` depends on, and the `--allow-writes` flag Phase 6's B2 attests to
- [22-authorized-targets.md](22-authorized-targets.md) — the registry D2's policy pre-flight check reads from
