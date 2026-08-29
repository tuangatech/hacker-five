# Phase 7 Implementation Plan — Weeks 49-56 (Agent Hardening, Ecosystem & Trust)

> Part of the [HackerFive documentation set](../README.md).

**Renumbered from "Phase 6" during the 2026-08-29 recon-phase restructuring** (see [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)'s Objective for the full reasoning): recon and the task-tree/`PlanTree` data model were split out into their own Phase 5 (no MCP dependency), pushing the MCP server/approval-gate work to Phase 6 and this hardening phase to Phase 7. This doc's content is otherwise unchanged from the original Phase 6 draft — only phase/week numbers and the step cross-references they depend on were corrected.

## Objective

[15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) builds the unsafe-to-skip backbone: the MCP server, the `elicitation`-based approval gate, the task tree wired to a live coordinator, and the hard safety blockers (program-policy pre-flight, hard-fail scope). This phase is everything [90-research-hackerbot.md](90-research-hackerbot.md)'s backlog still needs on top of that backbone to reach its own stated Definition of Done — rounding out approval coverage (`AllowWrites` attestation, scope-creep), upgrading observability from a queryable log into a live Web UI view, running the OWASP Agentic Top 10 mapping against a design that, by this point, actually exists, and closing out the template-ecosystem and eval-maturity items that don't block a first agent session but do block calling the feature actually trustworthy.

**This phase depends on Phase 6 existing, not the other way around** — every step below assumes `pkg/mcpserver`, a live `Job.PlanTree`, and the `plan`/`elicitation` approval flow are already in place. It also depends on Phase 5's recon package and read-only Plan-preview UI existing, transitively through Phase 6.

## Scope

1. ⬜ **Tool surface completion** (Week 49)
2. ⬜ **Approval & compliance rounding** (Week 50)
3. ⬜ **Observability upgrade: live Agent tab** (Weeks 51-52)
4. ⬜ **Live log injection + concurrency ceilings** (Week 53)
5. ⬜ **OWASP Agentic Top 10 mapping** (Week 54)
6. ⬜ **Template ecosystem & triage support** (Week 55)
7. ⬜ **Eval maturity + release** (Week 56) — `v0.7.0`

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step actually lands, same convention as doc09-15.)

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **A general-purpose logic engine for business-logic templates, or any other scope-expansion of Phase 4's detectors** — this phase is agent-integration hardening, not new vulnerability classes.
- **A fully generic template-authoring DSL for agent-proposed templates** — E2 below is a staging *directory* with human promotion, not an automated review/merge pipeline.
- **Multi-tenant / hosted-agent-service mode** — doc12's local-only architecture decision (loopback-first, no hosted SaaS) applies to the MCP server exactly as it applies to the Web UI; not revisited here.

## Dependencies used in this plan

**No new dependency for any step in this plan.** Everything here extends types and packages Phase 5/6 (or earlier phases) already introduced: `pkg/mcpserver`, `pkg/webui`, `pkg/agenttask` (wherever Phase 5 Step 2 landed `PlanTree`), `pkg/templatesync`. The OWASP mapping (Step 5) is a documentation/review pass, not code. If Step 7's benchmark run surfaces a need for something beyond stdlib (e.g. statistical reporting beyond simple pass/fail counts), verify via pkg.go.dev at that point rather than assuming here — same discipline as every prior phase.

---

## Step 1: Tool Surface Completion (Week 49) — ⬜ not yet implemented

### Design

**A4 — `hackerfive templates list --json`.** Expose the same tag/severity/category data doc12/Week 19 already extract for the Web UI's Templates page, as machine-readable JSON on the CLI directly — useful for any caller (agent or otherwise) that wants template metadata without going through the MCP server's `templates.list` tool.

**A5 — tool-list scoping.** Per OWASP's "least agency" principle: an MCP session shouldn't necessarily see every tool Phase 6's `pkg/mcpserver` registers, regardless of what it's doing. A read-only "triage this scan's findings" session and a "plan and (pending approval) run writes-capable business-logic checks" session are different agency levels and should get different tool lists from the server at session-init time, not the same list gated only by a runtime check inside each tool handler. Concretely: the MCP server gains a session-scope concept (e.g. `readonly` vs. `full`) set at connection time, and tool registration/listing filters against it — a `readonly` session never even sees `scan`'s write-capable parameters or `plan`'s approval flow for anything beyond read-only detectors.

### Files (anticipated, confirm at implementation time)
- `cmd/hackerfive/templates.go` — `--json` flag on the existing `templates list` subcommand.
- `pkg/mcpserver/server.go` — session-scope concept, tool-list filtering at connection/listing time.
- `tests/unit/templates_json_test.go`, `tests/unit/mcpserver_scoping_test.go`.

### Verification
Unit tests confirming a `readonly`-scoped session's tool list omits write-capable tool parameters/tools entirely (not just rejects them at call time). Live verification: connect two MCP client sessions with different declared scopes, confirm each sees a different tool list.

---

## Step 2: Approval & Compliance Rounding (Week 50) — ⬜ not yet implemented

### Design

**B2 — turn `AllowWrites` into an attested approval, not a bare boolean.** By this phase, Phase 4's `--allow-writes` flag exists (`scanner.Config.AllowWrites`, doc13 Step 3) and Phase 6's `plan`/`elicitation` flow exists. This step wires them together: the `scan` MCP tool only honors a write-capable business-logic check when the request carries an approval grant tied to a `plan` the human already reviewed via Phase 6's approval gate — an `elicitation` grant, not a self-asserted flag. **No process, including the agent itself, can set `AllowWrites` for its own call in the same breath it decided it wanted to** — this holds by construction (the grant comes from a separate elicitation round trip the agent doesn't control the content of), not by convention.

**B3 — document HackerOne submission as a permanent architectural invariant**, not a Phase-4-scoped decision: the `findings.export` tool (Phase 6) and the HackerOne `Exporter` (doc13 Step 4) produce a *draft* report a human reviews and submits — this doc states explicitly, for the record, that no code path in this project will ever call HackerOne's submission endpoint without a human clicking submit, regardless of how capable an agent orchestrating the rest of the flow becomes. Worth stating plainly given HackerOne's own CEO had to publicly clarify agentic-feature boundaries after a February 2026 researcher backlash (doc90 §3) — HackerFive holds itself to the same bar preemptively, in writing, before it's ever tested by an incident.

**B4 — scope-creep gate.** By this phase, Phase 6 has already wired `ReconResult.OutOfScope` into a first version of this gate; this step is the compliance-rounding pass over it (Web UI audit-trail entries, documentation) rather than the gate's first implementation.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/tools_scan.go` — `AllowWrites` gated on an elicitation grant reference, not a request-body boolean.
- `docs/05-hackerone-and-legal.md` — B3's invariant statement added.
- `tests/unit/allowwrites_attestation_test.go`.

### Verification
Unit tests: a `scan` call carrying `AllowWrites=true` without a valid elicitation grant reference is rejected. Live verification against a real MCP client.

---

## Step 3: Observability Upgrade — Live Agent Tab (Weeks 51-52) — ⬜ not yet implemented

### Design

**C1 (full) — Web UI "Agent" tab.** Phase 6's session log is structured and persisted but only queryable after the fact; this step renders it live in `pkg/webui`, over the same SSE mechanism the existing Scan Status page already uses (doc12) — a new `sse-swap="agent-event"` stream alongside the existing `finding`/`log`/`progress` events, so a human watching a running agent session sees each MCP tool call, its stated reasoning, and its result appear as they happen, not only in a post-hoc log dump. This is, per doc90 §2's most load-bearing lesson (the Thacker/xssdoctor team's own framing), the single highest-leverage item in this entire phase: the difference between a useful hacking agent and an expensive hallucination machine was observability, not model quality or tool count. It's deliberately sequenced here, not earlier: Phase 5 built a read-only Plan-preview page and Phase 6 made it an actionable approval surface, so by this step there's an approval mechanism worth visualizing live — building this tab any earlier would have nothing real to stream.

**C2 — extend the audit trail doc12 already specifies for the Web UI's authorization checkbox** to also capture agent-specific facts: which MCP session initiated a job, what scope/plan was approved and when, and the elicitation grant references B2 introduced.

**C3 — evidence-linked claims.** No agent-drafted report text (via `findings.export` or any future report-drafting surface) without a citation to a specific `Finding.ID` and its evidence — enforced at the exporter level (a draft referencing an ID that doesn't exist in the job's finding set is rejected), not just a style guideline for prompts.

### Files (anticipated, confirm at implementation time)
- `pkg/webui/handlers_scan.go` — new `agent-event` SSE stream on `/scans/{id}/events`.
- `pkg/webui/templates/scan_status.html` — Agent tab markup.
- `pkg/webui/auditlog.go` (or extend the existing authorization-checkbox log site) — C2's extra fields.
- `pkg/reporter/` — C3's citation-enforcement check on export.
- `tests/unit/agent_tab_test.go`, `tests/unit/audit_trail_agent_test.go`, `tests/unit/evidence_citation_test.go`.

### Verification
Live-verified against a real browser: a running agent session's tool calls and reasoning appear in the Agent tab in real time, matching the persisted session log exactly. Unit test confirms an export referencing a nonexistent `Finding.ID` is rejected.

---

## Step 4: Live Log Injection + Concurrency Ceilings (Week 53) — ⬜ not yet implemented

### Design

**C4 — live log injection (stretch).** The Thacker/xssdoctor build (doc90 §2) supports typing directly into a running worker's log to redirect it mid-task without stopping it. A text box on the Agent tab (Step 3) that appends an operator note into the coordinator's next reasoning turn — cheap to add once C1 exists, and directly useful for the "it got distracted, nudge it" scenario doc90 cites as a real, repeatedly-observed need. Lowest priority in this step; descope first if the week runs short.

**D1 — per-detector concurrency ceilings.** Distinct from Phase 4's prompt-injection-specific concurrency guardrail (doc13 Step 1, a stderr warning) — this is a general ceiling the coordinator's `scan` tool calls respect per detector type, so an agent driving many parallel `scan` calls across a session can't collectively exceed a safe aggregate concurrency against one target even if each individual call's `--concurrency` looks reasonable in isolation.

### Files (anticipated, confirm at implementation time)
- `pkg/webui/templates/scan_status.html` — C4's injection text box + `hx-post` wiring.
- `pkg/mcpserver/tools_scan.go` (or a session-level tracker) — D1's aggregate concurrency accounting across concurrent `scan` calls in one session.
- `tests/unit/concurrency_ceiling_test.go`.

### Verification
Unit test: two concurrent `scan` tool calls in the same session against the same target are throttled to the aggregate ceiling, not each independently allowed full concurrency. C4 live-verified by hand: an injected note visibly changes the coordinator's next action in a real session.

---

## Step 5: OWASP Agentic Top 10 Mapping (Week 54) — ⬜ not yet implemented

### Design

**D4.** OWASP published a peer-reviewed Top 10 for agentic applications in December 2025 (ASI01-ASI10). Doc90 §3 Group D already sketches HackerFive-specific mitigations for each risk against the *design*; this step re-walks that same table against the *actual shipped Phase 5-7 code* and records the result — mitigated (cite the file/mechanism), or explicitly accepted as residual risk with a stated reason — matching this project's own "revise down with reasoning, don't pad" discipline. Concretely, confirm or correct each row doc90 already drafted:

| ASI risk | Doc90's proposed mitigation | Confirm against real code |
|---|---|---|
| ASI01 Agent Goal Hijack | Untrusted target data, never instructions; D3 hard-fail on missing scope | `pkg/mcpserver/tools_scan.go`'s D3 check (Phase 6 Step 3) |
| ASI02 Tool Misuse & Exploitation | Decision 2 (no shell/exec tool) + schema-validated tools | `pkg/mcpserver` tool registrations (Phase 6 Step 1) |
| ASI03 Identity & Privilege Abuse | Short-lived, per-call credentials, never baked into agent context | Confirm `--auth-token`-equivalent handling in `tools_scan.go` doesn't persist beyond one call |
| ASI04 Agentic Supply Chain Vulnerabilities | Pinned-commit template sync + E2's staging directory | `pkg/templatesync` (existing) + Step 6's `templates/proposed/` (this phase) |
| ASI05 Unexpected Code Execution | No code-execution tool exists | Confirm against the final Phase 6 tool list |
| ASI06 Memory & Context Poisoning | `PlanTree` is durable, refreshed state, not open-ended memory | `pkg/agenttask` (Phase 5 Step 2) |
| ASI07 Insecure Inter-Agent Communication | Moot — single coordinator, no peer-agent channel | Confirm no peer-agent code was introduced anywhere in Phases 5-7 |
| ASI08 Cascading Agent Failures | Host-error-cache circuit breaker + spend/attempt ceiling | Existing `pkg/scanner/hosterrors` + Phase 6 Step 2's `H5`/Step 3's `H4` |
| ASI09 Human-Agent Trust Exploitation | Approvals only via audited Web UI controls or MCP `elicitation`, never the agent's own conversational assertion | Phase 6 Step 2's `plan` tool + this phase's Step 2 (`B2`) |
| ASI10 Rogue Agents | Kill switch/pause (Agent tab) + policy pre-flight hard blocker | Step 3's Agent tab (does it need an explicit pause/cancel action? confirm and add if missing) + Phase 6 Step 3's `D2` |

### Files (anticipated, confirm at implementation time)
- `docs/90-research-hackerbot.md` — D4's row updated from "proposed mitigation" to "confirmed against `<file>`" or "residual risk: `<reason>`" per row.

### Verification
Every row in the table above is checked against real code (a file path and line, not a restated intention) and recorded with either a confirmation or a stated residual-risk reason. Pay particular attention to ASI10 — if the Agent tab (Step 3) doesn't yet have an explicit pause/cancel control, add one during this step rather than recording ASI10 as mitigated when it isn't.

---

## Step 6: Template Ecosystem & Triage Support (Week 55) — ⬜ not yet implemented

### Design

**E1 — generated `templates/index.json`.** A machine-readable index of every loaded template's `info:` metadata (name/severity/tags/description) plus source (bundled/synced), generated at `templates sync`/`templates list` time — gives an agent (or A4's `--json` output) one flat file to reason over instead of parsing individual YAML files.

**E2 — agent-proposed templates land in `templates/proposed/`**, never directly in a trusted path (`./templates/` or the synced directory). A future "agent drafts a new detection template based on what it observed" capability — not built in this phase, but the staging convention is: any such template is written only to `templates/proposed/`, requires explicit human promotion (a file move, or a `hackerfive templates promote <name>` command if that turns out to be worth building) before it's ever loaded into a real scan.

**F1 — triage-assist mode on the existing `Exporter` output.** A mode that annotates exported findings with the agent's own triage notes (severity-context, likely false-positive flags) as a clearly-labeled *additional* field, never altering the underlying deterministic `Finding.Severity`/`Confidence` — consistent with this phase's repeated theme of agent output being additive/advisory, never authoritative over detector-set fields.

**F2 — structured feedback capture.** When a human overrides or dismisses an agent-surfaced finding/triage note during review, capture that decision in a structured, queryable form (not just "the user closed the tab") — useful raw material for Step 7's eval-maturity work and any future tuning of the coordinator's own prioritization logic.

### Files (anticipated, confirm at implementation time)
- `pkg/templatesync/index.go` — E1's `templates/index.json` generation.
- `templates/proposed/` — new, empty (gitkept) directory; `pkg/template` loader confirmed to never auto-load from it.
- `pkg/reporter/triageassist.go` — F1's annotation layer.
- `pkg/webui/handlers_scan.go` (or a new `feedback.go`) — F2's capture endpoint.
- `tests/unit/template_index_test.go`, `tests/unit/proposed_dir_isolation_test.go`, `tests/unit/triage_assist_test.go`.

### Verification
Unit test confirming `templates/proposed/` is never picked up by the default `--templates` load path (mirrors the isolation guarantee `templates/nuclei-samples/` already needs, but inverted — proposed is deliberately *excluded* by default). Triage-assist output verified to never mutate the underlying `Finding` struct it annotates.

---

## Step 7: Eval Maturity + Release (Week 56) — ⬜ not yet implemented — `v0.7.0`

### Design

**G1 (maturity) — the real benchmark run.** Phase 5 Step 1 built the harness stub and ran it with zero agent involvement to get a baseline. This step runs the same fixed challenge set against the lab targets *with* a real MCP-client-driven agent session (recon → plan → approve → scan → triage), tracking agent-driven false-positive/false-negative rate **separately from** the underlying detectors' own already-measured rate (Phase 2's 1.4%, doc11) — an agent could in principle introduce its own error mode (bad target/template selection, premature triage dismissal) even with zero change to detector accuracy itself. Full cost accounting per run (dollar cost, tool-call count, wall-clock time), modeled on MAPTA/Cyber-AutoAgent's published discipline, not a bespoke scoring rubric.

Full integration testing across the whole Phase 5-7 stack, then release.

### Files (anticipated, confirm at implementation time)
- `tests/eval/agent_run.go` (or extend Phase 5's harness) — real MCP-client-driven run against the fixed challenge set.
- `docs/90-research-hackerbot.md` — G1's row updated with real measured numbers, not left as a backlog item.

### Verification
The benchmark actually runs against all four lab targets with a real agent session, and the resulting fp/fn numbers (and their delta from Phase 5 Step 1's detector-only baseline) are recorded honestly — met, or not met with a stated reason, same "revise down with reasoning, don't pad" discipline every prior phase's real numbers followed (doc11's XSS/SQLi shortfall, doc13's own Phase 4 metrics).

## Definition of Done (Phase 7, Weeks 49-56)

This phase, combined with Phases 5-6, closes out doc90's full "Hacker-in-the-Loop Ready" Definition of Done:
- [ ] `hackerfive templates list --json` ships; MCP sessions get scoped tool lists based on declared agency level (read-only vs. full), confirmed by live-verifying two differently-scoped sessions see different tool lists
- [ ] `AllowWrites` is only honored on a `scan` call carrying a valid elicitation grant reference tied to an approved plan — confirmed no code path lets an agent set it for itself
- [ ] HackerOne submission's permanent human-in-the-loop invariant is documented in `docs/05-hackerone-and-legal.md`
- [ ] A scope-creep scenario triggers fresh elicitation rather than silent expansion, live-verified
- [ ] The Web UI's Agent tab streams every MCP tool call and its reasoning live, matching the persisted session log exactly
- [ ] `findings.export` (and any future report-drafting surface) rejects a draft citing a nonexistent `Finding.ID`
- [ ] Aggregate per-target concurrency across concurrent `scan` calls in one session is throttled to a stated ceiling
- [ ] All ten OWASP Agentic Top 10 risks (D4) are checked against real shipped code (file/line cited) and recorded as mitigated or accepted residual risk with a stated reason
- [ ] `templates/proposed/` exists, is confirmed never auto-loaded by the default `--templates` path, and requires explicit human promotion
- [ ] Triage-assist annotations never mutate `Finding.Severity`/`Confidence`
- [ ] Agent-driven false-positive/false-negative rate is measured live against all four lab targets, tracked separately from detector-level rate, with full cost accounting recorded
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.7.0` tagged and released, or explicitly held with a stated reason

## See also
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — the MCP server, approval gate, and task-tree backbone this phase hardens
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — the recon/`PlanTree`/`Finding`-schema foundations Phase 6 builds on and this phase's ASI06 row cites directly
- [90-research-hackerbot.md](90-research-hackerbot.md) — the full research and backlog this plan and doc14/doc15 together schedule
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-7 roadmap this plan is a slice of
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — the Web UI SSE/audit-trail precedent Step 3/C2 extend
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the `--allow-writes` flag and HackerOne `Exporter` this phase's Step 2 attests to and exports through
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — gains B3's permanent submission-invariant statement
