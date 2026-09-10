# Phase 7 Implementation Plan — Weeks 49-56 (Agent Hardening, Ecosystem & Trust)

> Part of the [HackerFive documentation set](../README.md).

**Renumbered from "Phase 6" during the 2026-08-29 recon-phase restructuring** (see [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)'s Objective for the full reasoning): recon and the task-tree/`PlanTree` data model were split out into their own Phase 5 (no MCP dependency), pushing the MCP server/approval-gate work to Phase 6 and this hardening phase to Phase 7. This doc's content is otherwise unchanged from the original Phase 6 draft — only phase/week numbers and the step cross-references they depend on were corrected.

## Objective

[15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) builds the unsafe-to-skip backbone: the MCP server, the `elicitation`-based approval gate, the task tree wired to a live coordinator, and the hard safety blockers (program-policy pre-flight, hard-fail scope). This phase is everything [90-research-hackerbot.md](90-research-hackerbot.md)'s backlog still needs on top of that backbone to reach its own stated Definition of Done — rounding out approval coverage (`AllowWrites` attestation, scope-creep), upgrading observability from a queryable log into a live Web UI view, and closing out the template-ecosystem and eval-maturity items that don't block a first agent session but do block calling the feature actually trustworthy. (The OWASP Agentic Top 10 mapping was originally planned here too; it moved wholly to [Phase 9](18-implementation-plan-ph9.md) Step 5 on 2026-09-10 — see the renumbering note under the Scope list below.)

**This phase depends on Phase 6 existing, not the other way around** — every step below assumes `pkg/mcpserver`, a live `Job.PlanTree`, and the `plan`/`elicitation` approval flow are already in place. It also depends on Phase 5's recon package and read-only Plan-preview UI existing, transitively through Phase 6.

## Scope

1. ✅ **Tool surface completion** (Week 49) — A4, A5, A6 all done 2026-09-06
2. ✅ **Approval & compliance rounding** (Week 50) — B2, B3, B4 all done 2026-09-06
3. ✅ **Observability upgrade: live Agent tab** (Weeks 51-52) — C6 ✅, C1/C2/C3/C5 ✅ 2026-09-07 (`ph7-step3a`), C7 ✅ 2026-09-07 (`ph7-step3b`)
4. ✅ **Live log injection + concurrency ceilings + redundant-request elimination** (Week 53) — D6 ✅ 2026-09-07 (`ph7-step4a`), D5 ✅ 2026-09-07 (`ph7-step4b`), C4 + D1 + H4 ✅ 2026-09-07 (`ph7-step4c`)
5. ✅ **Template ecosystem & triage support** (Week 55) — **F3** (content-gate response-grep secret templates, LT-67) + **F4** (narrow corpus load for a small leaf set, LT-71), done 2026-09-07. Detection-quality + performance; small, independent. **Renumbered 2026-09-10:** this was originally Step 6's "6a" sub-item; its sibling "6b" (E2/F1/F2, agent-output hygiene) and the former Step 5 (OWASP Agentic Top 10 mapping, D4) both moved wholesale to [Phase 9](18-implementation-plan-ph9.md) Step 5 — see the note below the scope list.
6. ⬜ **`v0.7.0` consolidation + release** (Week 56) — cut on **batch-readiness**, *not* gated on the OWASP mapping (see below).
7. ✅ **End-of-scan re-plan loop** (LT-107 + LT-108) — deterministic coverage-gap ledger + a single-call `hackerfive suggest` (print-only, no auto-apply), done 2026-09-10. Added 2026-09-08; not a `v0.7.0` blocker, folds into `v0.7.0` or `v0.8.0` on batch-readiness. Rungs 3–5 of the ladder (LT-109/LT-110) stay in [follow-up.md](follow-up.md).

**Renumbering note (2026-09-10).** The OWASP Agentic Top 10 mapping (D4) was originally its own step here, doing an "interim pass" against shipped Phase 5-7 code, with the **full re-walk** already deferred to [Phase 9](18-implementation-plan-ph9.md) Step 5 (it needs the agent-enumeration + active-injection surface Phase 9 Steps 3-4 add). Since Phase 9 was always going to re-walk the same ASI01-ASI10 table in full shortly after, doing a lighter pass here first just meant doing it twice — so the interim pass was dropped rather than kept as a `v0.7.0` gate, and the step was removed entirely (its ASI-row-by-row table moved to doc18's Step 5 as design residue). The former Step 6's "6b" sub-item (E2/F1/F2) was already deferred to that same Phase 9 Step 5 and is now folded in there too, with no separate mention here. `v0.7.0` therefore ships with no OWASP-mapping gate at all — Phase 9's Step 5 is the only pass.

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step actually lands, same convention as doc09-15.)

**Execution order.** The remaining Phase 7 + [Phase 8](17-implementation-plan-ph8.md)
+ [Phase 9](18-implementation-plan-ph9.md) open work is sequenced as **one backlog**,
ordered by (value × independence), with each phase's eval/release step as its
terminal gate — the full ordered list lives in
[17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) § "Execution order".
Phase 7's place in it: **Step 5 (F3/F4) is Tier 1 (do now)**, done 2026-09-07. The
OWASP mapping and the E2/F1/F2 trio (formerly this doc's Step 5 and Step 6b) are
Tier 3, now scheduled solely as [Phase 9](18-implementation-plan-ph9.md) Step 5.
Version tags are cut on batch-readiness, not step number.

**Partial landing 2026-09-06 (`post-demo-batch` branch), after the demo dry-run:** the self-contained items from Steps 1–3 —
- **A4** ✅ `hackerfive templates list --json` (`{"templates": [...], "rejected": N}`, `templatesync.Entry` shape).
- **A6 (`triage`)** ✅ `hackerfive triage --findings <scan.json> --llm-assist` (CLI entry point for `llmfallback.TriageFindings`, ranking-only, docs/follow-up.md LT-41).
- **B3** ✅ HackerOne-submission human-in-the-loop gate written into [05-hackerone-and-legal.md](05-hackerone-and-legal.md) as a permanent architectural invariant.
- **C6** ✅ `reporter.SplitAggregates` splits the nuclei `http-missing-security-headers` aggregate into per-header findings before `Dedup`, collapsing the native/nuclei N:1 overlap via the existing exact-ID key (docs/follow-up.md LT-6).

**Step 1 completed 2026-09-06 (`ph7-step1` branch):** **A5** (`mcp-serve --agency readonly|full`, launch-time tool-set filtering — stdio is one client per process, so there is no per-session negotiation) and **A6's recon-field self-suggest half** (new `pkg/fieldsuggest`, wired into `plan --llm-assist` and `scan --recon-file`; `plan` stdout is now `{tree, field_suggestions}`).

**Step 2 completed 2026-09-06 (`ph7-step2` branch):** **B2** (`AllowWrites` is now a two-round elicitation attestation on the `scan` tool and a per-plan `acknowledge_writes` on `plan`, never a bare request-body boolean; CLI `--allow-writes` unchanged), **B3** (confirmed already documented in doc05), **B4** (scope-creep compliance rounding — out-of-scope observations now land in the MCP `plan` session log and the Web UI job audit trail).

**Step 3 partial 2026-09-07 (`ph7-step3a` branch):** **C1** (in-process/job-scoped Agent section on the Scan Activity page — the webui process's own agent-like actions as structured `agenttask.SessionLogEntry` rows over a new `agent-event` SSE channel), **C2** (agent-specific audit facts on the `plan.execute` entry's params + the elicitation grant reference on the MCP `plan`/`scan` round-2 session-log entry), **C3** (`reporter.ValidateCitations` + `cited_finding_ids` on `findings.export`), **C5** (sequence-gated `#logs`/`#findings`/`#agent` catchup replay, LT-5).

**Step 3 completed 2026-09-07 (`ph7-step3b` branch):** **C7** (PlanTree structural upgrade + plausibility veto, LT-44/LT-49) — landed on its own branch as planned, since it changes the shared `pkg/agenttask` data-model shape and `pkg/registry.Resolve`'s output. See C7's "As built" note below.

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **A general-purpose logic engine for business-logic templates, or any other scope-expansion of Phase 4's detectors** — this phase is agent-integration hardening, not new vulnerability classes.
- **A fully generic template-authoring DSL for agent-proposed templates** — E2 below is a staging *directory* with human promotion, not an automated review/merge pipeline.
- **Multi-tenant / hosted-agent-service mode** — doc12's local-only architecture decision (loopback-first, no hosted SaaS) applies to the MCP server exactly as it applies to the Web UI; not revisited here.

## Dependencies used in this plan

**No new dependency for any step in this plan.** Everything here extends types and packages Phase 5/6 (or earlier phases) already introduced: `pkg/mcpserver`, `pkg/webui`, `pkg/agenttask` (wherever Phase 5 Step 2 landed `PlanTree`), `pkg/templatesync`. If Step 6's benchmark run surfaces a need for something beyond stdlib (e.g. statistical reporting beyond simple pass/fail counts), verify via pkg.go.dev at that point rather than assuming here — same discipline as every prior phase.

---

## Step 1: Tool Surface Completion (Week 49) — ✅ done 2026-09-06

### Design

**A4 — `hackerfive templates list --json`.** ✅ 2026-09-06. Expose the same tag/severity/category data doc12/Week 19 already extract for the Web UI's Templates page, as machine-readable JSON on the CLI directly — useful for any caller (agent or otherwise) that wants template metadata without going through the MCP server's `templates.list` tool.

**A5 — tool-list scoping.** ✅ 2026-09-06. Per OWASP's "least agency" principle: an MCP session shouldn't necessarily see every tool Phase 6's `pkg/mcpserver` registers, regardless of what it's doing. A read-only "triage this scan's findings" session and a "plan and (pending approval) run writes-capable business-logic checks" session are different agency levels and should get different tool lists.

**As built:**
- **`pkg/mcpserver` runs over stdio only** (`server.go`'s `Serve` → `mcp.StdioTransport`), strictly one client per process. So "session scope at connection time" is really **process scope at launch time** — no live multi-session to filter inside one running server, and no per-session tool-masking API in go-sdk v1.7.0 worth reaching for. A5 is `NewWithAgency(agency)` registering a filtered tool set, not runtime middleware.
- **Coarse two-level model:** `type Agency` = `AgencyReadOnly` | `AgencyFull` (zero value `AgencyFull`). `New()` stays as the back-compatible `NewWithAgency(AgencyFull)`. `NewWithAgency` always registers `recon`, `templates.list`, `templates.search`, `tools.search`, `findings.export`, `findings.triage`, `session.log`; registers `scan`, `plan`, `templates.sync` **only when `agency != AgencyReadOnly`** — a readonly client's `tools/list` never shows them (not a runtime refusal inside a handler). A three-tier `readonly` / `scan`-no-writes / `full` split is the natural follow-on.
- **Selector:** `hackerfive mcp-serve --agency readonly|full` (default `full`) + `HACKERFIVE_MCP_AGENCY` fallback; an unrecognized value fails loudly (`resolveAgency`). A readonly launch logs one stderr line naming what's omitted. Two client config entries with different `--agency` args is how an operator runs a read-only and a full assistant side by side.

**A6 — CLI `hackerfive triage` + recon-field self-suggest ([follow-up.md](follow-up.md) LT-41).** `llmfallback.TriageFindings` and `ResolveField` are reachable only from `pkg/mcpserver` and `pkg/webui` today, so the CLI pipeline has no triage step and can't self-fill `--endpoint` / `--protected-paths` / `--ssrf-param` from recon-derived candidates.

- **`hackerfive triage --findings <file> --llm-assist`** ✅ 2026-09-06 (post-demo-batch) — routes through `TriageFindings`, ranking-only.
- **Recon-field self-suggest** ✅ 2026-09-06. New `pkg/fieldsuggest` package: `Deterministic(result *recon.ReconResult, want map[string]bool) (suggestions []agenttask.FieldSuggestion, misses []Miss)` — the no-LLM auto-fill logic (single candidate → value, multiple → candidates, none/idor-ambiguous → a `Miss`) lifted out of `mcpserver.resolveFieldSuggestions`, importing only `recon` + `agenttask`. Callers apply the results themselves and decide whether to run I4 on the misses, so a `want`-excluded detector yields neither a suggestion nor a Miss — the DoD's "I4 never a standing parallel path" holds by construction. `mcpserver.resolveFieldSuggestions` now delegates its deterministic branches to it (no behavior change; `resolveOneFieldMiss`'s LLM branch stays local) plus a small `applyFieldSuggestion` switch. `plan` now emits `{"tree": …, "field_suggestions": […]}` (was a bare tree — the one breaking output change, agreed) — deterministic suggestions always, and under `--llm-assist` each miss resolved via an inline `llmfallback.ResolveFieldMiss` call against the same per-plan ceiling; without `--llm-assist` a miss is surfaced as an advisory escalate-to-human note, no model call. `scan --recon-file` self-fills a blank `--endpoint`/`--protected-paths`/`--ssrf-param`/`--login-paths`/`--logout-paths` from `fieldsuggest.Deterministic`'s suggestions (one stderr note per field); an idor 0/many-candidate miss is left for the existing "required for --detector X" validation — no `scan --llm-assist`, no metered call added to `scan`. An explicit flag always wins (`applyReconFieldSuggestion` no-ops on an already-set field). The `--recon-file` parse in `scan.go` was hoisted out of the narrow-by-tech branch so `--tags`/`--all-templates` no longer silently ignore it.

### Files (as built)
- `cmd/hackerfive/templates.go` — `--json` flag on `templates list` (A4).
- `cmd/hackerfive/triage.go` — `triage` subcommand (A6).
- `pkg/fieldsuggest/{fieldsuggest,fieldsuggest_test}.go` (new) — `Deterministic(result, want) (suggestions, misses)`.
- `pkg/mcpserver/tools_plan.go` — `resolveFieldSuggestions` delegates its deterministic branches to `fieldsuggest.Deterministic` + a new `applyFieldSuggestion` switch.
- `pkg/mcpserver/server.go` — `Agency` type, `AgencyFull`/`AgencyReadOnly`; `New()` = `NewWithAgency(AgencyFull)`; `NewWithAgency` filters `scan`/`plan`/`templates.sync`.
- `pkg/mcpserver/scoping_test.go` (new).
- `cmd/hackerfive/mcpserve.go` — `--agency` flag + `HACKERFIVE_MCP_AGENCY` + `resolveAgency`; `mcpserve_test.go` (new).
- `cmd/hackerfive/planfields.go` (new) — `planCmdOutput`, `planLeafDetectors`, `planFieldSuggestions`, `applyReconFieldSuggestion`; `planfields_test.go` (new).
- `cmd/hackerfive/plan.go` — deterministic field suggestions always + LLM misses under `--llm-assist`; stdout `{tree, field_suggestions}`.
- `cmd/hackerfive/scan.go` — `--recon-file` parse hoisted; single-/multi-candidate field auto-fill.
- `cmd/hackerfive/plan_test.go` — the three stdout-shape assertions updated to `planCmdOutput`.

### Verification — done 2026-09-06
`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` all clean (0 lint issues). Unit: `NewWithAgency(AgencyReadOnly)`'s `tools/list` omits `scan`/`plan`/`templates.sync` and keeps the seven read-only tools; `AgencyFull` and `New()` list all ten. `fieldsuggest.Deterministic` table tests (nil result, `want`-gating, single/zero/multi candidate per detector). `applyReconFieldSuggestion` (explicit flag wins, fill-when-unset, empty no-op). `planFieldSuggestions` (miss without `--llm-assist` = advisory note + zero spend). Live smoke: `scan --detector idor --recon-file <json>` auto-filled `endpoint_template` from a single recon candidate (`scan: auto-filled endpoint_template from --recon-file: /api/report?report_id={{id}} (A6)`); `mcp-serve --agency` help shows the flag. Still worth a manual pass: two real MCP client config entries (`--agency readonly` vs `full`) side by side.

---

## Step 2: Approval & Compliance Rounding (Week 50) — ✅ done 2026-09-06 (`ph7-step2`)

### Design

**B2 — turn `AllowWrites` into an attested approval, not a bare boolean.** ✅ 2026-09-06. By this phase, Phase 4's `--allow-writes` flag exists (`scanner.Config.AllowWrites`, doc13 Step 3) and Phase 6's `plan`/`elicitation` flow exists. This step wires them together: the `scan` MCP tool only honors a write-capable business-logic check when the request carries an approval grant tied to a `plan` the human already reviewed via Phase 6's approval gate — an `elicitation` grant, not a self-asserted flag. **No process, including the agent itself, can set `AllowWrites` for its own call in the same breath it decided it wanted to** — this holds by construction (the grant comes from a separate elicitation round trip the agent doesn't control the content of), not by convention.

**As built:**
- **`scan` tool** — `allow_writes: true` **with `detector: businesslogic`** now triggers a SEP-2322 two-round-trip attestation, the same mechanism `plan`/`findings.triage` already use (`handleScan` splits round 1 / round 2 around a bounded `pendingScan` cache in `planstate.go`). Round 1 returns an `InputRequests` elicitation carrying `attestWritesSchema` — two required booleans, `approve` **and** `acknowledge_writes` — with a message naming the concrete mutating checks (coupon self-mint/apply, apply-race) and the targets. `scanner.Config.AllowWrites` is set `true` only on the round-2 retry when `isWritesAttested(resp)` (accept + both booleans true). Every other scan runs single-round exactly as before; `allow_writes` for a non-`businesslogic` detector is inert and needs no attestation.
- **Degrade path:** a client with no elicitation capability, a declined attestation, or `acknowledge_writes=false` all land the same way — the businesslogic scan still runs, read-only, mutating checks skipped, with a `warn: allow_writes was requested but not attested via elicitation …` log line ahead of the engine's own generic `--allow-writes not set` warning. Never an error, never a silent write.
- **`plan` tool** — when `allow_writes` was requested **and** `registry.Resolve` actually produced a `businesslogic` leaf (`planHasBusinessLogicLeaf`), the plan's own elicitation schema gains `acknowledge_writes` alongside B4's existing `acknowledge_out_of_scope` (`buildApprovalSchema(requireScopeAck, requireWritesAck)` replaced the two hand-written schema vars), `summarizePlan` spells out the mutating checks, and `isPlanApproved(resp, requireScopeAck, requireWritesAck)` gates execution. On round 2 `pending.baseCfg.AllowWrites` is re-derived as `requireWritesAck` — a plan that asked for writes but has no businesslogic leaf runs with writes off (nothing would use them); approve-without-the-ack returns the plan unexecuted with a note naming the missing acknowledgement, mirroring the scope-ack behaviour exactly.
- **CLI `scan --allow-writes` is unchanged** — a human typing the flag on their own command line is already the explicit, non-agent decision B2 is about; this step only touches the MCP surface where an agent fills the field.

**B3 — document HackerOne submission as a permanent architectural invariant.** ✅ 2026-09-06 (landed in `post-demo-batch`, confirmed still current). `docs/05-hackerone-and-legal.md` §"Report submission is a permanent human-in-the-loop invariant (Phase 7 B3)" states, for the record, that no code path in this project will ever call HackerOne's submission endpoint without a human explicitly choosing to submit — `CreateReportIntent` only ever drafts, `report create` never chains into submission, only `report submit --yes` calls `SubmitReportIntent`. Worth stating plainly given HackerOne's own CEO had to publicly clarify agentic-feature boundaries after a February 2026 researcher backlash (doc90 §3).

**B4 — scope-creep gate compliance rounding.** ✅ 2026-09-06. Phase 6 wired `ReconResult.OutOfScope` into the gate (the `plan` tool's `acknowledge_out_of_scope`, and the `OnOutOfScope` executor halt on both the MCP and Web UI paths); this step is the audit-trail/documentation pass over it:
- **MCP `plan` session log** — `planResultSummary` now records `N out-of-scope host(s) observed` alongside the `approved=` outcome, so a reader of `session.log` sees the scope-creep observation and its acknowledgement together (`out.Note` already carries the "approve given but ack withheld" case verbatim).
- **Web UI audit trail** — `executePlan` appends a `warn`-level job-log entry (`scope: recon found N host(s) outside the approved scope; they will NOT be scanned: …`) at approval time. The hosts were rendered in the recon-results table but never written to the job's log, so the audit trail could not previously show that a run was approved while scope-creep observations were outstanding. They are still never scanned.

### Files (as built)
- `pkg/mcpserver/tools_scan.go` — `recordingScan`/`handleScan`/`runScan` split; `attestWritesSchema`, `isWritesAttested`, `writesRequested`, `writesAttestMessage`.
- `pkg/mcpserver/planstate.go` — `pendingScan` + `storePendingScan`/`takePendingScan`.
- `pkg/mcpserver/tools_plan.go` — `buildApprovalSchema`, `ackGiven`, `planHasBusinessLogicLeaf`; `isPlanApproved` and `summarizePlan` gain the writes-ack parameter; round-2 re-derives `baseCfg.AllowWrites`.
- `pkg/mcpserver/sessionlog_summary.go` — `scanParamsSummary` records `allow_writes`; `planResultSummary` records the out-of-scope count (B4).
- `pkg/webui/handlers_plan_exec.go` — B4 audit-trail log entry at approval time.
- `pkg/mcpserver/{tools_scan_test,tools_plan_test,planstate_test}.go` — attestation unit + round-trip tests.
- `docs/05-hackerone-and-legal.md` — B3 (already present).

### Verification — done 2026-09-06
`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` all clean. Unit: `isWritesAttested`/`isPlanApproved` truth tables; `pendingScan` one-shot + sweep; a non-elicitation-capable client and a declined/`acknowledge_writes=false` attestation each run the businesslogic scan read-only with the withheld-writes log line; an `approve + acknowledge_writes` attestation runs it without that line; `handlePlanApproval` leaves a writes-capable businesslogic plan unexecuted with an `acknowledge_writes` note when the ack is withheld. Still worth a manual pass: a real MCP client driving the `scan` attestation round trip against a live crAPI target with `--allow-writes` actually exercised.

---

## Step 3: Observability Upgrade — Live Agent Tab (Weeks 51-52) — ✅ done 2026-09-07 — C1/C2/C3/C5 (`ph7-step3a`), C6 earlier, C7 (`ph7-step3b`)

### Design

**C1 (full) — Web UI "Agent" tab.** Phase 6's session log is structured and persisted but only queryable after the fact; this step renders it live in `pkg/webui`, over the same SSE mechanism the existing Scan Status page already uses (doc12) — a new `sse-swap="agent-event"` stream alongside the existing `finding`/`log`/`progress` events, so a human watching a running agent session sees each MCP tool call, its stated reasoning, and its result appear as they happen, not only in a post-hoc log dump. This is, per doc90 §2's most load-bearing lesson (the Thacker/xssdoctor team's own framing), the single highest-leverage item in this entire phase: the difference between a useful hacking agent and an expensive hallucination machine was observability, not model quality or tool count. It's deliberately sequenced here, not earlier: Phase 5 built a read-only Plan-preview page and Phase 6 made it an actionable approval surface, so by this step there's an approval mechanism worth visualizing live — building this tab any earlier would have nothing real to stream.

**As built (2026-09-07, `ph7-step3a`) — in-process, job-scoped.** `pkg/mcpserver` (`hackerfive mcp-serve`) and `pkg/webui` (`hackerfive serve`) are separate processes with no shared store, so a literal "stream every MCP tool call into the Web UI" would need a new cross-process bridge this step doesn't build (the rejected alternative: a `HACKERFIVE_SESSION_LOG` JSONL file the webui tails — logged as a possible follow-on). Instead the Scan Activity page gains an **Agent** section (`<div id="agent" sse-swap="agent-event">`, `beforeend`, oldest-first — same shape as Logs) fed by a per-`Job` `agentLog *agenttask.SessionLog`: the webui process's *own* agent-like actions — `plan.resolve` (the LLM-fallback pass behind POST `/plan-preview/resolve`), `plan.reject`, and `plan.execute` (with its Result filled in when the background dispatch terminates) — are recorded as `agenttask.SessionLogEntry` rows, the exact type `pkg/mcpserver`'s `session.log` tool returns, so what the page shows and what a persisted session log holds line up field-for-field. `agenttask.SessionLog` gained a `SetOnAppend` hook; `Job.BeginAgentActivity(tool, reason, params)` mirrors `SessionLog.Begin` and, via that hook, renders + publishes each entry as an `EventAgent`. `renderFinding` grew a `seq int64` param and `Job` a monotonic `eventSeq` (shared with C5).

**C2 — extend the audit trail doc12 already specifies for the Web UI's authorization checkbox** to also capture agent-specific facts: which MCP session initiated a job, what scope/plan was approved and when, and the elicitation grant references B2 introduced.

**As built (2026-09-07).** The Web UI `plan.execute` agent entry (C1) carries structured params — `approved_leaves`, `excluded_leaves`, `allow_writes`, `scope_enforced`, `scope_wildcard`, `out_of_scope_count` — so the agent log *is* the extended audit trail, no parallel mechanism. "Which MCP session initiated a job" is N/A on the webui side (no MCP session in that process — a consequence of C1's in-process choice, stated not dropped). On the MCP side, `sessionlog_summary.go`'s new `withElicitationGrant` stamps `elicitation_grant` (the `RequestState` id) onto the `plan`/`scan` round-2 (post-elicitation) session-log entry — the "elicitation grant reference" — while round 1, which has no `InputResponses`, is unchanged. The accept/decline outcome is already visible in the result summary, so only the reference is added.

**C5 — idempotent `#logs`/`#findings` catchup replay ([follow-up.md](follow-up.md) LT-5).** Today `GET /scans/{id}/catchup` re-syncs only the idempotent, last-value-wins fragments (progress badge, Recon Results) — `#logs`/`#findings` are deliberately excluded because they render as an append list (`hx-swap`), so a blind replay would duplicate rows already delivered live (see `CatchupData`'s doc comment). A late-connecting or reconnecting client therefore permanently loses every log line and finding from before its SSE connection opened. Since this step is already reworking the SSE streams for the Agent tab, add a monotonic sequence number to `Job`'s log/finding accumulation and have the browser report its last-seen sequence on the catchup call (a query param or data attribute) so catchup replays only what the client actually missed — no duplication, no permanent loss.

**As built (2026-09-07).** `Job.eventSeq` is one monotonic counter bumped under `mu` on every `AppendLog`/`AppendFinding`/agent append; the value is stamped onto each item (`LogEntry.Seq`; `Job.findingSeqs` parallel to `findings` since `detectors.Finding` is shared; `SessionLogEntry.Seq` already existed) and rendered as `data-seq` on every row fragment — initial paint and live SSE swap alike. `scan_status.html`'s `hfMaxSeq(id)` reads the highest `data-seq` among a list's children; the catchup fetch passes `since_log` / `since_finding` / `since_agent` (three independent markers — the lists interleave on the shared counter, so one marker would drop a gap row), and `scanCatchup` replays only rows past each. `fragment_catchup.html` emits the extra `beforeend:#logs` / `afterbegin:#findings` / `beforeend:#agent` OOB blocks only when non-empty; findings are rendered newest-first so one `afterbegin` insertion lands them in page order. `CatchupData`'s doc comment went from "deliberately excluded" to "sequence-gated".

**C3 — evidence-linked claims.** No agent-drafted report text (via `findings.export` or any future report-drafting surface) without a citation to a specific `Finding.ID` and its evidence — enforced at the exporter level (a draft referencing an ID that doesn't exist in the job's finding set is rejected), not just a style guideline for prompts.

**As built (2026-09-07).** Finding IDs are kebab slugs (`misconfig-missing-header-X-Frame-Options`, `idor-report-id`) with no rigid shape to regex out of prose, so the citation list is **structured**, not text-scraped: `findings.export` gained `cited_finding_ids []string`, and `reporter.ValidateCitations(citedIDs, findings)` (a new exporter-package function, reused by any future report-drafting surface) hard-errors — naming the offending IDs — if any cited ID is absent from `findings`, before a single byte is rendered. Empty list = current behaviour. `exportParamsSummary` records `cited_count`.

**C6 — collapse the missing-header finding N:1 duplication ([follow-up.md](follow-up.md) LT-6, doc15 Open Issue #6).** A native `misconfig-missing-header-*` finding (one per header) and the nuclei `http-missing-security-headers` template (one aggregate row over many headers) both fire on the same response — ~5 findings for one underlying fact. `reporter.Dedup` is exact-`Finding.ID`-only by deliberate design and a naive topic-level key over-suppresses genuinely distinct findings. This step already reworks the exporter for C3, so do it here: split the nuclei `http-missing-security-headers` aggregate into per-header sub-facts *before* `Dedup`, so the existing exact-ID key then collapses the native/nuclei overlap on its own — no new fuzzy key, no cross-format semantic dedup. Not a `v0.6.0` blocker (the duplication is "two detectors agreeing", visible but not wrong).

**C7 — PlanTree structural upgrade + plausibility veto ([follow-up.md](follow-up.md) LT-44, LT-49).** Two coupled gaps the 2026-09-06 Meesho pipeline run made concrete. **(a)** `registry.Resolve` only ever built `root → one host node → flat leaf list` — `pkg/agenttask/plantree.go` claims "PentestGPT's PTT shape" but there was no vuln-class grouping, no priority/ordering field, and no way for a completed leaf's findings to seed a still-pending sibling (the valmo tree was 21 undifferentiated siblings, 9 near-identical swagger checks). **(b)** `llmfallback` acts only on `StatusUnresolved` leaves (`resolve.go`'s `ResolveTreeLeaves`), never vetoing a leaf the deterministic engine was *confident* about — so a fabricated `APISpecFact` (SPA catch-all, LT-30) or a CDN-brand tech fact (LT-31) yields 8–9 `ConfidenceHigh`/`Pending` leaves that sail straight through I4. The cheap non-LLM half (a relevance-score floor + a per-fact fan-out cap) is [follow-up.md](follow-up.md) LT-48, already landed.

**As built (2026-09-07, `ph7-step3b`).**
- **C7a structure.** `agenttask.PlanNode` gained `Priority int` and `Class string`; `GroupIntoClassNodes(hostNode, classOf)` folds a host's flat leaf list into one intermediate node per vuln-class (`misconfig`/`idor`/…, `templates` for a raw-template-ID leaf, `recon-followup` for an unresolved leaf), class nodes ordered by descending priority. `registry.Resolve` stamps each leaf's `Priority` (`PriorityForConfidence` band + a small bump for a specific-template/endpoint-confirmed leaf) then calls it; `registry.LeafClass` is exported so `llmfallback.MergeLLMProposals` routes a merged leaf into the same class node via the new `agenttask.AttachLeaf`. `Leaves()` still flattens the extra tier, so `planexec`, the webui recursive `fragment_plan_node.html`, and every `summarizePlan`/`planLeafDetectors` consumer are unaffected. `planexec.RunPlan` stable-sorts each dispatch tier by descending `Priority` (start order, not completion order — the pool is still concurrent).
- **C7a seeding — structural + one built-in hook.** `ExecOptions.SeedFn(done, findings, candidates) []LeafSeed` runs after each leaf; `planexec.EndpointSeedFromFindings` (the one built-in, wired at the MCP and webui `RunPlan` call sites) pulls URLs from a completed leaf's `Finding.Target`/`Evidence`, keeps same-host ones, and — reusing `recon`'s own `SuggestIDOREndpointCandidates`/`SuggestSSRFParamsFromRecon` templating — hands a still-pending same-host idor leaf an `{{id}}`-templated `EndpointTemplate` / an ssrf leaf its URL-valued params. Blank fields only; every applied seed is logged via `Notify`; the pre-dispatch missing-field gate is *deferred to `runLeaf`* for idor/ssrf/authbypass when a `SeedFn` is set, so a leaf that would otherwise be skipped for a blank field gets its chance. Best-effort by design (a seed lands only if its target leaf hasn't started — priority ordering makes that the common case). An explicit `DependsOn` edge graph and a broader `Finding→Config` extractor are **out of scope for this branch** — [follow-up.md](follow-up.md) LT-56.
- **C7b plausibility veto.** New `pkg/llmfallback/plausibility.go`: `VetPendingLeaves(ctx, leaves)` is one local-tier-first classification call returning a keep/demote/drop verdict per `StatusPending` leaf (validated in code — every id once, no unknowns, action in the set — degrading to `EscalateToHuman`, never trusting a bad set). `VetoImplausibleLeaves(ctx, fb, fbErr, tree)` orchestrates: no-op when `fb` is nil, respects `tree.SpendCeilingUSD`, applies `demote` (Confidence one band down via `agenttask.DemoteConfidence`, reason prefixed onto Rationale) and `drop` (new `agenttask.StatusVetoed` — kept visible, `planexec` skips it, `ResolveTreeLeaves` never re-touches it) via `ApplyLeafUpdate`, returns one note per demoted/dropped leaf. Wired opt-in behind `--llm-assist` in `cmd/hackerfive/plan.go` (stderr notes), and into the MCP `plan` tool + webui `resolvePlanLeaves` (notes folded into the escalation list the approval surface shows). It can only ever weaken a plan — never adds a leaf or raises a confidence.

### Files (as built — `ph7-step3a`, C1/C2/C3/C5)
- `pkg/agenttask/sessionlog.go` — `SetOnAppend` hook; the `Begin` finish func fires it after each entry.
- `pkg/webui/jobs.go` — `Job.eventSeq` monotonic counter; `LogEntry.Seq`, `findingSeqs`, `FindingRow`, `Event.Seq`; `EventAgent`; `agentLog *agenttask.SessionLog` + `BeginAgentActivity`; `renderFinding` gains a `seq` param; `Snapshot` gains `FindingSeqs` + `AgentEntries`.
- `pkg/webui/handlers_scan.go` — `snapshotData` renders agent rows + `data-seq`; `scanCatchup` reads `since_log`/`since_finding`/`since_agent` and replays only rows past each; `parseSeqParam`.
- `pkg/webui/handlers_plan.go` — `plan.resolve` agent activity around the LLM-fallback pass; `countUnresolvedLeaves`.
- `pkg/webui/handlers_plan_exec.go` — `plan.reject` / `plan.execute` agent activities; `plan.execute` params carry the C2 audit facts; finish in the dispatch goroutine.
- `pkg/webui/types.go` — `CatchupData` gains `LogsHTML`/`FindingsHTML`/`AgentHTML` (doc comment "deliberately excluded" → "sequence-gated"); `ScanStatusData` gains `AgentRowsHTML`.
- `pkg/webui/templates/{scan_status,fragment_catchup,fragment_log_line,fragment_finding_row}.html` + new `fragment_agent_entry.html` — `data-seq` on every row, `hfMaxSeq` + `hx-vals` on the catchup fetch, the Agent section, the conditional append-list OOB blocks.
- `pkg/mcpserver/sessionlog_summary.go` — `withElicitationGrant` (C2 grant reference on `plan`/`scan` round 2); `exportParamsSummary` records `cited_count`.
- `pkg/mcpserver/tools_plan.go`, `pkg/mcpserver/tools_scan.go` — wrap the params summary in `withElicitationGrant`.
- `pkg/mcpserver/tools_findings.go` — `cited_finding_ids` input + `reporter.ValidateCitations` gate.
- `pkg/reporter/exporter.go` — `ValidateCitations` (C3).
- Tests: `pkg/webui/handlers_scan_test.go` (C5 catchup gating), `pkg/webui/agent_tab_test.go` (C1/C2), `pkg/mcpserver/tools_scan_test.go` (C2 grant reference), `pkg/mcpserver/tools_findings_test.go` (C3 rejection), `tests/unit/reporter_citations_test.go` (C3 unit).

### Files (as built — `ph7-step3b`, C7)
- `pkg/agenttask/plantree.go` — `PlanNode.Priority`/`.Class`; `StatusVetoed`; `PriorityLow/Medium/High` + `PriorityForConfidence`; `DemoteConfidence`; `ClassNodeID`; `GroupIntoClassNodes`; `AttachLeaf`.
- `pkg/registry/decisionengine.go` — `Resolve` stamps `leaf.Priority` (`leafPriority`) then `GroupIntoClassNodes(hostNode, LeafClass)`; exported `LeafClass`; `builtinDetectorClasses`.
- `pkg/llmfallback/plausibility.go` (new) — `VetPendingLeaves`, `VetoImplausibleLeaves`, `LeafVerdict`, `validateVerdicts`.
- `pkg/llmfallback/planfromrecon.go` — `MergeLLMProposals`/`leafExists` route through `agenttask.AttachLeaf` / `agenttask.Leaves` for the grouped shape.
- `pkg/planexec/executor.go` — `ExecOptions.SeedFn` + `LeafSeed`; `sortByPriorityDesc` per tier; `StatusVetoed` skip; deferred missing-field gate for seed-fillable detectors; `EndpointSeedFromFindings`; `applyLeafSeed`; `executionResult.skip`.
- `cmd/hackerfive/plan.go` — `VetoImplausibleLeaves` pass under `--llm-assist`.
- `pkg/mcpserver/tools_plan.go` — veto pass folded into `escalations`; `SeedFn: planexec.EndpointSeedFromFindings` on the `RunPlan` call.
- `pkg/webui/handlers_plan.go` / `handlers_plan_exec.go` — veto pass into `resolvePlanLeaves`' escalations + `plan.resolve` activity summary; `SeedFn` on the execute-path `RunPlan` call.
- Tests: `tests/unit/plantree_test.go` (grouping/attach/priority/demote/vetoed), `pkg/registry/decisionengine_test.go` (`TestResolve_GroupsLeavesUnderVulnClassNodes` + the `hostLeaves` helper for the extra tier), `pkg/planexec/executor_test.go` (vetoed skip, `EndpointSeedFromFindings`, deferred-gate seed, priority order), `pkg/llmfallback/plausibility_test.go`.
- (C6's per-header missing-header split already landed in `post-demo-batch`.)

### Verification — done 2026-09-07 (`ph7-step3a`)
`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` all clean (0 lint issues). Unit: C5 catchup replays only rows past the client's per-list sequence with no duplication, and emits no append-list OOB block when the client missed nothing; a malformed marker over-delivers. C1: `plan.reject` and `plan.execute` produce agent entries matching `job.agentLog.Entries()`, the Scan Activity page paints the Agent section on first load, agent entries are catchup-gated. C2: the `plan.execute` entry's params carry `approved_leaves`/`allow_writes`/`out_of_scope_count`; a `scan` round-2 session-log entry carries `elicitation_grant`, round 1 does not. C3: `ValidateCitations` truth table; a `findings.export` citing a nonexistent ID is rejected with the ID named. **Still worth a manual pass:** a real browser watching a live resolve → approve flow populate the Agent section, and a hard-reload mid-run confirming no duplicated/lost log/finding/agent rows (Playwright, per CLAUDE.md).

### Verification — done 2026-09-07 (`ph7-step3b`, C7)
`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` all clean (0 lint issues). Unit: `GroupIntoClassNodes` produces one node per class in descending-priority order, is idempotent, and `Leaves()` still flattens; `AttachLeaf` reuses/creates the right class node; `PriorityForConfidence`/`DemoteConfidence` bands; `registry.Resolve` nests leaves under `class:*` nodes with the right `LeafClass` and stamps `Priority` from the confidence band. `planexec`: a `StatusVetoed` leaf is reported in `skipped` and never dispatched; `EndpointSeedFromFindings` templates an `{{id}}` endpoint / ssrf params from a same-host finding and never seeds cross-host; a `SeedFn` supplying a blank endpoint lets an otherwise-skipped idor leaf run (deferred gate), and with `DetConcurrency 1` leaves start in descending-`Priority` order. `llmfallback`: `VetPendingLeaves` round-trips a valid verdict set and degrades an unknown/missing/invalid one to `EscalateToHuman`; `VetoImplausibleLeaves` applies demote/drop, is a safe no-op with a nil client, makes no call with nothing pending, and respects the spend ceiling. **Still worth a manual pass:** a real `plan --llm-assist` run against a target with a known-fabricated SPA-catch-all APISpec, confirming the veto pass demotes/drops the fanned-out leaves; and a live MCP/webui plan-execute where an early misconfig finding seeds a later idor leaf's endpoint (watch for the `seeded idor endpoint_template …` log line).

---

## Step 4: Live Log Injection + Concurrency Ceilings + Redundant-Request Elimination (Week 53) — ✅ complete: D6 (`ph7-step4a`), D5 (`ph7-step4b`), C4+D1+H4 (`ph7-step4c`), all 2026-09-07

### Design

**C4 — live log injection (stretch).** The Thacker/xssdoctor build (doc90 §2) supports typing directly into a running worker's log to redirect it mid-task without stopping it. A text box on the Agent tab (Step 3) that appends an operator note into the coordinator's next reasoning turn — cheap to add once C1 exists, and directly useful for the "it got distracted, nudge it" scenario doc90 cites as a real, repeatedly-observed need. Lowest priority in this step; descope first if the week runs short.

**D1 — per-detector concurrency ceilings.** Distinct from Phase 4's prompt-injection-specific concurrency guardrail (doc13 Step 1, a stderr warning) — this is a general ceiling the coordinator's `scan` tool calls respect per detector type, so an agent driving many parallel `scan` calls across a session can't collectively exceed a safe aggregate concurrency against one target even if each individual call's `--concurrency` looks reasonable in isolation.

**H4 — cost/attempt-aware stop-and-escalate** (moved here from [Phase 6](15-implementation-plan-ph6.md) Step 3, 2026-09-05 — Phase 6's executor runs each leaf exactly once, so there was no per-leaf retry/grind loop for the rule to gate). By this phase a coordinator loop and the persisted session log (Step 3) exist to measure against. `agenttask.PlanNode` gains per-leaf `Attempts`/`SpendUSD` counters; the I4 resolution path (`pkg/llmfallback`) increments them per model call for a leaf (the one place per-leaf cost actually repeats — deterministic execution is single-shot); a new `StatusEscalated` + a `ShouldEscalate()` rule (MAPTA's finding: rising tool-call count, dollar cost, token count, and elapsed time on one leaf each *independently* correlate with **falling** odds of success — r ≈ −0.6, doc90 §2) surfaces "still grinding, no confidence gain" to the coordinator as a stop signal, not a reason to spend more on the same leaf. Pairs naturally with D1: both bound aggregate cost/effort a session can pour into one target or one leaf.

**D5 — eliminate redundant per-target HTTP in the template executor** ([follow-up.md](follow-up.md) LT-54 + LT-55; design-review follow-on to LT-18, which closed causes (a)–(d) of "a scan spends its wall-clock unrelated to the target"). A scoped scan still fires one loop over templates per target, each re-issuing its own `path:`/`raw:` requests; across the ~2,200-template misconfig floor the same handful of paths (`/`, `/.env`, `/.git/config`, `/robots.txt`, common CVE probes) are fetched many times over, and round-trip latency — not CPU — is the wall-clock (LT-18(b): `user 2.6s` for a 2m+ run). Two changes sharing one `pkg/template/nuclei` plumbing pass and one carve-out review: **(1)** an `Executor`-scoped, mutex-guarded, count-bounded response cache keyed on `(method, full URL, rendered-header fingerprint)`, consulted before `e.client.Do`, with hard carve-outs that always hit the network — `req.usesInteractsh`, any `duration`/`duration_N` reference (blind-timing templates), `req.pathCorrelated`, multi-value `payloads:` iterations, and `raw:` blocks unless a safe key normalization proves out; **(2)** a known-404 path set threaded from a `scan --recon-file` result so a single-request, matcher-only `path:` entry against a path recon already saw 404 is skipped — gated to the same auth posture recon ran under (an unauthenticated recon 404 is not a guaranteed authenticated-scan 404), or opt-in. The shared rate limiter stays the real throttle; both changes only remove redundant round trips, never widen concurrency. Fits this step's D1/H4 theme — bounding the effort/traffic one target absorbs — from the scan-engine side rather than the agent-session side. The carve-out set for (1) is the whole correctness surface: settle it in review before implementing.

**As built (`ph7-step4b`, 2026-09-07).** **(1)** New `pkg/template/nuclei/respcache.go`: `respCache` is `Executor`-scoped, `sync.Mutex`-guarded, 512-entry FIFO-evicted, keyed on `sha256(method \n URL \n Host \n sorted rendered headers \n body)`. Only `tryPath` consults it — before `e.client.Do`, populated after; `tryRaw`/`tryPathCorrelatedIteration` never touch it. `respCacheableKey` carve-outs (always network): `req.usesInteractsh`, the **new load-time `req.usesTiming` flag** (`loader.go`'s `usesTimingRef` — any matcher/extractor referencing bare `duration` or `duration_N`, or `part: duration`), `req.pathCorrelated`, a multi-value `payloads:` iteration (`idSuffix`), and any non-GET/HEAD method (a POST/PUT probe may be non-idempotent even here). Bodies > 512 KiB aren't stored. Default-on in `nuclei.New`. On a cache hit `elapsed` is 0, harmless since `usesTiming` never reaches the cache. **(2)** `recon.ReconResult.DeadPaths()` (new `pkg/recon/deadpaths.go`) → `cmd/hackerfive/scan.go` → `scanner.Config.KnownDeadPaths` → `nuclei.Executor.WithKnownDeadPaths`. `respcache.go`'s `knownDeadSkip` fires no request for a lone `len(tmpl.HTTP)==1`, single-`path:`, `len(Matchers)>0`, no-extractor, GET/HEAD template whose one rendered path is known-dead — **gated to `len(e.extraHeaders)==0`** (no `--header` = recon's unauthenticated posture). Not opt-in behind a flag: the gate makes it conservative by construction. **Deliberately not done:** caching `raw:` (no safe key normalization pass was worth the correctness risk for the handful of single-`raw:` templates that would benefit); a webui/MCP `KnownDeadPaths` path (the doc scoped it to `scan --recon-file`; the response cache itself is frontend-agnostic since it's default-on in `New`). Tests: `tests/unit/nuclei_respcache_test.go`, `pkg/recon/deadpaths_test.go`.

**As built (`ph7-step4c`, 2026-09-07).**
- **H4.** `agenttask.PlanNode` gains `Attempts int` / `SpendUSD float64` (json `omitempty`), `agenttask.StatusEscalated`, package consts `MaxLeafResolveAttempts = 3` / `MaxLeafResolveSpendUSD = 0.05`, `PlanNode.ShouldEscalate()`, and `PlanTree.RecordLeafAttempt(nodeID, spentUSD) (budgetExhausted bool, err error)` (additive; does *not* itself flip Status). `PlanNodePatch` gains `Attempts *int` / `SpendUSD *float64` (assignment semantics). `llmfallback.ResolveTreeLeaves` pre-filters unresolved leaves: any that already `ShouldEscalate()` is flipped to `StatusEscalated` **before the `fb == nil` check** (so no model client is consulted); post-call it charges `RecordLeafAttempt(leaf.ID, cost)` and, when the decision left the leaf unresolved *and* the budget is now exhausted, `applyLeafDecision` sets `StatusEscalated` instead of leaving it `StatusUnresolved` for another grinding pass. `planexec.executor` skips a `StatusEscalated` leaf exactly like `StatusVetoed`. Tests: `pkg/agenttask/plantree_h4_test.go`, `tests/unit/h4_escalation_test.go`.
- **D1.** New `pkg/mcpserver/scangate.go`: a package-level (== session-level, stdio is one client/process) `scanConcurrencyGate`. `runScan` calls `sessionScanGate.enter(in.Targets)` → blocks while any target host is at `maxConcurrentScansPerHost = 3`, then returns a per-target `TemplateConcurrency` of `aggregateTemplateConcurrencyPerHost (10) / (calls now active on the most-contended host)`, floored at `minTemplateConcurrency = 2`, plus a once-guarded release deferred for the scan's lifetime. A ceiling, not a precise partition — the first-admitted call keeps its budget. Tests: `pkg/mcpserver/scangate_test.go` (`tests/unit` can't reach the unexported gate).
- **C4.** New route `POST /scans/{id}/agent/note` → `handlers.agentNote` (`pkg/webui/handlers_agent_note.go`): trims the `note` form field (cap `maxOperatorNoteLen = 2000`, blank → 204 no-op), appends it via `job.BeginAgentActivity("operator.note", note, …)` + immediate `finish(...)` — a structured `agenttask.SessionLogEntry` streamed to every client over the existing `agent-event` SSE channel, where a coordinator loop reading the log picks it up. `scan_status.html` gains an `#agent-note-form` (`hx-post`, `hx-swap="none"`, CSRF hidden field, resets on success). Tests: `pkg/webui/agent_note_test.go`. **Live "an injected note changes the coordinator's next action" verification stays a manual step** — the webui process has no in-process coordinator loop; the note lands in the log the loop consumes.

**D6 — "uniform response wall" detection, wired into three consumers** ([follow-up.md](follow-up.md) LT-43(2) + LT-58 + LT-59 + LT-62; the 2026-09-07 `www.valmo.in` re-run made the 403 variant concrete — Akamai returns one `Access Denied` block page on every path, so the `--recon-file` misconfig scan ran 30 min+ with 0 findings while the native detector answered `misconfig-waf-blocked` correctly in 5.8 s). One primitive — "does this host answer every request identically, or with a known block page?" — built once from the LT-30 `reconCanaryPath` result + `pkg/detectors/misconfig`'s `looksLikeKnownWAFBlockPage`, then wired into: **(1)** the scan corpus short-circuit (LT-43(2) for the 200-catch-all SPA, LT-59 for the 403 WAF wall) — once established, emit the one honest note (`misconfig-uniform-catchall` / `misconfig-waf-blocked`) and skip the rest of the per-target template pass, behind an `--all-templates`-style override; **(2)** `registry.reconShowsAdminSurface` (LT-58) — require a *path-discriminating* 401/403 (status or body differs from the canary) before keeping misconfig's ~1,591-template `panel` floor tag, so a blanket WAF 403 no longer re-admits what LT-43(1) gated out; **(3)** a `pkg/recon` per-host blocked-probe ratio (LT-62) — at ≈1.0 emit a warning + a `plan` note recommending an in-region/residential egress or a pivot to the non-web surface. Shares D5's "the scan wastes round trips" theme and its `pkg/scanner`/`--recon-file` plumbing.

**As built (`ph7-step4a`, 2026-09-07).** New leaf package **`pkg/uniformwall`** holds the one primitive: `Verdict` (`VerdictNone`/`VerdictWAFBlock`/`VerdictCatchall`), `LooksLikeKnownBlockPage` (the block-page marker list, moved here — `pkg/detectors/misconfig`'s `looksLikeKnownWAFBlockPage` now delegates), `Observation`, and `Classify(canary, *root)` — a block-page signature or a 401/403/429 canary is decisive; a catch-all needs the root to be shape-identical *or* a storage-origin `Server` header (GCS `UploadServer` / S3 — LT-66's storage-bucket variant rides along). **Wire-up:** (1) `pkg/recon` Wave 3 (`recordUniformResponse` in `crawl.go`) classifies from the existing canary probe + one root GET and records `ReconResult.UniformResponse *UniformResponseFact{Host, Kind, CanaryStatus, BlockedRatio}` (schema `recon-result.schema.json` v1.4) with a warning; (2) `registry.reconShowsAdminSurface` drops the bare-`401/403` admit when `UniformResponse.Kind == "waf-block"`, keeping `panel` only for an auth-boundary heuristic hit or an admin-shaped path; (3) `scanner.Engine.Run` reads `Config.UniformWallHosts` (a `host→kind` map the frontends fill from `ReconResult.UniformResponse` — `cmd/hackerfive/scan.go`'s `--recon-file`, `pkg/webui`'s `applyTechStackNarrowing`, `pkg/mcpserver`'s `scan`/`plan` tools) and, unless `--all-templates`/`--scan-uniform-anyway`, skips `runTemplates` for a walled host, emitting one `misconfig-waf-blocked`/`misconfig-uniform-catchall` finding; (4) `cmd/hackerfive/plan.go`'s `uniformWallDiagnostic` prints the LT-62 stderr note. **Deliberately not done:** an inline engine probe when no `--recon-file` is given — the expensive case (the ~2,200-template `--recon-file` corpus) by definition has a recon result to carry the verdict, and probing every mock httptest server inline mislabels a fixed-response fixture. Tests: `pkg/uniformwall/uniformwall_test.go`, `pkg/recon/crawl_test.go` (`TestRunWave3_UniformResponseWall`), `pkg/registry/decisionengine_test.go` (`TestDetectorTemplateTagsForRecon` D6 cases), `tests/unit/engine_test.go` (`TestEngineRun_UniformWallHost_SkipsTemplateCorpus`).

### Files
- ✅ **C4 (`ph7-step4c`):** `pkg/webui/handlers_agent_note.go` (new) + `pkg/webui/server.go` (route) + `pkg/webui/templates/scan_status.html` (`#agent-note-form`) + `pkg/webui/agent_note_test.go`.
- ✅ **D1 (`ph7-step4c`):** `pkg/mcpserver/scangate.go` (new) + `pkg/mcpserver/tools_scan.go` (`sessionScanGate.enter` in `runScan`) + `pkg/mcpserver/scangate_test.go`.
- ✅ **H4 (`ph7-step4c`):** `pkg/agenttask/plantree.go` (`Attempts`/`SpendUSD`/`StatusEscalated`/`ShouldEscalate`/`RecordLeafAttempt`/patch fields) + `pkg/llmfallback/resolve.go` (pre-filter + `RecordLeafAttempt` + `applyLeafDecision` escalation) + `pkg/planexec/executor.go` (skip `StatusEscalated`) + `pkg/agenttask/plantree_h4_test.go` + `tests/unit/h4_escalation_test.go`.
- ✅ **D6 (`ph7-step4a`):** `pkg/uniformwall/` (new) + `pkg/recon/{crawl,types,aggregate}.go` + `docs/schema/recon-result.schema.json` + `pkg/detectors/misconfig/detector.go` (delegate) + `pkg/registry/decisionengine.go` + `pkg/scanner/{engine,config}.go` + `pkg/scanner/uniformwall.go` (new) + `cmd/hackerfive/{scan,plan}.go` + `pkg/webui/handlers_launch.go` + `pkg/mcpserver/tools_{scan,plan}.go`.
- ✅ **D5 (`ph7-step4b`):** `pkg/template/nuclei/respcache.go` (new) + `pkg/template/nuclei/{executor,loader,schema}.go` (cache lookup in `tryPath`; `usesTiming` load-time flag) + `pkg/recon/deadpaths.go` (new) + `pkg/scanner/{engine,config}.go` + `cmd/hackerfive/scan.go` (`KnownDeadPaths` plumbing) + tests `tests/unit/nuclei_respcache_test.go`, `pkg/recon/deadpaths_test.go`.

### Verification (as run)
- **D1** (`pkg/mcpserver/scangate_test.go`): two `enter` calls against the same host return budgets 10 and 5, a third returns 3, all reset to 10 after release; distinct hosts don't contend; a 4th call against a host at `maxConcurrentScansPerHost` blocks until a release; double-release is idempotent.
- **H4** (`tests/unit/h4_escalation_test.go`, `pkg/agenttask/plantree_h4_test.go`): a `StatusUnresolved` leaf already at `MaxLeafResolveAttempts` flips to `StatusEscalated` with `fb == nil` never dereferenced; a fresh sibling still takes the "fallback unavailable" path; an already-`StatusEscalated` leaf produces no new work on re-resolve.
- **C4** (`pkg/webui/agent_note_test.go`): a POSTed note becomes one `operator.note` `AgentEntries` row with a non-zero `Seq`; a blank note is a 204 no-op; the Scan Activity page renders the `hx-post` note form. "An injected note changes the coordinator's next action" remains a manual check — no in-process coordinator loop in the webui.
- **D5** (`tests/unit/nuclei_respcache_test.go`): two templates hitting an identical URL issue one HTTP request; `duration` / `interactsh_` / `payloads:` templates each still fire every request; a `--recon-file` known-404 `path:` makes no request under recon's posture and still fires with a credential present.

---

## Step 5: Template Ecosystem & Triage Support (Week 55) — ✅ done 2026-09-07

> **Renumbering note (2026-09-10).** This step was originally split 2026-09-07 into
> "6a" (F3 + F4, near-term) and "6b" (E2/F1/F2, deferred to the Phase 9 window). A
> separate "Step 5" here also used to hold the OWASP Agentic Top 10 mapping (D4),
> sequenced as an interim pass now plus a full re-walk deferred to
> [Phase 9](18-implementation-plan-ph9.md) Step 5. Since the full re-walk was always
> going to redo the same ASI01-ASI10 table shortly after (Phase 9 Steps 3-4 add
> surface that changes several rows materially), the interim pass was dropped rather
> than kept as a `v0.7.0` gate — see the note under the Scope list above. That freed
> up this step's number: what was "6a" is now simply Step 5, and "6b" is folded into
> [Phase 9](18-implementation-plan-ph9.md) Step 5 alongside the OWASP full re-walk.
> The full ASI01-ASI10 table that used to live here (doc90 §3 Group D, confirmed
> against real code) moved to doc18's Step 5 design section as reference material for
> that full re-walk.

**F3 + F4 — ✅ done 2026-09-07.** Detection-quality (F3) and performance (F4);
both landed together with the LT-40 (b)/(c) spec-walker tail. Build / `go vet` /
`go test -race` / `golangci-lint` all clean. What shipped:
- **F3 (LT-67)** — `pkg/registry/decisionengine.go`: `isBodyGrepSecretTemplate`
  (a `token`/`secret`/`api-key`/`credential` tag **and** an `exposure`/`disclosure`
  tag — the shopify-`*`-token / aws-access-key-value family, ~114 corpus entries)
  gated by `hostServesDynamicContent(host, result)` in `resolveTechFact`. Returns
  false — leaf dropped — only on a positive static/walled signal: a recorded
  catch-all wall on the host, recon's `AppSurface: none`, or every measured 2xx
  body on the host below `dynamicContentBodyFloor` (1 KiB). Biased toward emitting.
- **F4 (LT-71)** — `nuclei.LoadDirByIDs` (id:-peek fast path, `peekTemplateID`
  column-0-anchored, 4 KiB head) + `templatesync.LoadByIDs` (cross-format wrapper).
  `scanner.Engine.loadTemplates` takes it for a `TemplateID`-only narrow with no
  tag scope (`fastLoadNucleiIDs`), falling back to a full parse if the peek misses
  a requested id (`nucleiIDsCovered`) so it's a pure optimisation. `pkg/planexec`'s
  specific-template leaves get it for free. Still open: the pure-`--tags` scan path
  (no plan) — needs a guaranteed-fresh index; low value vs. the plan-executor win.
- Tests: `TestResolve_BodyGrepSecretTemplate_{SuppressedOnStaticHost,KeptOnDynamicHost}`,
  `TestLoadDirByIDs_*`, `TestEngineRun_TemplateID_FastLoadSkipsCorpusParse`,
  `TestLoadByIDs_*`.

The original design + files + verification are below. (E1/E2/F1/F2 — formerly this
step's "6b" sub-item — moved wholly to [Phase 9](18-implementation-plan-ph9.md)
Step 5 on 2026-09-10, alongside the OWASP full re-walk; their design text now
lives only there.)

### Design

**F3 — gate response-grep secret/exposure templates on real app content ([follow-up.md](follow-up.md) LT-67).** The `shopify-*` / generic secret-scanning templates grep a response body for leaked credentials; against a static error page or a storage-bucket 404 shell (linkpop's 746-byte SPA, 2026-09-07) that is structurally impossible, yet `registry.Resolve` still emits and `planexec` still fires those leaves — 8 of them on linkpop. Add a minimum-dynamic-content gate to template selection: a response-grep secret/exposure template is only emitted for a host whose recon shows app-generated markup — body size over a floor, a server-rendered/framework marker, or a non-catch-all canary (`ReconResult.UniformResponse.Kind != "catchall"`, D6). Fits this step because it's template-selection quality — the same surface F1's triage annotations describe. Keep the <5% false-positive discipline: a doubtful "is this app content" signal errs toward still emitting the leaf, not suppressing it.

**F4 — "load only these template IDs/paths" fast path in the corpus loader ([follow-up.md](follow-up.md) LT-71).** `planexec.RunPlan`'s LT-18(c) logic forces a full ~9.5k-template corpus load/parse/filter for any specific-template leaf, and a narrow `--tags` scan pays the same cost to run a handful of matches (linkpop: 2,224 loaded + 201 rejected + 7,256 filtered to run 9 named leaves). Add an enumerable-ID/path load path in `pkg/templatesync` + the `pkg/template/nuclei` loader, used when the requested tag/ID set resolves to a small explicit list — skips parsing everything else. Speeds the plan-executor path and any narrow `--tags` scan; pairs with a future `scan --plan-file` that dispatches exactly the approved leaves. Originally slated for Step 4 with LT-54/55; re-homed here when Step 4 shipped without it. Pure performance — no behavior change to which templates match, verified by a before/after finding-set diff on a fixed target.

### Files (anticipated, confirm at implementation time)
- `pkg/registry/decisionengine.go` — F3's dynamic-content gate in `matchTemplateTags` / `resolveTechFact` for response-grep secret/exposure templates.
- `pkg/templatesync/`, `pkg/template/nuclei/loader.go` — F4's enumerable-ID/path fast load path, taken when the requested set is small and explicit.
- `pkg/planexec/executor.go` — F4: pass the specific-template leaf's ID set to the loader instead of forcing a full corpus load.
- `tests/unit/template_select_content_gate_test.go`, `tests/unit/nuclei_loader_idlist_test.go`.

### Verification

F3: against a recon fixture whose host serves a static catch-all, no
response-grep secret/exposure leaf is emitted; against an app-content fixture they
still are; measure the gate's decoy false-positive rate. F4: a plan naming N specific
templates loads exactly those (assert the loader's parsed count), and a full
before/after finding-set diff on a fixed lab target is empty.

---

## Step 6: Eval Maturity + Release (Week 56) — ✅ gate met 2026-09-10, tag pending — `v0.7.0`

> **`v0.7.0` is cut on batch-readiness (2026-09-07 reprioritisation), not on a step
> count.** It requires Steps 1-4 (all done) and Step 5 (F3/F4) — the OWASP mapping
> is no longer part of this gate at all (moved wholly to
> [Phase 9](18-implementation-plan-ph9.md) Step 5, see the note under Step 5 above).
> The integration/eval work below (auth-bypass tests, `--scope` live verification,
> the crAPI credentialed round trip) is the real gate — **all done 2026-09-10**,
> see the Definition of Done below for the real, honest numbers (including two
> open agent-specific findings, LT-138, that don't block the tag). Tagging
> itself is a separate, deliberate action, not automated by this doc.

### Design

**G1 (maturity) — the real benchmark run.** Phase 5 Step 1 built the harness stub and ran it with zero agent involvement to get a baseline. This step runs the same fixed challenge set against the lab targets *with* a real MCP-client-driven agent session (recon → plan → approve → scan → triage), tracking agent-driven false-positive/false-negative rate **separately from** the underlying detectors' own already-measured rate (Phase 2's 1.4%, doc11) — an agent could in principle introduce its own error mode (bad target/template selection, premature triage dismissal) even with zero change to detector accuracy itself. Full cost accounting per run (dollar cost, tool-call count, wall-clock time), modeled on MAPTA/Cyber-AutoAgent's published discipline, not a bespoke scoring rubric.

Full integration testing across the whole Phase 5-7 stack, then release. **Includes
checking in the auth-bypass integration tests** ([follow-up.md](follow-up.md)'s
"Testing & Verification Gaps"): `authbypass_crapi_test.go`/`authbypass_vapi_test.go`
are live-verified ad hoc against real targets but not yet reproducible Go tests — this
integration pass is where they land as checked-in tests against the compose-stack lab
targets, alongside the `--scope` live-verification the same section calls for, **and the
crAPI credentialed recon → plan → approve → scan → export round trip** (moved here from
Phase 6 Step 5 on 2026-09-06 — the round-trip mechanism is already proven by the DVWA +
WebGoat e2e runs; what's left is the credentialed/auth-token variant against the heavy
crAPI stack, which is the same concern as the auth-bypass tests above).

### Files (anticipated, confirm at implementation time)
- `tests/eval/agent_run.go` (or extend Phase 5's harness) — real MCP-client-driven run against the fixed challenge set.
- `tests/integration/authbypass_crapi_test.go` / `authbypass_vapi_test.go` — the ad-hoc checks, made reproducible against the compose-stack targets.
- `docs/90-research-hackerbot.md` — G1's row updated with real measured numbers, not left as a backlog item.

### Verification
The benchmark actually runs against all four lab targets with a real agent session, and the resulting fp/fn numbers (and their delta from Phase 5 Step 1's detector-only baseline) are recorded honestly — met, or not met with a stated reason, same "revise down with reasoning, don't pad" discipline every prior phase's real numbers followed (doc11's XSS/SQLi shortfall, doc13's own Phase 4 metrics).

---

## Step 7: End-of-scan re-plan loop — coverage-gap ledger + `suggest` ([follow-up.md](follow-up.md) LT-107, LT-108) — ✅ done 2026-09-10 (rungs 1-2 only; rungs 3-5 stay LT-109/LT-110)

> **Ships on batch-readiness, not step order.** Listed after Step 6's `v0.7.0`
> gate because it is not a `v0.7.0` blocker; it folds into `v0.7.0` if green
> before that batch closes, otherwise `v0.8.0`. Same convention as the items now
> moved to Phase 9 Step 5. In [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md)
> § "Execution order": **LT-107 is Tier 1**, LT-108 is Tier 1/2 boundary (it
> consumes the ledger). This is doc90 Group E/I at minimal scope.

### Design

This step builds the first two rungs of the "end-of-scan → propose → (later)
apply → re-scan" loop the user has asked for. The loop is a **five-rung ladder**;
only rungs 1–2 are in scope here. Rungs 3–5 are named, not built, and each gets
its own [follow-up.md](follow-up.md) item so the deferral is tracked, not
silently dropped.

| Rung | Item | What it does | Human gate |
|---|---|---|---|
| 0 ✅ | I4 draft → `templates-proposed/` | mid-plan, per uncovered leaf; validated through the real `checkDisallowedBlocks` rejection pipeline (`pkg/llmfallback/resolve.go` `writeProposedTemplate` → a deliberate sibling of `templates/`, on no loader's path) | human file-move to promote |
| **1** | **LT-107** coverage-gap ledger (deterministic, no LLM) | at end of a recon+scan, emit a structured record per `(host, fingerprinted product/version)` that **no loaded template tag and no native detector matched** — the concrete artifact that makes the native-vs-template decision data-driven, and the trigger input rung 2 (and doc90 I4) consume | none — read-only over data that already exists post-scan |
| **2** | **LT-108** `hackerfive suggest <scan-output>` (one stateless frontier call) | takes the rung-1 ledger + the scan's findings, returns a **printed-only** structured list of proposed next actions | spend ceiling H5; **no auto-apply, no re-scan** |
| 3 | **LT-109** (new) `hackerfive templates promote <name>` + a webui "review proposed templates" panel | turns a `templates-proposed/` draft into a loadable template via one explicit action (formalises E2's optional promotion command — the manual `mv` is the fallback today) | explicit human promote |
| 4 | **LT-110** (new) webui "Apply and Run" | takes the operator's selected rung-2 suggestions → drafts the named templates into `templates-proposed/`, queues the second-pass leaves, presents them at the **existing Plan Preview approve/reject gate** (C5), and on approval launches a **fresh scoped scan Job** through the normal launch path — never an in-place mutation of a finished job | Plan Preview / elicitation; spend cap |
| 5 | (folded into LT-110) the closed loop | rung 4's fresh job's own end-of-scan ledger feeds rung 2 again — bounded by the per-plan spend ceiling and a max-iteration cap | every iteration re-crosses the approve gate |

**LT-107 — coverage-gap ledger.** A new post-scan pass (deterministic) that
cross-references three things that already exist after any recon-fed scan:
- the fingerprinted tech facts on `ReconResult` (product + version per host),
- the capability registry (`pkg/registry`, I1) and the decision engine's
  `TechFact`→tag match (I3) — did any of that product's tags resolve to a leaf?
- the **loaded** template set for the job — was a template carrying a matching
  tag actually loaded (survived narrow-by-tech / the time budget / the uniform-wall
  skip)?
A `(host, product, version)` triple where the answer to all of "native detector
fired", "I3 produced a leaf", and "a tag-matching template was loaded" is *no*
becomes one ledger row: `{host, product, version, reason: no-native|no-i3-leaf|template-not-loaded, source_fact}`.
Standalone-useful for a human operator reading a scan result ("you fingerprinted
Webmin 2.111 on `gateway` and nothing checked it"); it is also exactly the signal
rung 2 needs. Emitted to the job's finding stream as an `info`-severity
`coverage-gap-*` entry and to the CLI/JSON report.

**LT-108 — `hackerfive suggest <scan-output>`.** One stateless frontier-tier call
(doc90 Decision 5's shape: schema-in / schema-out, one call, no persistent agent),
bounded by the existing per-plan spend ceiling (H5). Input: the rung-1 ledger +
the scan's findings. Output: a printed, structured list — never applied. Action
kinds the model may propose:
- **templates to draft** for a ledger row nothing covers (→ `templates-proposed/`
  via the rung-0 pipeline; *proposed*, not written, at this rung),
- **second-pass leaves** to run — I3 + `hostnameProductHints` seeds from a
  finding (disclosed admin path → an authbypass leaf; a version banner → a
  targeted CVE template),
- **recon to redo** with better parameters when the ledger shows a thin endpoint
  surface (LT-99 headless crawl, LT-100 param-mining, LT-101 apex-seed fix),
- **cross-host correlation** — the same product+version on N hosts → one grouped
  finding plus "the other N−1 were not checked",
- **triage / dedup groupings** for the report draft (already fenced by
  `reporter.ValidateCitations`, C3).
`--llm-assist`-gated on the CLI exactly like `plan`/`triage`; without it the
command prints the deterministic ledger and stops (no model call). No
`suggest`-initiated scan, no file write beyond the human reading stdout.

**Invariants (carried from CLAUDE.md's detection-philosophy bullet + doc90
Decisions 5–6, unchanged by this step):** every LLM call is spend/attempt-capped
and sits behind a human gate before anything consequential runs; a drafted
template never auto-loads (rung 0's sibling-dir guarantee); a re-scan (rung 4+)
is a normal read-only enumeration Job through the approve gate, never an in-place
edit of a finished job; nothing here touches HackerOne submission.

**Explicitly out of scope for this step (named, deferred to LT-109/LT-110):**
the promote command, the webui "review proposed" panel, the "Apply and Run"
button, and any automated re-scan. This step stops at "the operator reads the
printed suggestions and acts by hand" — the same stopping point `plan`'s
field-suggestion misses and the "recon also suggests" log line already use.

### Files

Landed 2026-09-10, three deviations from the "anticipated" shape above,
each because the concrete architecture didn't have what the sketch assumed:
no `*Job`/`*scanner.Result` param exists for a pure post-scan pass, so
`Ledger` takes `[]recon.TechFact` + the loaded index directly; there is no
wrapper report type anywhere in `pkg/reporter` (every `Exporter` serializes
a bare `[]detectors.Finding`), so a ledger row is an ordinary `Finding`
(`coverage-gap-*` ID, `info` type) in that same array rather than a new
`coverage_gaps` report section; and the two match signals the ledger needs
(`matchTechRules`/`matchTemplateTags`) already existed in `pkg/registry` as
unexported helpers, so they're exposed via one new `registry.CoverageStatus`
rather than reimplemented.

- `pkg/registry/coverage.go` (new) — `CoverageStatus(techName string, templateIndex []templatesync.Entry) (hasNative, hasTemplate, nonActionable bool)`.
- `pkg/coveragegap/ledger.go` (new) — `Ledger(techStack []recon.TechFact, loaded []templatesync.Entry) []GapRow`; pure function, imports `recon` + `registry` + `templatesync` only.
- `pkg/scanner/coveragegap.go` (new) + `pkg/scanner/engine.go` — `Config.TechStack []recon.TechFact` (new field), threaded in by `cmd/hackerfive/scan.go`, `pkg/mcpserver/tools_scan.go`, `pkg/webui/handlers_launch.go`; the ledger pass runs after `pool.Wait()` and emits `coverage-gap-*` info findings via the existing `emitFinding`.
- `pkg/llmfallback/suggest.go` (new) — `Suggest(ctx, ledger []coveragegap.GapRow, findings []detectors.Finding) (SuggestResult, cost, err)`; mirrors `TriageFindings`'s shape exactly, validates each returned action's `kind` against a fixed 5-value allow-list, drops (never fabricates) anything outside it.
- `cmd/hackerfive/suggest.go` (new) — `hackerfive suggest <scan.json> [--llm-assist]`; always prints the deterministic ledger (reconstructed from the scan output's own `coverage-gap-*` findings), the frontier call only under `--llm-assist`; a missing LLM tier or a failed call degrades to ledger-only output rather than failing the command.
- Tests: `pkg/registry/coverage_test.go`, `pkg/coveragegap/ledger_test.go`, `tests/unit/engine_test.go` (`TestEngineRun_CoverageGap_EmitsFindingOnlyForUncoveredTech`), `pkg/llmfallback/suggest_test.go`, `cmd/hackerfive/suggest_test.go`.

### Verification
LT-107: `TestEngineRun_CoverageGap_EmitsFindingOnlyForUncoveredTech` confirms a
fingerprinted product with no native-rule/template-tag match gets exactly one
`coverage-gap-*` finding and a covered product gets none.
LT-108: `TestSuggest_EmptyInput_NoCall` / `TestSuggestCmd_NoFlag_PrintsLedgerOnly_NoModelCall`
confirm zero model calls without `--llm-assist`; `TestSuggest_ValidActions` /
`TestSuggest_ModelInventsUnknownKind_Drops` confirm a valid response is passed
through and an out-of-contract action kind is dropped, never fabricated;
`TestSuggestCmd_LLMAssist_NoTierConfigured_DegradesToLedgerOnly` confirms a
missing LLM tier degrades to ledger-only output rather than failing.
`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` all clean.
A live before/after against a lab target with `hackerfive suggest` is still
worth doing but not yet run.

## Definition of Done (Phase 7, Weeks 49-56)

This phase, combined with Phases 5-6, closes out doc90's full "Hacker-in-the-Loop Ready" Definition of Done:
- [x] `hackerfive templates list --json` ships (2026-09-06); MCP servers get scoped tool lists by launch-time agency (`mcp-serve --agency readonly` omits `scan`/`plan`/`templates.sync` from `tools/list`) — unit-verified via a real client session at each level; a manual two-config side-by-side pass still worth doing
- [x] `hackerfive triage` + recon-field self-suggest (A6): `pkg/fieldsuggest.Deterministic` feeds `plan --llm-assist` and `scan --recon-file`; `plan` stdout is now `{tree, field_suggestions}` (2026-09-06)
- [x] `AllowWrites` is only honored on a `scan` call once a human clears a two-round elicitation attestation (`approve` + `acknowledge_writes`), and on `plan` only with a per-plan `acknowledge_writes` when a businesslogic leaf exists — set by the round-2 handler from the elicitation response, never from the request body, so no code path lets an agent set it for itself (2026-09-06, `ph7-step2`)
- [x] HackerOne submission's permanent human-in-the-loop invariant is documented in `docs/05-hackerone-and-legal.md` (§"Report submission is a permanent human-in-the-loop invariant (Phase 7 B3)")
- [x] Scope-creep gate (Phase 6) rounded out 2026-09-06: out-of-scope observations recorded in the MCP `plan` session log (`planResultSummary`) and the Web UI job audit trail (`executePlan`); a full fresh-elicitation live re-run stays on the Step 6 integration pass
- [x] The Web UI's Agent section streams agent activity live, as the same `agenttask.SessionLogEntry` records `session.log` returns (C1, 2026-09-07, `ph7-step3a`) — in-process/job-scoped: the webui's own agent-like actions (`plan.resolve`/`plan.reject`/`plan.execute`), not an out-of-process MCP session's tool calls (separate processes, no shared store — a JSONL file-tail bridge is a named possible follow-on)
- [x] SSE `/catchup` replays `#logs`/`#findings`/`#agent` a late/reconnecting client missed, sequence-gated so nothing duplicates (C5 / [follow-up.md](follow-up.md) LT-5) — 2026-09-07
- [x] Agent-specific audit facts captured (C2, 2026-09-07): the `plan.execute` agent entry's params (approved-leaf count, `allow_writes`, scope-enforced/wildcard, out-of-scope count) and the elicitation grant reference on the MCP `plan`/`scan` round-2 session-log entry
- [x] A missing-header response yields one finding per absent header with no native/nuclei duplicate pair — the nuclei `http-missing-security-headers` aggregate is split into per-header sub-facts before `reporter.Dedup` (C6 / [follow-up.md](follow-up.md) LT-6 / doc15 Open Issue #6) — landed in `post-demo-batch`
- [x] `findings.export` (and any future report-drafting surface, via `reporter.ValidateCitations`) rejects a draft whose `cited_finding_ids` names a `Finding.ID` absent from the finding set (C3, 2026-09-07)
- [x] Aggregate per-target concurrency across concurrent `scan` calls in one session is throttled to a stated ceiling (D1, `ph7-step4c`) — `pkg/mcpserver/scangate.go`: `runScan` blocks at `maxConcurrentScansPerHost = 3` calls/host and each admitted call's `TemplateConcurrency` is `10 / active-calls-on-host` (floor 2)
- [x] Cost/attempt-aware prioritization (H4, moved from Phase 6 Step 3, `ph7-step4c`): a `PlanTree` leaf at `MaxLeafResolveAttempts`/`MaxLeafResolveSpendUSD` flips to `agenttask.StatusEscalated` — `ResolveTreeLeaves` pre-filters it out before any model client is consulted, `planexec` skips it like `StatusVetoed`
- [x] Live log injection (C4, `ph7-step4c`): `POST /scans/{id}/agent/note` appends an operator note as an `operator.note` `agenttask.SessionLogEntry` streamed over the `agent-event` SSE channel; `scan_status.html` has the injection textbox. (Note→coordinator-action effect is a manual check — the webui has no in-process coordinator loop.)
- [x] Redundant per-target HTTP eliminated (D5 / [follow-up.md](follow-up.md) LT-54 + LT-55) — 2026-09-07 (`ph7-step4b`): `pkg/template/nuclei/respcache.go`'s `respCache` serves a repeat GET/HEAD `(method, URL, Host, header-fp, body)` from a 512-entry FIFO cache in `tryPath` — timing (`req.usesTiming`)/`interactsh_`/`pathCorrelated`/`payloads:`/non-GET-HEAD/`raw:` all carved out; `knownDeadSkip` fires no request for a lone matcher-only `path:` template a `--recon-file` marks 404 when the scan carries no `--header` (recon's posture), still firing it when a credential is present; the shared rate limiter is still the only throughput cap
- [x] Uniform response wall handled (D6 / [follow-up.md](follow-up.md) LT-43(2) + LT-58 + LT-59 + LT-62) — 2026-09-07 (`ph7-step4a`): `pkg/uniformwall.Classify` runs in recon Wave 3 and records `ReconResult.UniformResponse`; `scanner.Engine` skips `runTemplates` for a `Config.UniformWallHosts` match (unless `--scan-uniform-anyway`/`--all-templates`), emitting one `misconfig-waf-blocked`/`misconfig-uniform-catchall`; `reconShowsAdminSurface` keeps `panel` behind a WAF wall only for a path-discriminating signal; recon warns and `plan` prints the blocked-probe-ratio note
- [x] Response-grep secret/exposure templates are only emitted for a host recon shows serving app-generated content (Step 5 / F3 / [follow-up.md](follow-up.md) LT-67) — 2026-09-07: `isBodyGrepSecretTemplate` ∧ `hostServesDynamicContent`, biased toward emitting; unit-tested on catch-all / `AppSurface:none` / sub-floor-body hosts vs. a real-content host
- [x] A specific-template leaf loads only its own template via `nuclei.LoadDirByIDs`' id:-peek fast path, not the full corpus, with an empty before/after finding-set diff (Step 5 / F4 / [follow-up.md](follow-up.md) LT-71) — 2026-09-07; falls back to a full parse on a peek miss so it can't change results. Pure-`--tags`-scan (no plan) still full-loads — follow-on
- [x] Coverage-gap ledger (Step 7 / LT-107) — 2026-09-10: `pkg/coveragegap.Ledger` cross-references `Config.TechStack` against the job's loaded template set (via `registry.CoverageStatus`) and `pkg/scanner/engine.go` emits one deterministic `coverage-gap-*` info finding per fingerprinted product neither a native rule nor a loaded template tag covers — no LLM
- [x] `hackerfive suggest <scan-output>` (Step 7 / LT-108) — 2026-09-10: prints the deterministic ledger always (reconstructed from the scan output's own `coverage-gap-*` findings); `--llm-assist` makes one stateless frontier call (`llmfallback.Suggest`, global-spend-ceiling-capped) that prints a structured action list validated against a fixed kind allow-list; no auto-apply, no re-scan, nothing written to disk. Rungs 3–5 (promote command, "Apply and Run", closed loop) are LT-109/LT-110, out of scope for this step
- [x] Agent-driven false-positive/false-negative rate is measured live against all four lab targets, tracked separately from detector-level rate, with full cost accounting recorded — **2026-09-10, real numbers, not padded**: see [90-research-hackerbot.md](90-research-hackerbot.md) §G1 for the full write-up. Headline: $0.0000 model spend across all 4 targets (neither gap below reached I4); DVWA 7 findings/0 unexpected, Juice Shop 4/1, vAPI 7/1, crAPI 5/5 (crAPI's idor/authbypass leaves were skipped at execution, not wrong — see below). One real bug found and fixed mid-run (**LT-137**: `plan` execution never applied doc15 Step 6a's tech-based template narrowing, causing the first run's timeouts); two genuine agent-specific gaps found and left open (**LT-138**: crAPI's idor/authbypass leaves resolve as pending but get skipped at execution — active-depth unauthenticated recon can't fill their required fields and I4 never gets a turn at it; and `misconfig-method-*`, a native check, silently didn't fire in the agent path against any of the 3 misconfig-only targets, root cause not yet found)
- [x] `authbypass_crapi_test.go`/`authbypass_vapi_test.go` land as reproducible tests against the compose stack, and the crAPI credentialed recon → plan → approve → scan → export round trip is live-verified (moved from Phase 6 Step 5) — **2026-09-10**: both test files already existed (committed 2026-08-28 for Phase 2, but only ever live-verified against whatever instance was up that day); re-verified live today against a fresh crAPI + vAPI Docker Compose bring-up on this machine, all passing (`go test -tags=integration ./tests/integration/...`). The credentialed round trip separately live-verified via the CLI: `hackerfive recon` (active depth, owner token) → `hackerfive plan --recon-file` → `hackerfive scan --recon-file` with both crAPI tokens (7 real `idor-*` BOLA findings, 8 real `authbypass-*`/`coverage-gap-*` findings incl. 3 critical `alg:none` JWT bypasses and the LT-92 BFLA check) → `--format markdown` export — see [follow-up.md](follow-up.md)'s "Testing & Verification Gaps" section for detail
- [x] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean — 2026-09-10
- [ ] `v0.7.0` tagged and released, or explicitly held with a stated reason

**Moved wholly to [Phase 9](18-implementation-plan-ph9.md) Step 5 (2026-09-10 renumbering — formerly this phase's Step 5 (D4) and Step 6b):**
- [ ] All ten OWASP Agentic Top 10 risks re-walked against real shipped Phase 5-9 code (file/line cited), ASI02/ASI04/ASI05/ASI10 re-checked against the new agent-enumeration + active-injection surface
- [ ] `templates/proposed/` exists, is confirmed never auto-loaded by the default `--templates` path, and requires explicit human promotion (E2)
- [ ] Triage-assist annotations never mutate `Finding.Severity`/`Confidence` (F1); structured feedback on an overridden agent finding is captured queryably (F2)

## See also
- [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) — detection-coverage breadth/precision; its § "Execution order" holds the single cross-phase backlog Phase 7's Step 5 (F3/F4) sits in
- [18-implementation-plan-ph9.md](18-implementation-plan-ph9.md) — detection-coverage depth/active; absorbs this phase's former Step 5 (D4, OWASP mapping) and former Step 6b (E2/F1/F2) wholly into its own Step 5
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — the MCP server, approval gate, and task-tree backbone this phase hardens
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — the recon/`PlanTree`/`Finding`-schema foundations and decision-engine registry (R9, `templates/index.json`) Phase 6 builds on and this phase's ASI04/ASI06 rows cite directly
- [90-research-hackerbot.md](90-research-hackerbot.md) — the full research and backlog (Groups A-I, plus R for recon) this plan and doc14/doc15 together schedule
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-7 roadmap this plan is a slice of
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — the Web UI SSE/audit-trail precedent Step 3/C2 extend
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the `--allow-writes` flag and HackerOne `Exporter` this phase's Step 2 attests to and exports through
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — gains B3's permanent submission-invariant statement
