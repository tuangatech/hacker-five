# Phase 6 Implementation Plan — Weeks 41-48 (MCP Server & Approval Gate)

> Part of the [HackerFive documentation set](../README.md).

**Renumbered from "Phase 5" during the 2026-08-29 recon-phase restructuring.** This doc originally covered both the recon-independent foundations (eval harness, `Finding`-schema freeze, `PlanTree` data model) and the MCP-server/approval work together. [91-research-recon-phase.md](91-research-recon-phase.md)'s research surfaced a real reason to split them, not just a sizing one: [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)'s content (now covering recon + the data-model foundations) has zero dependency on an MCP SDK actually working, while everything in this doc depends on it directly. Bundling them meant an SDK risk outside this project's control could stall recon work that has nothing to do with it. This doc keeps the original MCP-server/approval-gate content, renumbered and re-sequenced to build on doc14 instead of building the foundations itself.

## Objective

[90-research-hackerbot.md](90-research-hackerbot.md) researched how the field's serious 2026 LLM-driven pentesting tools structure themselves and resolved six open design questions (single coordinator, no shell/exec tool, MCP `elicitation`/`tasks` for approval, `Confidence` ≠ `Severity`, and — added 2026-08-30, per the user's hybrid-architecture direction — a stateless/tiered LLM invocation model and deterministic-first dispatch) plus an eight-group backlog (A-H), extended by [91-research-recon-phase.md](91-research-recon-phase.md) into a ninth (Group R, recon) and by the same 2026-08-30 direction into a tenth (Group I, decision engine). Scheduled across three phases: [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) (recon, task-tree/schema foundations, **and the deterministic decision engine/capability registry** — Group I1-I3, no MCP dependency), this phase (the MCP server, `tools.search`/`templates.search` over that registry, the tiered LLM fallback for what the registry can't resolve — Group I4, human-approval gate, and hard safety blockers — the part that's actually unsafe to skip once an agent exists), and [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) (hardening/ecosystem polish on top of a backbone this phase builds). **Nothing in Phase 7 should ship before this phase exists.**

**Scope broadened 2026-09-01, at doc14 Step 7's own request, not silently absorbed:** doc14 Step 7 (recon-derived field suggestions — e.g. `idor`'s endpoint template, `authbypass`'s protected/login/logout paths) deliberately stayed 100% deterministic and left its own zero-/multiple-candidate misses visibly unresolved rather than building a Phase-5-illegal LLM call, on the explicit reasoning that those misses are the same shape as an R8 registry miss — "fires only on a deterministic miss," never a standing parallel path. Group I4 below is broadened accordingly: `pkg/llmfallback` resolves **both** an unresolved `PlanTree` leaf (detector selection) **and** an unresolved recon-derived field suggestion (doc14 Step 7) through the same stateless, schema-in/schema-out mechanism — one fallback subsystem with two callers and two small, distinct output schemas, not two subsystems to design and safety-review separately.

**Scope broadened again 2026-09-02, at an external review's suggestion, not silently absorbed:** a **post-scan finding-triage/prioritization** capability — given a completed job's real `Finding` list, help a human decide which N are worth writing up first — is a genuinely lower-risk shape than everything else in this phase (no autonomous probing decision, no new request ever sent to a target; it only ever reads findings that already exist) and needs no new subsystem: it's a third caller of the same I4 tiered client Step 2 already builds, with its own small, distinct output schema. Deliberately **not** promoted to its own step or its own phase — doing so would fragment one fallback mechanism into three, the exact "three projects, not one" framing that same external review separately (and correctly, for the earnings-table/rate-limit-messaging parts of it) criticized doc02/doc05 for inviting elsewhere. See Step 2's I4 paragraph below for the concrete schema and gating.

**Ordering relative to Phase 4:** this phase comes *after* [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) (Prompt Injection/SSRF/Business Logic Flaws), not instead of it. Confirmed as a real dependency, not just a scheduling preference: doc90's `findings.export` MCP tool (Step 1 below) needs Phase 4 Step 4's `Exporter`/HackerOne-JSON work, which doesn't exist yet as of this writing (`pkg/reporter` today only has `WriteJSON`, confirmed against the actual tree). By the time this phase starts, Phase 4 will have shipped it.

**Ordering relative to Phase 5:** this phase depends directly on doc14's `ReconResult` schema and `Job.PlanTree` data model existing — Step 2 below seeds the coordinator's first `plan` proposal from a real `ReconResult`, and Step 3 wires `ReconResult.OutOfScope` into the scope-creep gate. Neither is buildable before doc14 ships.

## Scope

1. ⬜ **MCP server** (Weeks 41-42)
2. ⬜ **Approval gate + PlanTree executor + spend ceiling** (Week 43 — see this step's note on week pressure, added 2026-08-31)
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

**Second new dependency, for Step 2's tiered LLM fallback (doc90 Decision 5/I4), verified at that step's kickoff, not assumed here**: a local-model runtime client and an OpenRouter client. Per doc02 §8's own updated Dependencies section, both are candidates for a plain `net/http` REST client rather than an SDK (OpenRouter's API is OpenAI-chat-completion-compatible; a local runtime like Ollama exposes the same shape over its own REST endpoint) — apply the `interactsh-client` lesson (doc02 §8) before adding anything heavier: check the real transitive footprint with a scratch `go get`, don't trust a client library's doc page.

**No new dependency for Steps 3-5** — pure Go logic and additions to types doc14 already introduced (`Job.PlanTree`, `ReconResult`, the capability registry); a new `pkg/mcpserver` package calls straight into `pkg/scanner`/`pkg/template`/`pkg/reporter`/`pkg/recon`/`pkg/registry`, duplicating no scan logic, the same boundary doc12 already drew for `pkg/webui`.

---

## Step 1: MCP Server (Weeks 41-42) — ⬜ not yet implemented

### Design

**A1 — `pkg/mcpserver/`**, exposing `scan`, `templates.list`, `templates.sync`, `findings.export`, `recon` (doc91's R4, new), `tools.search`/`templates.search` (new, doc90 I1), and `plan` (built out fully in Step 2) as MCP tools. Calls straight into the existing `pkg/scanner`/`pkg/template`/`pkg/reporter`/`pkg/recon`/`pkg/registry` packages — no scan logic duplicated, the same boundary doc12 already drew for `pkg/webui`. Consumes the same `Engine.WithFindingCallback`/`WithLogCallback` hooks `pkg/webui` already uses (doc90's A2, already landed in Phase 3) — the MCP server is a second frontend on the unchanged core, not a second implementation of it.

**`tools.search`/`templates.search` — the answer to "should every detector/recon-tool/template be its own MCP tool": no.** Both are thin query wrappers over doc14's `pkg/registry` (I1) and `templates/index.json` (R9) — an agent calls `tools.search("wordpress")` and gets back matching registry entries (name/description/when-to-use), not a fixed MCP tool per capability. This is the same search-then-fetch shape this project's own tool ecosystem already uses for large catalogs, applied to HackerFive's own capability list instead of designing something bespoke.

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
- `pkg/mcpserver/tools_registry.go` — `tools.search`/`templates.search`, calling `pkg/registry` (doc14 I1) and `templates/index.json` (doc14 R9).
- `cmd/hackerfive/mcpserve.go` — new `hackerfive mcp-serve` (or similar) subcommand.
- `tests/unit/mcpserver_*_test.go` — schema-validated request/response tests per tool, no live target needed.

### Verification
Unit tests per tool against a mock/stub scanner config. A real MCP client (e.g. Claude Desktop or Claude Code configured against this server) can list and call `scan`/`templates.list`/`templates.sync`/`findings.export`/`recon` and get back structured JSON — live-verified before this step is marked done, not just unit-tested.

---

## Step 2: Approval Gate + PlanTree Executor + Spend Ceiling (Week 43) — ⬜ not yet implemented

**Week-pressure note, added 2026-08-31, named rather than silently absorbed:** this step grew a real subsystem (the executor, below) after this revision found it had no home anywhere in the original plan. One week for `plan`/`elicitation`, the tiered LLM fallback, the executor (plus the `PlanTree` mutex it requires), and the spend ceiling is tight — flag for re-estimation at Step 2 kickoff rather than silently stretching the week, same discipline this doc set already applies to other estimate risks (see doc13's own week-pressure calls).

### Design

**B1 — `plan` MCP tool, built on native `elicitation`/`tasks`.** The agent proposes a full run (targets, detectors, templates, whether writes are required) and gets back a structured plan snapshot (doc14's `PlanTree`) in `input_required` state — no request sent yet. The human's approval is an `elicitation` response, captured natively by the transport rather than a plan-ID string HackerFive has to mint, store, and trust the agent not to replay. This is doc90's single highest-leverage item: today the CLI just executes, and there is currently no point where a human sees and approves a plan before traffic goes out.

**R5 — seed the plan from a real `ReconResult` — largely already done by doc14's R8, this step's job shrinks to exposing it.** Doc14's decision engine (R8) already turns a `ReconResult` into real `PlanTree` leaves with zero agent involvement, deterministically, before this phase even starts. This step's actual remaining work: the `plan` tool returns *that* tree (not an empty one, and not a second, redundant seeding implementation) in `input_required` state for `elicitation`, and — new since the 2026-08-30 hybrid direction — resolves any leaf R8 left visibly unresolved (no registry match) via the tiered LLM fallback below, *before* presenting the final tree for human approval. A leaf the agent or the tool itself invents out of nothing, bypassing both R8 and the fallback, is exactly the "hallucinated plan" doc90's PentestGPT-derived leaf-mutation guard already exists to catch.

**I4 — tiered LLM fallback (doc90 Decision 5/6), invoked only on an R8 registry miss.** For each `PlanTree` leaf R8 left unresolved, one stateless call to the appropriate model tier: a local small model for the routine case (does this unmatched fingerprint still look worth a generic template category), a frontier model via OpenRouter for the rare case nothing in the synced template corpus covers at all — the new-template-authoring path. Each call: build a prompt from that single leaf's `TechFact`/context, get back a schema-validated decision (`{use_existing_tag: string}` or `{draft_template: <nuclei-compatible YAML>}` or `{escalate_to_human: reason}`), apply it as a leaf mutation, done — no conversation carried to the next leaf, no session held open. A drafted template is **untrusted input**: it goes through the *same* rejection pipeline already built for Phase 1b's untrusted-template loading (reject `code:`/`javascript:`/`headless:`/`file:` blocks at load time) and lands in `templates/proposed/` (doc90 E2, Phase 7) for human review — it is never eligible to run against a live target from this step alone, `elicitation` approval (B1, this step) is still required either way. Every call is logged as a single input→output pair tied to its leaf (Step 5's session log format), the same as any other tool call — this is the concrete, auditable shape doc90 Decision 5 describes, not an abstraction.

**I4, second caller (added 2026-09-01, per the Objective's scope-broadening note) — the same fallback also resolves doc14 Step 7's unresolved recon-derived field suggestions.** When Step 7's deterministic heuristics leave an `idor` endpoint template or an `authbypass` path list unresolved (zero candidates, or — for `idor` specifically — more than one and no safe auto-pick), the `plan` tool's pre-approval pass (this step's R5 paragraph) is the natural place to also resolve *these*, not just `PlanTree` leaves: same local-small-model tier for the routine case (does this recon-observed URL look ID-shaped enough to template), same frontier tier only if genuinely needed. **Output schema is deliberately different from a leaf mutation** — `{suggested_value: string, rationale: string}` or `{escalate_to_human: reason}`, never a `draft_template`/YAML shape, since a field suggestion is a plain string slotted into an already-`Validate()`-checked `scanner.Config`, not a new template entering the untrusted-template pipeline. Same rule as the leaf case: this suggestion is presented for human review inside the same `elicitation` round trip as the rest of the plan (B1) — it does not bypass approval by virtue of being "just a field," and a wrong suggestion here costs nothing worse than a zero-finding run (doc14 Step 7's own reasoning, since `idor`/`authbypass`/`misconfig` are all read-only detectors), so it never gets a stricter gate than a leaf mutation does, just the same one.

**I4, third caller (added 2026-09-02, per the Objective's second scope-broadening note) — the same fallback resolves post-scan finding-triage/prioritization, not just pre-scan plan gaps.** Once a `Job` reaches `StatusDone` with a real `[]detectors.Finding` list, a human can request one stateless call: build a prompt from the job's own findings (ID, type, severity, confidence, target, description — never raw request/response bodies, which may carry PII/secrets per doc05's logging guidance), get back a schema-validated `{ranked: []{finding_id: string, rank: int, rationale: string}, escalate_to_human: reason}` shape. **This caller only ever reorders/annotates a list that already exists — it can never add a finding, change a `Severity`/`Confidence` value, or trigger a new request against any target.** Same rule as the other two callers: presented via `elicitation` for human review (a ranking, like a leaf mutation or a field suggestion, is never auto-applied or auto-included in an exported report), and it's the *lowest*-risk of the three callers, not a reason to relax the gate — a wrong ranking costs nothing worse than a human reading findings in a suboptimal order, but it still goes through the identical approval step, no exceptions carved out for "it's just sorting."

**Real-world confirmation, 2026-09-02 — not a hypothetical, a live gap hit on the same run.** A real scan against aalberts.com ([22-authorized-targets.md](22-authorized-targets.md), an authorized target, capped at 5 runs/day) hit both of I4's first two callers' target cases at once:
- `idor`/`authbypass`/`ssrf` all skipped — recon found 15 real endpoints but none matched the deterministic ID-shaped/SSRF-param-keyword/protected-path heuristics (doc14 Step 7's zero-candidate-miss path). Exactly the second caller's case above.
- `misconfig` ran unattended against the full synced corpus (3512 templates) with no tech-specific signal to narrow it by — aalberts.com's fingerprint surfaced nothing as obvious as `wordpress`/`springboot`. Exactly the first caller's case above.

**Explicit decision, same date, user's call, not assumed:** a deterministic tech-name → template-tag lookup table (the shape `pkg/registry`'s existing `techRules` already uses for detector selection) was considered for this second case and declined — LLM-based suggestion is preferred over a hardcoded table on the reasoning that it covers meaningfully more cases than any curated list would. Nothing pulled forward or built early because of this: both gaps stay exactly where I4 already scoped them, not built as a standalone pre-Phase-6 shortcut.

**Commitment:** once Step 1/Step 2's first pieces exist, re-run this exact aalberts.com scan as the live regression check — confirming `idor`/`authbypass`/`ssrf` no longer skip silently and `misconfig` no longer fires the full unnarrowed corpus, using this same real run as the before/after rather than a synthetic test case.

**H5 — per-job spend ceiling**, sequenced alongside B1 per doc90's own note (a hard budget cap has a same-day reference implementation to copy — Strix's `--max-budget-usd` — so there's no reason to treat it as a stretch goal). A hard, enforced cap on cumulative agent-attributable cost (LLM token spend the coordinator itself reports, not HackerFive's own request cost) for a `Job` — exceeding it fails the job with a clear reason, it does not just log a warning.

**Executor — the PlanTree walker that turns an approved plan into real scan calls (new, added 2026-08-31, cross-referenced from doc02 §7's flow diagram).** A real, load-bearing gap this revision found: every step in this doc up through Step 5 assumes execution happens (Step 5's own Verification says a round trip includes "scan execution with live findings/logs"), but no step before this addition actually specified what runs once `elicitation` returns approved. Concretely: once the human approves (B1), a new `pkg/mcpserver/executor.go` walks the approved `PlanTree`'s leaves and, per leaf, calls into `pkg/scanner`/`pkg/recon` the same way `pkg/webui` already does — no scan logic duplicated, same boundary as everywhere else in this doc. Two concurrency tiers, not one blanket policy:
- **Deterministic leaves (R8-matched, zero LLM cost)** parallelize freely across `scanner.Engine`'s existing worker pool (doc02 §4) — the same concurrency the CLI already exercises today for multiple templates/detectors against a target, just dispatched per-leaf instead of per-template-list.
- **LLM-fallback leaves (I4)** stay conservative — low, explicit concurrency (a small fixed cap, not the same pool size as the deterministic tier) — per MAPTA's measured finding that rising cost/attempts/time on one leaf correlates with *falling* success odds (doc90 §2), and H5's spend ceiling: firing many expensive frontier calls in parallel burns budget before H4's stop-and-escalate signal gets a chance to fire.

As each leaf's execution completes, the executor calls `ApplyLeafUpdate` to record its outcome — this is the concrete trigger point Step 3's B4 scope-creep gate reacts to: a leaf's own recon re-run populating `ReconResult.OutOfScope` is what the executor checks before continuing to that leaf's siblings, not a mechanism floating unconnected to anything that calls it. **Hard prerequisite, not assumed**: `pkg/agenttask.PlanTree`/`PlanNode` (doc14 H2) currently carry no mutex — safe there because nothing calls `ApplyLeafUpdate` concurrently in Phase 5, unsafe the moment this executor calls it from parallel leaf goroutines. Add the mutex here, mirroring `pkg/webui`'s `Job`/`ReconJob`, which already guard their mutable fields the same way — a small, well-scoped addition to `pkg/agenttask/plantree.go`, not a redesign.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/tools_plan.go` — `plan` tool, `elicitation` request/response handling, resolving R8's decision-engine output (doc14) plus any I4 fallback resolutions before presenting for approval.
- `pkg/mcpserver/executor.go` — the PlanTree walker: dispatches approved leaves to `pkg/scanner`/`pkg/recon`, two-tier concurrency (deterministic vs. LLM-fallback), calls `ApplyLeafUpdate` per completed leaf, checks for scope-creep after each leaf (feeds Step 3's B4 gate).
- `pkg/agenttask/plantree.go` (doc14, extended) — adds a `sync.Mutex` guarding `PlanNode` field access, so `ApplyLeafUpdate` is safe from concurrent callers.
- `pkg/llmfallback/{tiers,localmodel,openrouter}.go` — the tiered fallback client and its schema-in/schema-out call, invoked per unresolved `PlanTree` leaf, per unresolved doc14 Step 7 field suggestion, **and** per requested post-scan finding-triage pass (three small, distinct output schemas — leaf mutation, `{suggested_value, rationale}`, and `{ranked, escalate_to_human}` — through the same tiered client).
- `pkg/webui/jobs.go` (or doc14's shared package) — `Job`/`PlanTree` gains a `SpendCeiling`/`SpendSoFar` pair; the coordinator reports spend increments via a new field on the MCP tool call metadata.
- `tests/unit/plan_tool_test.go` — approve/reject/timeout paths against a mock elicitation response, including a test confirming the initial tree is seeded from a real (doc14 R8) decision-engine output, not empty and not re-derived.
- `tests/unit/executor_test.go` — confirms deterministic leaves run concurrently (bounded by the worker pool) while LLM-fallback leaves respect the lower concurrency cap; confirms `ApplyLeafUpdate` under concurrent leaf completions doesn't race (`-race` is the actual proof here, not just a passing assertion); confirms a leaf whose execution populates `OutOfScope` blocks its siblings pending re-approval.
- `tests/unit/llmfallback_test.go` — confirms the fallback fires only for a leaf R8 left unresolved (mocked model responses), never for an already-matched leaf; confirms a drafted template is rejected at load time if it contains a disallowed block; confirms the same client, called for a doc14 Step 7 field-suggestion miss, returns the `{suggested_value, rationale}` shape and never a `draft_template`; confirms a finding-triage call returns `{ranked, escalate_to_human}` and never mutates the input `Finding` list it was given (severity/confidence/IDs identical before and after).
- `tests/unit/spend_ceiling_test.go` — confirms a job hard-fails once the ceiling is crossed, not just logs.

### Verification
Unit tests for the elicitation round trip (mocked), the decision-engine-seeded initial plan, the tiered-fallback trigger condition, the spend-ceiling hard-fail, and the executor's concurrency/mutex/scope-creep-trigger behavior (`go test -race` specifically exercising concurrent `ApplyLeafUpdate` calls, not just a single-goroutine happy path). Live verification: a real MCP client runs `recon` then proposes a plan, a human approves or rejects it via the client's own elicitation UI, and the server only proceeds on approval — confirmed against a real client, not just a mock. Separately, live-verify the fallback fires exactly once per unresolved leaf against a real local model and, for the new-template case, a real OpenRouter call. Separately, live-verify the executor against a real lab target with a plan containing multiple deterministic leaves — confirm they actually run concurrently (elapsed time close to the slowest single leaf, not the sum of all leaves), not accidentally serialized.

---

## Step 3: Hard Safety Blockers + Scope-Creep Gate + Cost-Aware Prioritization (Weeks 44-45) — ⬜ not yet implemented

### Design

**D2 — program-policy pre-flight check, a hard blocker.** Before any agent-driven run against a real (non-lab) target, check the target's disclosure policy (via [22-authorized-targets.md](22-authorized-targets.md)'s registry, or a fetched `security.txt`/program policy — doc14's Wave 0 already fetches this during recon) for whether automated scanners are disallowed — refuse to proceed if so. This is the one item in doc90's whole backlog with a documented real-world cost of skipping it (XBOW's own program removal, doc90 §2) — implemented as a hard block, not a warning, unlike `--scope`'s existing softer treatment.

**D3 — hard-fail, not warn, on missing `--scope` for agent-initiated runs.** The CLI's existing "warn, don't silently proceed" behavior for a missing `--scope` (doc02 §3) is the right default for a human at a terminal who typed the command themselves; it's the wrong default for an agent-initiated `scan`/`recon` MCP tool call, where nobody read the warning. Both tools reject the call outright if `--scope`-equivalent isn't set, rather than proceeding with a stderr line nobody's watching.

**B4 — scope-creep gate, first implementation.** doc90's B4 requires fresh approval when a scan's own recon surfaces hosts/paths outside `--targets`/`--scope`; doc14's `ReconResult.OutOfScope` (doc91's R6) is the producer this gate has been missing. Concretely: Step 2's new executor is the actual caller — after each leaf's execution (whether that's the `recon` tool directly or a leaf-scoped re-run mid-scan), the executor checks whether that leaf's result populated `OutOfScope`; if so, it halts dispatch of that leaf's remaining siblings and a second `elicitation` round trip (reusing Step 2's `plan` mechanism) is required before anything touches the newly-found hosts. Naming the executor as the trigger point here closes what was otherwise a gate with no specified caller. Phase 7 Step 2 rounds this out with audit-trail/documentation coverage; this is where the gate first actually exists and blocks something.

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
- **An explicit, always-reachable kill switch/pause control** — doc90's OWASP ASI10 mitigation names this as a requirement; this step is where it's actually built, not just referenced. A single button that cancels the job's context (the same `r.Context().Done()` mechanism doc12's SSE unsubscribe path already relies on) and is visible on every page a running job's status appears on, not buried in a menu. **Scoping note, added 2026-08-31, from a Guided Scan UX review**: this control is not agent-specific — plain New Scan and doc14's Guided Scan (`/recon?mode=guided` → `/guided-scan/plan` → confirm → run) already dispatch into the exact same `Job`/`JobStore` (`pkg/webui/jobs.go`) this step's kill switch would gate, and neither currently has any way to stop a run once started. Build the cancel mechanism once against `Job`'s own lifecycle context and surface it on every `/scans/{id}` render (New Scan, Guided Scan, and the agent-approval flow alike), not only the plan-preview page — three call sites for one control, not three controls.

### Files (anticipated, confirm at implementation time)
- `pkg/webui/handlers_plan.go` (new) or extend `handlers_scan.go` — approve/reject/edit endpoints resolving an `elicitation` response.
- `pkg/webui/templates/plan_preview.html` (doc14's page, extended) — action buttons, budget gauge, kill switch.
- `pkg/webui/templates/scan_status.html`/`fragment_progress.html` (doc12/doc14, extended) — the same kill switch control, since New Scan and Guided Scan runs render here, not on `plan_preview.html`.
- `tests/unit/plan_ui_test.go` — approve/reject via HTTP produces the same effect as an MCP-client-side elicitation response.

### Verification
Live-verified against a real browser: approving a plan via the Web UI unblocks a session that's waiting on `elicitation`, exactly as approving via an MCP client's own UI would. The kill switch, clicked mid-scan, is confirmed to actually stop the job (no further findings/logs after the click), not just hide the UI.

---

## Step 5: Session Log + Release (Weeks 47-48) — ⬜ not yet implemented — `v0.6.0`

### Design

**C1 (minimal) — agent session log.** A structured, append-only record of every MCP tool call, the coordinator's stated reasoning for it (if the calling agent provides one — this is a courtesy field the tool schemas accept, not something HackerFive can force an agent to fill honestly), and the raw result. Persisted per job (reusing `Job`'s existing accumulation pattern from doc12). **Not yet the Web UI's live Agent tab** — that's Phase 7 Step 3's job; this step's deliverable is that the log exists, is queryable, and is complete, even if today it's only inspectable via a CLI dump or the MCP server's own `job.log` equivalent.

Full integration testing across Steps 1-4 together (a real MCP client running a recon → plan → approve → scan → findings.export round trip against a lab target), then release.

**Lab targets for this round trip, added 2026-09-02: crAPI/DVWA plus WebGoat/bWAPP (added to [20-setup-testing-targets.md](20-setup-testing-targets.md)/[20-setup-testing-targets-macos.md](20-setup-testing-targets-macos.md) the same day).** crAPI still covers the credentialed path (a `plan` proposing `idor`/`authbypass` leaves against a target `misconfig`-only lab apps can't exercise). WebGoat/bWAPP are useful for a different, complementary reason: both are `misconfig`-only today (no registry entry drives them toward `idor`/`authbypass`/`ssrf`), so a real plan against either should resolve every leaf deterministically via R8 with **zero I4 fallback calls** — a clean, live confirmation that "deterministic-first" actually means zero LLM invocation on the common case, not just zero on average. Whichever of WebGoat's Spring Boot fingerprint or bWAPP's PHP/Apache fingerprint the registry *doesn't* already have an entry for is also a candidate for live-verifying I4's registry-miss fallback path itself (Step 2's I4 paragraph) — a real, natural unresolved leaf rather than a synthetic one contrived for the test.

**Real-target confirmation, separate from the lab-target round trip above:** Step 2's I4 section records a real, live-hit gap against aalberts.com (2026-09-02) — `idor`/`authbypass`/`ssrf` all skipped, `misconfig` ran the full unnarrowed corpus. Once I4's first pieces exist, re-run that same aalberts.com scan (not a lab target, so not part of this step's own round-trip fixture set above) as the before/after confirmation that both gaps are actually resolved, per that section's commitment.

### Files (anticipated, confirm at implementation time)
- `pkg/agenttask/sessionlog.go` (or peer to `Job`) — the append-only log type.
- `tests/integration/agent_e2e_test.go` — full round trip against a lab target via a real or scripted MCP client.

### Verification
The full round trip (recon → plan proposal → human approval via elicitation or the Web UI → scan execution with live findings/logs → findings.export) works end-to-end against at least one lab target (crAPI or DVWA), live-verified, not just unit-tested piecewise. Also live-verified against WebGoat and/or bWAPP specifically for the all-deterministic, zero-fallback-calls case named above.

---

## Definition of Done (Phase 6, Weeks 41-48)

- [ ] `pkg/mcpserver` exposes `scan`/`templates.list`/`templates.sync`/`findings.export`/`recon`/`tools.search`/`templates.search`/`plan` and nothing shell/exec-shaped; live-verified against a real MCP client
- [ ] The `plan` tool's human approval is captured via MCP `elicitation`, not a hand-rolled plan-ID flag; live-verified against a real client's own approval UI
- [ ] A coordinator's first `plan` proposal is demonstrably seeded from doc14's real decision-engine output (R8), not an empty, hand-authored, or redundantly-re-derived tree
- [ ] The tiered LLM fallback (I4) fires only on a confirmed decision-engine miss — never as a standing parallel path — with every call logged as one stateless input→output pair per `PlanTree` leaf
- [ ] The same tiered LLM fallback also resolves a doc14 Step 7 unresolved field-suggestion miss (`idor`/`authbypass`), returning `{suggested_value, rationale}` — confirmed distinct from the leaf-mutation schema and confirmed it still goes through `elicitation` approval like any other plan content, never auto-applied
- [ ] The same tiered LLM fallback also offers post-scan finding-triage/prioritization on a completed job's real `Finding` list, returning `{ranked, escalate_to_human}` — confirmed it never adds a finding, never mutates `Severity`/`Confidence`/any existing field, never sends a new request to any target, and still goes through `elicitation` approval like the other two callers
- [ ] An LLM-drafted template is confirmed, live, to go through the existing untrusted-template rejection pipeline and land in `templates/proposed/`, never running against a live target without separate human promotion
- [ ] A per-job spend ceiling hard-fails a job when crossed, not just logs
- [ ] The PlanTree executor dispatches approved leaves into real `pkg/scanner`/`pkg/recon` calls; deterministic leaves run concurrently via the existing worker pool while LLM-fallback leaves respect a lower, explicit concurrency cap — both confirmed live, not assumed from the design
- [ ] `pkg/agenttask.PlanTree`/`PlanNode` are confirmed race-free under concurrent `ApplyLeafUpdate` calls (`go test -race`), not just correct in a single-goroutine test
- [ ] A program-policy pre-flight check (D2) hard-blocks an agent-driven run against a target whose disclosure policy disallows automated scanners
- [ ] A missing `--scope`-equivalent hard-fails an agent-initiated `scan`/`recon` tool call, distinct from the CLI's existing warn-only behavior for a human-typed command
- [ ] A discovered out-of-scope host actually populates `ReconResult.OutOfScope` and triggers a fresh `elicitation` round trip before it's touched, live-verified
- [ ] Cost/attempt-aware prioritization (H4) surfaces a stop-and-escalate signal on a `PlanTree` leaf after repeated low-yield attempts
- [ ] The Web UI's Plan-preview page supports Approve/Reject/Edit, a budget gauge, and an always-reachable kill switch that actually stops a running job — and that same kill switch is confirmed on `/scans/{id}` for plain New Scan and Guided Scan runs too, not only the agent-approval flow
- [ ] A structured, persisted agent session log exists and is queryable per job, even without a live Web UI view yet
- [ ] A full recon → plan → approve → scan → export round trip is live-verified end-to-end against at least one lab target, plus a separate run against WebGoat and/or bWAPP confirming an all-`misconfig` plan resolves every leaf deterministically with zero I4 fallback calls
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.6.0` tagged and released, or explicitly held with a stated reason

## See also
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — the recon package, `Finding`-schema freeze, `PlanTree` foundations, and the decision engine/registry (R7-R9, Group I1-I3) this phase's `tools.search`/`templates.search`/tiered-fallback work builds directly on; Step 7 specifically is I4's second caller (recon-derived field-suggestion misses), per this doc's Objective/Step 2 addendum
- [90-research-hackerbot.md](90-research-hackerbot.md) — the research and backlog (Groups A-I, plus R for recon) this plan schedules the MCP-server/approval half of; Decisions 5-6 and Group I4 are this phase's direct scope
- [91-research-recon-phase.md](91-research-recon-phase.md) — Group R, the recon research this phase's Steps 1-3 wire into the MCP server and approval gate
- [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — the hardening/ecosystem/trust phase that follows this one
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — `Finding`/`Exporter`/`Engine` design this plan builds on
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-7 roadmap this plan is a slice of
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — the `WithFindingCallback`/`WithLogCallback` hooks and `Job` model this plan reuses and extends
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the `Exporter`/HackerOne-JSON work `findings.export` depends on, and the `--allow-writes` flag Phase 7's B2 attests to
- [22-authorized-targets.md](22-authorized-targets.md) — the registry D2's policy pre-flight check reads from
