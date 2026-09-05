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

1. ✅ **MCP server** (Weeks 41-42) — done 2026-09-02
2. ✅ **Approval gate + PlanTree executor + spend ceiling** (Week 43 — see this step's note on week pressure, added 2026-08-31) — done 2026-09-02
3. ⬜ **Hard safety blockers + scope-creep gate + cost-aware prioritization** (Weeks 44-45)
4. 🟡 **Approval UI: make the plan preview actionable** (Week 46) — partially done 2026-09-04
5. ⬜ **Session log + release** (Weeks 47-48) — `v0.6.0`
6. ⬜ **Scan-execution efficiency: corpus scoping + concurrency + corpus-once-per-host** (added 2026-09-05 from [follow-up.md](follow-up.md) LT-18 and the 2026-09-06 nettix.com.pe review) — gates Step 5's `v0.6.0` release

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step actually lands, same convention as doc09-14.)

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **A peer-agent mesh of any kind** — Decision 1 (doc90) is a permanent architectural boundary, not a v1 limitation to relax later. A "specialized recon agent" or "specialized exploit agent" is not a future item on this backlog; it's the alternative doc90 evaluated and rejected. (Doc91's research reinforces this further — see doc14's Objective.)
- **Anything shell/exec-shaped in the MCP tool surface** — Decision 2, same permanence. A future "just let the agent run curl for this one edge case" request gets the same answer every other feature request in this project already gets: add a template or detector, don't add a raw-exec tool. Doc91's research found this is a genuinely conservative position relative to the field (every comparable tool researched gives its agent a shell) — see doc14's Objective for the full finding.
- **The full Web UI "Agent" tab with live SSE streaming** — deferred to Phase 7 Step 3 (doc90's C1, full version). This phase upgrades doc14's read-only Plan-preview page into an actionable approval surface (Step 4 below) and ships a structured, queryable session log (Step 5) — real, but the live reasoning-trace tab needs an approval mechanism to visualize, which doesn't fully exist until this phase's own Step 2.
- **OWASP Agentic Top 10 mapping (D4)** — deferred to Phase 7 Step 5; it's a review-and-document pass over a design that needs to actually exist first (this phase builds most of what D4 would be checking).

## Dependencies used in this plan

**New dependency, verified at Step 1 kickoff, not assumed here — resolved 2026-09-02**: an MCP Go SDK. `github.com/modelcontextprotocol/go-sdk` v1.7.0 (official, maintained with Google) was verified via a real scratch `go get` (not just its own go.mod page) before adding: 11 new modules, lean, two already pinned in this project at identical versions. It supports the 2026-07-28 spec's `elicitation` primitive Decision 3 commits to. **One real correction found**: it does not have a "tasks" extension, despite an early assumption otherwise — the real, available mechanism for a long-running call (`scan`/`recon`, which can take 15+ minutes per CLAUDE.md's documented gotcha) is the standard MCP progress-notification mechanism instead, used in Step 1 (see Step 1's Done note). Same discipline the Phase 2 JWT library and Phase 4's candidate Interactsh client both followed: verify before adding, don't assume a package's maturity or feature set from this doc.

**Second new dependency, for Step 2's tiered LLM fallback (doc90 Decision 5/I4) — resolved 2026-09-02**: a local-model runtime client and an OpenRouter client, built as `pkg/llmfallback` (new package). Confirmed as predicted: both really are a plain `net/http` + `encoding/json` REST client (OpenRouter's API is OpenAI-chat-completion-compatible; a local runtime like Ollama exposes the same shape over its own REST endpoint) — **zero new `go.mod` entries**, the `interactsh-client` lesson (doc02 §8) applied and confirmed rather than needed as a correction this time.

**No new dependency for Steps 3-5** — pure Go logic and additions to types doc14 already introduced (`Job.PlanTree`, `ReconResult`, the capability registry); a new `pkg/mcpserver` package calls straight into `pkg/scanner`/`pkg/template`/`pkg/reporter`/`pkg/recon`/`pkg/registry`, duplicating no scan logic, the same boundary doc12 already drew for `pkg/webui`.

---

## Step 1: MCP Server (Weeks 41-42) — ✅ done 2026-09-02

`pkg/mcpserver` ships `scan`, `recon`, `templates.list`, `templates.sync`, `findings.export`, `tools.search`, `templates.search`, and a minimal `plan`, registered via `hackerfive mcp-serve`. Calls straight into the existing `pkg/scanner`/`pkg/template`/`pkg/reporter`/`pkg/recon`/`pkg/registry` packages — no scan logic duplicated, the same boundary `pkg/webui` already uses, including the same `WithFindingCallback`/`WithLogCallback` hooks. Deliberately excludes anything shell/exec-shaped (Decision 2): the agent selects targets/templates, every `Finding` still comes from the existing deterministic matcher/extractor engine.

**Decisions:**
- **Dependency: `github.com/modelcontextprotocol/go-sdk` v1.7.0** (official, maintained with Google). Footprint verified via a real `go get` before adding: 11 new modules, two already pinned at identical versions — no interactsh-client-style bloat. Supports 2026-07-28 `elicitation`. It has **no "tasks" extension** (an early assumption otherwise, corrected by reading the real SDK source) — `scan`/`recon`'s long-running calls (some run 15+ minutes) use the SDK's standard progress-notification mechanism instead (`ServerSession.NotifyProgress`), relayed through `WithFindingCallback`/`WithLogCallback`/`WithProgressCallback`.
- **D3 (missing-scope hard-fail) pulled forward from Step 3.** Every agent-initiated `scan`/`recon`/`plan` call requires a non-empty `scope` — enforced twice: the JSON schema marks it required, and `requireScope` (`pkg/mcpserver/scope.go`) additionally rejects an explicit empty list. `pkg/scanner/scope.New` extracted from `Parse` so in-memory scope entries skip the temp-file round trip; `scanner.Config.Scope` is checked ahead of `ScopeFile`, so the CLI's existing warn-and-continue behavior for a human-typed command is unchanged. D2 (program-policy pre-flight) stays in Step 3 — needs registry data this step doesn't touch.
- **`plan`'s `OutputSchema` is an explicit, permissive `{"type":"object"}`**, not auto-inferred — `agenttask.PlanNode` is self-referential (`Children []*PlanNode`), which the SDK's reflection-based schema inference can't represent (panicked at startup). `PlanTree`'s real shape is already enforced at construction by `registry.Resolve`, not by this wire-level schema.
- **A minimal `plan` tool shipped here**, mirroring `cmd/hackerfive/plan.go`'s pipeline (recon → `registry.Resolve`) with no elicitation — Step 2 adds approval on the same handler.
- **`templates/index.json`'s loader consolidated** into `templatesync.LoadIndex`/`WriteIndex` (`pkg/templatesync/index.go`) once a third consumer needed it — `cmd/hackerfive/templates.go` and `pkg/webui/handlers_plan.go` each carried their own copy before.
- **`tools.search`/`templates.search` are thin query wrappers** over `pkg/registry` and `templates/index.json` — not one MCP tool per detector/template/recon-tool.
- **`findings.export`** calls Phase 4's `Exporter` implementations (Markdown/HTML/HackerOne-JSON); degrades to JSON-only (`reporter.WriteJSON`) if Phase 4 Step 4 hasn't shipped by the time this step starts.

### Files (as built)
- `pkg/mcpserver/server.go` — MCP server setup (`New`, `Serve`), tool registration.
- `pkg/mcpserver/scope.go` — `requireScope`, D3's shared hard-fail helper.
- `pkg/mcpserver/defaults.go` — shared rate-limit/concurrency/timeout/index-path defaults, mirroring `pkg/webui/handlers_scan.go`'s own constants.
- `pkg/mcpserver/tools_scan.go` — `scan` tool, wired to `Engine.WithFindingCallback`/`WithLogCallback`, relaying progress notifications.
- `pkg/mcpserver/tools_templates.go` — `templates.list`, `templates.sync`, calling `pkg/templatesync`.
- `pkg/mcpserver/tools_findings.go` — `findings.export`, calling `pkg/reporter.ExporterFor`.
- `pkg/mcpserver/tools_recon.go` — `recon` tool, calling `pkg/recon`, relaying `WithProgressCallback`.
- `pkg/mcpserver/tools_registry.go` — `tools.search`/`templates.search`, calling `pkg/registry.Search` (new) and `templatesync.LoadIndex`; the minimal `plan` tool.
- `cmd/hackerfive/mcpserve.go` — new `hackerfive mcp-serve` subcommand, registered in `root.go`.
- `pkg/scanner/scope/scope.go` — `New` extracted from `Parse`; `pkg/scanner/config.go` — `Config.Scope`; `pkg/scanner/engine.go` — `loadScope` checks it first.
- `pkg/registry/registry.go` — `Search`, the substring lookup `tools.search` calls.
- `pkg/templatesync/index.go` (new) — `LoadIndex`/`WriteIndex`, deduplicating the loader `cmd/hackerfive/templates.go` and `pkg/webui/handlers_plan.go` each carried their own copy of.
- Tests are **in-package** `*_test.go` files (`pkg/mcpserver/tools_scan_test.go` etc.), not `tests/unit/` — the actually-used convention in this tree (`pkg/hackerone`, `pkg/registry` are in-package; `tests/unit/` is for cross-package/fixture-style tests), confirmed by reading the real tree rather than assumed from this doc's original guess.

### Verification
`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` clean. Live-verified against a real MCP client over a real subprocess (`mcp.CommandTransport`): `tools/list` returns all 8 tools, `tools.search("idor")` returns real registry data, `scan`/`plan` both correctly refuse an unscoped call end to end.

---

## Step 2: Approval Gate + PlanTree Executor + Spend Ceiling (Week 43) — ✅ done 2026-09-02

`pkg/mcpserver`'s `plan` tool now runs recon → `registry.Resolve` → I4 fallback resolution (leaves + idor/authbypass field misses) → elicitation → (on approval) the two-tier executor, returning real findings. `findings.triage` (I4's third caller) ships alongside it. `pkg/agenttask.PlanTree` gained a mutex and a spend ceiling. `pkg/llmfallback` (new package, plain `net/http`, zero new `go.mod` entries) is the tiered local/OpenRouter client.

**Decisions:**

- **B1 — elicitation uses SEP-2322's multi-round-trip shape, not a synchronous `Elicit` call.** Protocol version 2026-07-28 rejects a synchronous `Elicit` mid-request (confirmed against the SDK itself, not its example code, which is stale/older-protocol). A handler instead returns `CallToolResult{InputRequests, RequestState}` with a zero-value `Out`; the client's own multi-round-trip middleware fulfills the elicitation and retries with `InputResponses`/`RequestState` populated. The tree/ranking is cached between the two rounds in a short-lived, single-use, TTL-bounded in-memory store (`pkg/mcpserver/planstate.go`) keyed by `RequestState` — not a durable/replayable plan-ID, since it's scoped to one retry loop (10-minute TTL, evicted on first use).
- **A client without elicitation support gets the tree back unexecuted, with a note**, rather than a framework-level failure — `clientSupportsElicitation` (`pkg/mcpserver/scope.go`) checks the client's declared capabilities before `plan`/`findings.triage` return `InputRequests`.
- **H5 — two spend ceilings, not one.** Per-call default **$0.10** (`HACKERFIVE_SPEND_CEILING_USD`, overridable per call) lives on `agenttask.PlanTree` (not `webui.Job` — `pkg/mcpserver` has no dependency on `pkg/webui`, and a ceiling is naturally scoped to one plan's resolution, not a `Job`'s lifecycle). A process-lifetime cumulative ceiling, default **$2.00** (`HACKERFIVE_SPEND_CEILING_TOTAL_USD`, `pkg/llmfallback/spend.go`), gates every frontier-tier call across the whole server process — bounds aggregate cost across many `plan` calls, not just one resolution pass. Exceeding either stops further I4 calls for that pass (remaining leaves/fields escalate to human) but never blocks elicitation or execution of leaves already resolved — discarding completed deterministic (R8) work over an unrelated budget overrun isn't the goal.
- **Executor concurrency is two-tiered by trust, not by "deterministic vs. LLM."** R8-matched leaves run at full `workerpool` concurrency; `use_existing_tag`-resolved leaves (a detector assignment picked by a model, not deterministically matched) get a lower cap — smaller blast radius for a less-trusted assignment's first live run, since execution itself never calls an LLM. The I4 fallback-*resolution* pass (before elicitation) gets its own separate small concurrency cap (`llmFallbackResolutionConcurrency = 3`) for the real cost-during-parallel-calls reason (MAPTA's finding that rising cost/attempts on one leaf correlates with falling success odds). A `draft_template`-resolved leaf never executes this step — it lands in `templates-proposed/` for human promotion. As each leaf completes, the executor calls `ApplyLeafUpdate`, which is now mutex-guarded (`pkg/agenttask/plantree.go`) since parallel leaf goroutines call it concurrently.
- **`templates-proposed/` is a sibling of `templates/`, not a subdirectory** — every existing loader walks `templates/` recursively, so a nested `templates/proposed/` would have silently entered the live scan corpus the instant a draft landed there. `pkg/mcpserver/tools_plan.go`'s `proposedTemplatesDir` constant.
- **I4 — one tiered LLM-fallback client, three stateless callers, distinct schemas, same elicitation gate:**
  1. **Leaf resolution** — an R8-unresolved `PlanTree` leaf: local tier decides `use_existing_tag`/`needs_new_template`/`escalate`; only `needs_new_template` calls the frontier tier to draft a new template (untrusted input, goes through the same load-time rejection pipeline as any template, lands in `templates-proposed/`).
  2. **Field-suggestion resolution** (doc14 Step 7's `idor`/`authbypass` zero-/multiple-candidate misses) — originally local-tier-only, escalating outright if unavailable rather than spending on the frontier tier, since a wrong guess costs nothing worse than a skipped detector run. **Reversed 2026-09-04, at the user's explicit request** (a real user has no local tier at all): now falls back to the frontier tier via the same `completeBestAvailable` tiering `ResolveLeaf`/`findings.triage` already use, for consistency — see the addendum below.
  3. **Post-scan finding triage** (`findings.triage`) — ranks an existing `[]Finding` list only; never adds a finding or changes `Severity`/`Confidence`.
  All three are single input→output calls with no carried conversation state, and all three go through the same `elicitation` approval as any other plan mutation — none bypasses the gate, including triage ("it's just sorting" is not an exception).
- **Declined: a hardcoded tech-name → template-tag lookup table**, in favor of I4's leaf-resolution LLM call — a real scan against aalberts.com hit both the leaf-miss and field-miss cases live (recon found endpoints matching no deterministic heuristic, and `misconfig` had no tech signal to narrow the corpus by); LLM-based suggestion was judged to cover meaningfully more cases than any curated table would (user's explicit call).
- **Cross-platform config: a first-party `.env` loader** (`cmd/hackerfive/dotenv.go`, no new dependency), applied once in `main()` before any subcommand runs, covering `scan`/`serve`/`mcp-serve` identically on Windows and macOS. A real env var always wins over `.env`. `env.example` documents every var (named without a leading dot — this environment blocks writing dotfiles directly; content is otherwise the real `.env` shape).
- **Frontier-tier `requestTimeout` is 180s, not 60s** — the draft-template-authoring call generates a full YAML template (plus, for reasoning models, hidden reasoning tokens) and was observed live needing up to ~91s; classification/triage/field calls finish in a few seconds, so the ceiling is sized for the outlier, not the common case.
- **`draftTemplateSystemPrompt` carries a condensed rules subset sourced from `docs/template-writing-guide.md`'s "Supported" section** (matcher/extractor types, `part:` values, an explicit ban on `raw:`/`payloads:`/`flow:`, one worked example), not the full guide — the guide covers a second, irrelevant format plus edge cases the model should avoid rather than learn to use. Reduces wasted, rejected frontier calls; keep in sync with the guide's "Supported" section if it changes.

### Files (as built)
- `pkg/mcpserver/tools_plan.go` — `plan` tool: `handlePlan` (round 1: recon → `registry.Resolve` → I4 leaf/field resolution → `InputRequests`) and `handlePlanApproval` (round 2: look up the cached plan, run the executor on approval).
- `pkg/mcpserver/planstate.go` — the short-lived, TTL-bounded, in-memory cache (`pendingPlan`/`pendingTriage`, keyed by a minted `RequestState` token) bridging `plan`/`findings.triage`'s two SEP-2322 rounds.
- `pkg/mcpserver/executor.go` — `RunPlan`, the PlanTree walker: two-tier `workerpool` dispatch (R8-matched vs. `use_existing_tag`-resolved), skips template-ID leaves and any leaf missing a required field (idor/authbypass/ssrf) it couldn't get filled, calls `ApplyLeafUpdate` per completed leaf.
- `pkg/mcpserver/tools_triage.go` — `findings.triage`, I4's third caller, same two-round elicitation shape as `plan`.
- `pkg/agenttask/plantree.go` (extended) — `sync.Mutex` guarding `PlanTree`; `SpendCeilingUSD`/`AddSpend`/`SpendSoFar`; `PlanNodePatch` gained a `Detector` field (needed for I4's `use_existing_tag` leaf mutation, not anticipated in the original patch shape).
- `pkg/agenttask/fieldsuggestion.go` (new) — `FieldSuggestion` type.
- `pkg/llmfallback/{client,leaf,field,triage,types}.go` (new package) — plain `net/http` tiered client (local-first, OpenRouter for new-template drafting only), zero new `go.mod` entries as predicted at Step 2 kickoff.
- `pkg/recon/suggest.go` (extended) — `SuggestAuthBypassPathsFromRecon` extracted from a private `pkg/webui/handlers_launch.go` function of the same shape (a third recon-derived-suggestion function alongside the two already there), so `plan`'s field-suggestion wiring didn't need a fourth private copy; `pkg/webui` switched to calling the shared version.
- `templates-proposed/` (new, repo root) — where a `draft_template` I4 decision lands; deliberately not under `templates/` (see Done note's safety-gap paragraph).
- Tests, in-package: `pkg/agenttask` (mutex/spend, extended in `tests/unit/plantree_test.go`, including a `-race`-run concurrent-`ApplyLeafUpdate` test), `pkg/llmfallback/*_test.go`, `pkg/mcpserver/{executor,tools_plan,tools_triage}_test.go`, `pkg/recon/suggest_test.go` (extended).

### Verification
`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` clean. Unit tests cover the mutex/spend-ceiling behavior under `-race`, the tiered-fallback decision branches against a mocked chat-completions endpoint (including drafted-template rejection), the executor's eligibility filtering, and both `plan`'s and `findings.triage`'s full elicitation round trip (declined/approved/graceful-degrade) against a real in-memory MCP client.

Live-verified against the real compiled binary and a real MCP client: `plan` against `example.com` triggers the `InputRequests`/retry round trip end to end and returns `approved: true`. Live-verified against real models, not just mocks: a local Ollama model (`gemma3:4b`) and a paid OpenRouter model (`deepseek/deepseek-v4-flash-0731`) both exercised all three I4 callers, including the frontier-tier draft-template-authoring path, which produced a real nuclei template that passed the actual load-time validator.

**Addendum, 2026-09-03 — six follow-up fixes from a review of I4's actual mechanics:**
1. **`draftTemplateSystemPrompt` now sources its rules from `docs/template-writing-guide.md`'s "Supported" section** instead of a hand-duplicated summary — keeps the two from drifting apart.
2. **`ResolveLeaf`'s tag sample is now relevance-ranked** (`rankRelevantTags`, `pkg/llmfallback/leaf.go`): scores every tag against the leaf's tech-fact name (exact match > substring > word overlap), takes up to 200, pads to 300 total with the old fixed-order walk as a fallback. Reuses `pkg/registry.NormalizeTechName` (newly exported). Replaces a blind first-200-of-thousands cap that showed the same arbitrary tags on every call regardless of the leaf — a measured cause of avoidable `needs_new_template` decisions.
3. **Unresolved-leaf `Rationale` now includes real recon-observed endpoints when any exist on that host** (`correlatedEndpoints`/`describeEndpoints`, `pkg/registry/decisionengine.go`) — up to 3, method+path+status. Both `ResolveLeaf` and the draft-authoring call already embed `Rationale` verbatim into their prompts, so one change benefits both. Previously the only context was a bare hostname + tech name, even though `ReconResult.Endpoints` already existed and was already used by the sibling field-suggestion path.
4. **A leaf naming a specific template now actually executes, not just informational-only.** `pkg/scanner/config.go` gained `Config.TemplateID` (exact `id:` match, unlike `Tags`' OR-match against `tags:`) and `ValidateOptions.SkipDetectorRequired`; `engine.go` gained `filterNucleiByID`/`filterNativeByID` and a `case "":` no-op in `runDetector`; `pkg/mcpserver/executor.go`'s `RunPlan` dispatches a leaf whose `Detector` matches a real `templatesync.Entry.ID` as a templates-only run instead of skipping it. A hallucinated name keeps skipping, unchanged. **Fully closes the gap for R8's own deterministic matches; an I4 `use_existing_tag` decision still can't dispatch — see Open Issues below.**
5. **DSL evaluator now supports `<=`/`>=`** (`pkg/template/dsl`) — a real tokenizer gap, not a deliberate exclusion; fixes real upstream CVE templates using time-based/ordering checks.
6. **Synced template corpus widened from 4 categories (3,512 templates) to 7** — added `cves/`, `exposures/`, `default-logins/`, and the rest of `vulnerabilities/`. Both `scripts/sync-nuclei-templates.sh` and `pkg/templatesync.Categories` (the CLI's real sync list) updated. A separate top-level `cloud/` directory was evaluated and rejected: `code:`-block-based (shells out to cloud CLIs), needs cloud IAM credentials this project has no concept of — wrong protocol and wrong threat model. Real measured load-success after running the actual sync + index commands: 7,716 of 9,682 templates (79.7%).

`go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` clean. New/extended tests: `pkg/template/dsl` + `tests/unit/dsl_test.go`, `pkg/llmfallback/tagrank_test.go` (new), `pkg/registry/decisionengine_test.go`, `tests/unit/config_test.go`/`engine_test.go`, `pkg/mcpserver/executor_test.go`.

**Addendum, 2026-09-03 — follow-ups from a Web UI review (logging/visibility, I4 wiring, recon hygiene, LLM-tier config):**
1. **Itemize the detector-scan job's logging, not just aggregate counts.** Root cause: `loadTemplates` reported only a rejection count, and `Run`'s per-target template loops silently `continue`d on a genuine execution failure. Fix (`pkg/scanner/engine.go`, streamed to the Web UI Logs panel): a `warn` line per file rejected by both loaders (path + both formats' reasons), and per template execution error (id/target/error) — except when the scan's own context is done (`ctx.Err()` on the outer job context, not a per-template client-timeout), where the loop `break`s instead of logging every remaining template.
2. **Wire I4 into the Web UI plan-preview.** Root cause: `planPreview` (`GET /plan-preview`) called `registry.Resolve` only — the zero-LLM path — so an R8-unresolved leaf rendered unresolved with no LLM attempt. Fix: the resolution logic (walk unresolved leaves → `ResolveLeaf` → apply decision → write draft to `templates-proposed/`) extracted to exported `llmfallback.ResolveTreeLeaves`, now shared by `pkg/mcpserver`'s `plan` tool and `pkg/webui`. New **`POST /plan-preview/resolve`** — an explicit button, not automatic on GET, since I4 costs real money and seconds per leaf; classify/draft only, never execute. `Job` caches the resolved tree so a reload or second click doesn't re-spend; `GET` prefers the cached tree over a fresh `registry.Resolve`. *Not verified in a real browser* — exercised via the full `httptest` request/response path against the real server object.
3. **Wire I4 into the New-Scan launch flow too.** Root cause: `handlers_launch.go`'s `fillReconFields` — the code emitting the real `idor`/`authbypass`/`ssrf: skipped` log lines — had zero `llmfallback` wiring; item 2 only reaches `/plan-preview`, which New Scan never calls. Fix: new shared `llmfallback.ResolveFieldMiss` primitive; `fillReconFields` gained a `ctx` param and a lazily-memoized I4 client. The Web UI has no per-field review step, so this *preserves* the "never run with an unreviewed guess" invariant rather than relaxing it — a miss still skips the detector exactly as before, now additionally logging an LLM-suggested value for the operator to copy in and re-launch. `ssrf` untouched (no miss case). *Not live-verified* against a real target with a real local model.
4. **Filter static-asset/junk paths out of authbypass's recon-derived protected-path suggestion.** Root cause: `SuggestAuthBypassPathsFromRecon` bucketed any endpoint katana saw a 401/403 on into `protected`, no static-asset filter — a live run got ~60 entries, only 4 real routes (rest Next.js JS bundles + one degenerate `/\`). Real risk: `checkMissingAuth` fires a live GET at each and reports high-confidence on `200`, so a rate/bot-based 401/403 flipping to `200` is a genuine false positive. Fix: `looksLikeStaticAssetOrJunk` — static-asset extension list or no alphanumeric content — applied once per endpoint before the protected/login/logout split.
5. **Re-verify a katana-observed 401/403 before trusting it as "protected"; fix authbypass's double-slash `Target`.** Root cause: a single crawl-time 401/403 was trusted as proof of access control, usually just a WAF/bot block of the crawler — same shape as item 4 but broader, since a normal-looking path (`/giftcard/`, confirmed FP — 301s to a public storefront) can't be caught by path-shape filtering; the fix has to distrust the signal itself. Fix: `runKatana` holds 401/403 facts back into a candidate list; a new `verifyAuthCandidates` pass re-issues one direct GET each and keeps it (promoted to `ConfidenceHigh`) only if the fresh request reproduces the status. Separately: `authbypass` built every URL as `target + path` with no normalization — fixed at `doRequestBody`'s `fullURL` (`strings.TrimSuffix(target,"/")+path`), and all four `Finding.Target`s now use `req.URL.String()`.
6. **`ResolveField` now falls back to the frontier tier.** Root cause: it escalated outright whenever the local tier wasn't usable, never trying a configured OpenRouter — a user with no local runtime got `model 'llama3.1' not found` and no fallback. Fix: `ResolveField` now calls the shared `completeBestAvailable` — same tiered fallback `ResolveLeaf`/`findings.triage` use: frontier tier if local is unreachable/unconfigured or its call fails. (Only fires when `OPENROUTER_API_KEY` is set; with no key, the bare local error is returned immediately — documented, correct behavior, not a bypassed fallback.)
7. **Stop recon's WHOIS/ASN lookups firing against loopback/private targets** — the real cause of recurring `pkg/webui` CI timeouts. Root cause: `runWave1` called `runWHOISAndASN` unconditionally; unlike the shelled-out binaries, WHOIS (`whois.iana.org:43`, up to 8s ×2) and ASN (Team Cymru DNS TXT) are native Go clients that fire in every environment, so every scan-submitting `pkg/webui` test made a live third-party round-trip for a `127.0.0.1` test server. Fix: `isPrivateOrLoopbackHost` (`"localhost"` + `net.IP.IsLoopback`/`IsPrivate`/`IsLinkLocalUnicast`/`IsUnspecified`); `runWave1` skips straight to an explanatory warning — correct behavior, since no registry data exists for a private address. `pkg/webui` suite ~25s → ~2.3s.
8. **Honor an explicitly-emptied `HACKERFIVE_LOCAL_MODEL_URL`/`_NAME`.** Root cause: `getenvDefault` used `os.Getenv`, which can't distinguish "set to empty" from "unset" — both fell back to the built-in `localhost:11434`, so clearing the var still made `New()` probe a runtime that was never installed. Fix: `os.LookupEnv`; an explicit empty value short-circuits `localReachable()` (no 2s probe) and goes straight to the frontier tier.

`go build`/`vet`/`test -race`/`golangci-lint` clean throughout.

**Addendum, 2026-09-04 — Batch 1 of the decision-engine / recon→plan signal-use follow-ups (P0-3, P0-5, P0-4 from [docs/follow-up.md](follow-up.md)'s "Decision Engine & Recon→Plan Signal Use" section).** From a review of a real `plan`-equivalent pass over `andertone.com` (31 TechFacts / 4 hosts): the PlanTree was dominated by non-actionable and byte-identical leaves, and every `misconfig`/nuclei `Finding.Target` on a trailing-slash target carried a `//`. Batch 2 (P0-2) is separate.

1. **P0-3: `Finding.Target` no longer double-slashes on a trailing-slash target.** Root cause: the reported `Target` was built as `target + <path>` with no slash normalization (the fired request URL was already correct). Fix: `pkg/detectors/misconfig/detector.go`'s five affected finding fields (`checkExposedPaths`/`checkDirListing`/`checkDisallowedMethods`/`checkVerboseErrors`/`checkDefaultCreds`) now use `req.URL.String()`, reusing the already-correct request URL; root-only checks still report bare `target` (a trailing slash there is a valid URL). `pkg/template/nuclei/executor.go`: `Executor.Run` trims one trailing slash from `target` up front — Nuclei's `{{BaseURL}}` convention carries no trailing slash, so templates write `{{BaseURL}}/path`; one trim covers `path:` and `raw:`, and `runFlow` inherits it.
2. **P0-5: non-actionable-tech denylist.** `nonActionableTech` (`pkg/registry/decisionengine.go`): `http/2`, `http/3`, `hsts`, `wordpress block editor`, `hostinger`, `hostinger cdn`, `google cloud`, `google cloud cdn`. Checked at the top of `resolveTechFact` (before rule/tag matching) against `NormalizeTechName`'s whole version-stripped name — not a substring match, so `google cloud` won't also silence a `google cloud storage` finding. Each entry is a transport fact, a posture fact `misconfig` already checks directly (`hsts` ↔ `checkMissingHeaders`), a hosting/CDN brand with no scannable surface, or a sub-component a broader sibling fact covers (`wordpress block editor` ↔ `WordPress`). Removed 12 of 31 fact instances on the real stack, nearly all pure unresolved-leaf noise.
3. **P0-4: dedup leaves that run the identical check against the identical target.** `Resolve` keys every leaf via `leafDedupKey` and keeps the first in recon order — a pending leaf by `(target, detector)`, an unresolved leaf by `(target, NormalizeTechName(fact.Name))`. Many TechFacts on one host converge (PHP/WordPress/MySQL/nginx/LiteSpeed → `misconfig`; `Yoast SEO` + `Yoast SEO Premium` → one yoast template), so without this a host emitted a dozen-plus identical leaves. A host reduced to zero leaves no longer emits an empty host node. The surviving leaf's Rationale/Confidence are kept as-is; merging them across duplicates (e.g. keep the highest confidence) is deferred to P1.

Combined P0-5 + P0-4 on the real `andertone.com` stack (template index omitted, to isolate from Batch 2): **31 leaves / 4 hosts → 8 leaves / 4 hosts**. `go build`/`vet`/`test -race`/`golangci-lint` clean.

**Caveat:** the before/after was computed by feeding the saved recon JSON's 31-fact TechStack through `registry.Resolve` — the recon toolchain (`httpx`/`subfinder`/`naabu`/…) isn't installed here, so no live end-to-end `hackerfive plan` re-run yet.

**Addendum, 2026-09-04 — Batch 2: P0-2 ranked template-tag selection + canonical tech→tag map (subsumes P0-1a; P0-1b — true semver affected-version gating — deferred to P1-4).** All in `pkg/registry/decisionengine.go`'s `matchTemplateTags`; no caller/signature change.

Root cause: the old body returned the first `maxTemplateLeavesPerTech` index entries *in file order* whose tags shared any word with the normalized tech name — over-matched on generic words and surfaced whatever sat early in `templates/index.json` rather than the templates that matter.

1. **Selection is now by relevance score, not file order.** Every entry tied to the tech is scored, top N returned:
   - **Tag tier:** tag equal to the tech's *primary* (product) word → 100; any other include/word tag hit → 50; no product tag → dropped. (An ID/Name-substring tier was built and removed — on the real corpus it pulled in more product-prefixed false friends, e.g. `weaver-jquery-file-upload`, than genuine templates.)
   - **Severity:** critical +25 / high +15 / medium +6.
   - **CVE recency (P0-1a):** `CVE-YYYY` parsed from ID or tags; `(YYYY − 2016) × 4` for `YYYY ≥ 2016`.
   - **Stale-CVE penalty (P0-1a):** −20 for a pre-2016 CVE template, *only when the TechFact carried an explicit `:version`* (a current-looking version makes a decade-old CVE implausible, but recon's version can be wrong/spoofed, so deprioritize rather than drop). True affected-version gating needs an index schema with version ranges — P0-1b / P1-4.
   - **Sort:** score ↓, CVE year ↓, ID ↑ (deterministic). Cap raised **5 → 8** — kept entries are now the best, not arbitrary, and P0-4 dedup collapses cross-fact repeats.
2. **`canonicalTechTags` pins the tag set for names whose word match is known-wrong**, with `exclude` (tags) and `excludeIDSubstr` (ID substrings) for false friends the corpus tags with the bare product tag anyway. Six entries, every exclude verified against the real corpus's actual tags/IDs: `nginx` (excl `proxy-manager`/`ingress-nginx`/`nginxwebui`), `jquery` (excl tag `file-upload` + ID substr `jquery-file-upload`), `mysql` (excl `esafenet`/`eventum`/`weaver`/`ecology`/`fanwei`/`odoo`), and plain pins `wordpress`/`woocommerce`/`litespeed`. A name absent from the map uses the generic-word-filtered word set.
3. **`genericTechWords`** (`cloud`, `cdn`, `editor`, `block`, `cache`, `server`, `web`, `api`, `core`, `plugin`, `google`, `http`, …) never match a tag alone and can never be a name's primary word; pure-numeric fragments (`http/3` → `3`) are excluded too. Stops `WordPress Block Editor` → every `editor`-tagged template and `Google Cloud` → every `google`-tagged CVE.

**Real-index measurement** (`andertone.com` 31-fact TechStack × the real 7,716-entry `templates/index.json`): **107 template leaves → 74**, survivors now recent, severity-ranked CVE templates for the fingerprinted tech (WordPress/WooCommerce/LiteSpeed/PHP/MySQL) plus real `nginx` path-traversal/misconfig templates — every observed false friend gone. apex/`www` still carry identical lists — host canonicalization is a separate follow-up. `go build`/`vet`/`test -race`/`golangci-lint` clean (incl. `-tags integration`).

**Caveat:** as Batch 1 — before/after from the saved recon JSON's TechStack against the on-disk index, no live end-to-end run.

**Addendum, 2026-09-04 — P1 coverage: endpoint-driven leaves + WordPress plugin/theme enumeration (P1-1, P1-3, and P1-5's woocommerce row, from [docs/follow-up.md](follow-up.md)'s P1 section).** P1-2 (port-driven leaves) and P1-4 (nuclei loader DSL gaps) are deliberately not in this batch — see follow-up.md for why.

**Issue**: `pkg/mcpserver/tools_plan.go` already computed idor/authbypass/ssrf endpoint candidates (`recon.Suggest*`) into `baseCfg`, but `registry.Resolve` only ever emitted those leaves when a `TechFact` hit `techRules` (only `swagger`/`graphql`/`openresty`/`express` did) — so on a target with none of those techs, the candidates were computed and never used. Separately, `Resolve`'s host set only walked `TechStack`, never `Endpoints`, so an endpoint-only host was unreachable; WordPress plugin/theme versions sitting in already-crawled endpoint paths were never extracted into `TechStack` at all; and hyphenated tags like `contact-form-7` could never match because `matchTemplateTags`' word-decomposition always fragments a hyphenated name first.

**Solution**: new `resolveEndpointFacts` (`pkg/registry/decisionengine.go`) emits `idor`/`authbypass`/`ssrf` leaves by reusing the existing `Suggest*` functions per host, plus a `businesslogic` leaf on a cart/checkout-shaped path — deliberately without any new path auto-derivation, still relying on crAPI defaults or an operator-supplied `--coupon-*-path` (guessing mutating-request paths would violate CLAUDE.md's write-safety rule); `missingRequiredField` gained a matching `businesslogic` gate on `AllowWrites`+`AuthToken`. `endpointSignals` maps concrete observed endpoints (`xmlrpc.php`, `wp-json/wp/v2/users`) straight to specific template IDs, stronger evidence than a shared tag. `Resolve`'s host set now unions `TechStack` and `Endpoints`. `woocommerce` added to `techRules` → `misconfig`. New `pkg/recon/wpplugins.go` parses `/wp-content/plugins|themes/<slug>/` paths already in `ReconResult.Endpoints` (no new fetch) into one `TechFact{"<slug>[:<version>]"}` per host/slug, versioned from the URL's `?ver=` param when present; `scoreTemplateForTech`/`matchTemplateTags` gained a `fullSlug` tier so a hyphens-intact full slug is itself a primary-tier match candidate.

**Real result** (saved `andertone.com` recon JSON, real index): idor/ssrf/businesslogic leaves went from always-0 to 1 each; 9 real plugin/theme slugs extracted, 79 → 87 leaves after folding them in. Not yet exercised through a live Wave 3 crawl (recon toolchain absent in this environment) — verified via unit tests plus this real-data simulation.

**Addendum, 2026-09-04 — P1-2: port-driven visibility leaves.** Interim scope, an explicit choice: a `StatusUnresolved` leaf naming an open port, no new detector — real TCP-service checking (anonymous FTP, unauth Redis, etc.) is a separate, larger follow-up, since `pkg/template/nuclei/loader.go`'s `disallowedBlocks` hard-rejects any template with a top-level `tcp:`/`network:` block, so the whole class of templates that could check these is unloadable in this codebase today regardless of decision-engine wiring.

**Known, accepted cost, decided explicitly rather than by omission**: `llmfallback.ResolveTreeLeaves` sends *every* `StatusUnresolved` leaf to a real LLM call, and a port leaf can never resolve into anything real (see above) — so on a frontier-tier-only setup, every scan with a common infra port open burns a doomed-to-fail paid call. The alternative (a new `PlanNodeStatus` excluded from that walk) was scoped and rejected for now — it touches `agenttask`'s shared status vocabulary (part of the MCP tool's JSON output) and the Web UI's badge rendering, real added scope beyond pure `pkg/registry` wiring. Logged in follow-up.md for whoever revisits this.

1. **`resolvePortFacts`** (`pkg/registry/decisionengine.go`): one leaf per open port on a host that `interestingPorts` recognizes (`21`/ftp, `23`/telnet, `3306`/mysql, `5432`/postgresql, `6379`/redis, `9200`/elasticsearch, `27017`/mongodb) — naabu's own `PortFact.Service` string is used in the rationale when present, more specific than the static table's generic name. `Resolve`'s host set now also unions `Hosts[].Ports` (a raw-TCP-only host with no HTTP surface at all was otherwise unreachable, same shape as P1-1's Endpoints-host fix).
2. **Real bug caught by measuring against real data before writing this up**: the first version keyed a port leaf's dedup entry with a synthetic `"port:<N>"` name fed through `unresolvedDedupKey`, which normalizes via `NormalizeTechName` — and `NormalizeTechName` strips everything from the *first* `:` onward. `"port:21"` and `"port:3306"` both normalized to bare `"port"`, so every port leaf on one host silently collapsed into whichever port came first. Caught immediately: `staging.andertone.com` genuinely has both 21 and 3306 open, and only 21 was surviving. Fixed by switching the synthetic name to a dash (`"port-<N>"`), which `NormalizeTechName` doesn't split on. Every synthetic test case up to that point had used exactly one port per host, so unit tests alone hadn't caught it — a `TestResolve_MultipleInterestingPorts_AllProduceLeaves` regression guard was added specifically because of this.
3. **Real-data measurement** (`andertone.com`, real index, after the fix): `staging.andertone.com` now correctly produces two leaves — `port 21/tcp (ftp)` and `port 3306/tcp (mysql)` — 81 leaves total, up from 79 (pre-P1-2) / 80 (P1-2 with the bug still live, port 21 only).

Tests: `pkg/registry/decisionengine_test.go` — `TestResolve_{InterestingPortOpen_ProducesUnresolvedLeaf,UninterestingPortOpen_NoLeaf,PortService_PrefersObservedOverStaticTable,MultipleInterestingPorts_AllProduceLeaves,PortLeafAndUnrelatedUnresolvedTechFact_BothSurvive}`. `go build`/`vet`/`test -race`/`golangci-lint` clean (incl. `-tags integration`).

---

**Addendum, 2026-09-04 — P1-4 (partial): `content_type_N`/`duration`/`duration_N` DSL support.** `pkg/template/nuclei/`. Real corpus measurement first (the doc's "1-10 templates each" estimate for these was stale): of 1,966 templates rejected at load, `duration`/`duration_N` alone was 280 (14%) and `content_type_N` 63 (3%) — by far the largest addressable DSL gaps, not the small ones the estimate suggested.

1. **`content_type_N`** — a direct extension of the pre-existing `body_N`/`header_N`/`status_code_N` mechanism (`loader.go`'s `rawIndexedDSLContext`, `executor.go`'s `tryRawIteration`): same per-raw:-entry binding, same load-time dummy-context validation, no new design.
2. **`duration`/`duration_N`** (elapsed whole seconds) needed no new `dsl.Context` field — routed through the existing `IntVars` map, the same mechanism `status_code_N` already uses, since a bare identifier here has no dedicated Context field to alias from (unlike `status_code`/`body`/`header`/`content_type`). Bound in `tryRawIteration` (per raw: entry, plus a bare `duration` aliased to the last entry) *and* `tryPath` (bare `duration` only) — real corpus check showed 227/230 duration-using templates are raw:-based but 3 are plain `path:`-based (e.g. upstream's `CVE-2023-2130.yaml`), so both request styles needed it. All 230 real threshold comparisons use integer seconds with `>=`/`>` (none exact-equality, none fractional) — confirmed before implementing, so int-truncated-seconds is a faithful representation, not a shortcut.
3. **Known, accepted caveat**: measured duration is wall-clock around `client.Do`, so it includes this project's own retry/backoff time (`pkg/scanner/httpclient`'s `WithRetry`, up to ~3 attempts) on a transient failure — a narrow over-counting risk on a flaky connection, not specially excluded.
4. **Real-data result**: re-running the same load-time classification against the full corpus, 1,966 → 1,634 rejected (332 templates newly loadable). The `dsl: duration`/`dsl: content_type_N` buckets are gone except 3 genuine edge cases (2 templates hit a second, still-open gap behind the one just fixed; 1 references an out-of-range `duration_2` on a single-raw-entry block, same class as the pre-existing out-of-range `body_N` cases).
5. **Also corrected while measuring**: `docs/follow-up.md`'s multi-key `payloads:` (pitchfork/clusterbomb/batteringram) estimate — "2 templates only" was wrong. The same-day "485" re-estimate was *also* wrong (see the dedicated addendum below) — it conflated multi-key rejections with the separate file-based-`payloads:` gap. Left as a separate follow-up item either way, not folded into this pass (unrelated feature — payload-iteration strategy, not a DSL/`part:` gap).
6. **Deliberately not in this pass** (still open except items 6a/6b, see `docs/follow-up.md`'s P1-4 entry for the full list): several smaller items (`location`/`server`/`set_cookie` parts, `xpath` extractor type, `flow:` `set`/`for`, DSL `+`/`replace`/`trim_space`/`startswith`).
   6a. The `body_N`/`header_N`-as-`part:`-value gap for `path:`-multi-request templates, estimated here as "~220 templates — a real correlation-model refactor" — done, see the dedicated addendum below. Real measurement found the true correlation-refactor slice was only ~40 templates; the ~220 estimate had conflated it with a separate, much larger (239 templates), zero-execution-risk `part:`-recognition gap on already-working `raw:` templates.
   6b. `interactsh_*`/OOB, estimated here as "~350, separate infra project" — done, see its own dedicated addendum below. Real measurement found 532 templates reference it (larger than the estimate), 519 rejected at load; 488 net newly-loadable after the work.

Tests: `tests/unit/nuclei_loader_test.go` — `TestNucleiLoadDir_{MultiRawEntry_ContentTypeAndDurationLoad,BareDurationOnPlainPathTemplateLoads}`; `tests/unit/nuclei_executor_test.go` — `TestExecutorRun_{PathDuration_SlowResponseMatches,PathDuration_FastResponseNoMatch,RawDurationN_CorrelatesPerEntry,RawContentTypeN_Correlates}` (real `httptest` servers, including an actual slow-vs-fast timing comparison). `go build`/`vet`/`test -race`/`golangci-lint` clean (incl. `-tags integration`).

---

**Addendum, 2026-09-04 — Multi-key `payloads:` (attack: pitchfork/clusterbomb/batteringram).** `pkg/template/nuclei/schema.go`. The single largest item surfaced by the P1-4 measurement, deliberately kept as its own follow-up item rather than folded into P1-4 (unrelated feature — payload-iteration strategy, not a DSL/`part:` gap).

1. **Root cause**: `resolvePayload` (singular) hard-rejected any request with more than one `payloads:` key, so every real credential-stuffing/multi-position template (`default-logins/*`, mostly `username`+`password` pairs) never loaded regardless of the attack mode it declared.
2. **Solution**: `resolvePayloads` (plural) returns every substitution pass for however many keys exist, per the declared (or default `batteringram`) attack mode — `pitchforkIterations` (zip every key's list together, index i of each, for i = 0..shortest-list-length-1), `clusterbombIterations` (full Cartesian product via an odometer-style counter — no equal-length requirement, that's the point), `batteringRamIterations` (one shared list — the first sorted key's — broadcast into every key at once). `runPathRequest`/`tryRaw` in `executor.go` now iterate `[]map[string]string` instead of a single key/value pair; `tryPath`/`tryRawIteration` were unaffected (they already merged an arbitrary `extraVars` map).
3. **Why these three semantics specifically**: Nuclei borrowed the naming directly from Burp Intruder's own identically-named, well-documented attack types — not derived from the nuclei source itself, but cross-checked against real corpus templates before writing code (e.g. `zabbix-default-login.yaml`'s `clusterbomb` with lists of length 2/1/1 declares `metadata: max-request: 2`, exactly `2×1×1` — confirms the cartesian-product read). Pitchfork's shortest-list truncation on a length mismatch (7 of 207 real pitchfork templates) matches Burp's own documented behavior, not a guess. Battering ram's multi-key broadcast semantics are unverified against a genuine real example (all 13 real corpus battering-ram templates define only one key, where every mode degenerates identically) but match the documented Nuclei/Burp definition.
4. **A real correction to a same-day estimate**: the "485 templates" figure logged against this item earlier today (see the P1-4 addendum above, item 5) was itself wrong — the classifier bucket it came from conflated genuine multi-key rejections with the separate file-based-`payloads:` gap (an external wordlist file, e.g. `payloads: {path: helpers/wordlists/adminer-paths.txt}`), since the old code's `len(Payloads) > 1` check ran before any per-key inspection. Direct YAML inspection (not the load-error classifier) gives the real split: 238 templates multi-key-only, 248 file-based-only, 3 both (the file-based half done separately — see the addendum below).
5. **Real-data result**: 1,634 → 1,434 rejected (200 templates newly loadable) — short of the 238 "should now load" figure because some templates hit a second, still-open gap behind this one (real example: the pitchfork template `CVE-2019-15642.yaml` also uses `part: body_2`, the still-open `path:`-multi-request correlation gap tracked in the P1-4 addendum above).

Tests: `tests/unit/nuclei_loader_test.go` — `TestNucleiLoadDir_{MultiKeyPayloadsLoad,UnsupportedAttackModeRejected}`; `tests/unit/nuclei_executor_test.go` — `TestExecutorRun_{Pitchfork_ZipsKeysLockstep,Clusterbomb_TriesEveryCombination,BatteringRam_BroadcastsSingleListToAllKeys}` (each proves the actual combinatorics via request counting against a real `httptest` server, not just that the template loads). `go build`/`vet`/`test -race`/`golangci-lint` clean (incl. `-tags integration`).

---

**Addendum, 2026-09-04 — File-based `payloads:` (WordPress-version-detection pattern).** `pkg/template/nuclei/schema.go`, `pkg/templatesync/sync.go`, `pkg/template/dsl/dsl.go`. Smaller and simpler than the original backlog description once inspected directly against real templates, rather than assumed.

**Issue**: the real pattern (`http/technologies/wordpress/plugins/wp-crontrol.yaml`-style: `payloads: {last_version: helpers/.../wp-crontrol.txt}`) is a single-line version file read via `compare_versions(internal_detected_version, concat("< ", last_version))`, using the same-request extractor→matcher binding this project already had working — no new correlation mechanism needed, despite the backlog implying one. Three real blockers: the synced corpus only ever fetched `http/`, never upstream's `helpers/` directory the payload files live in; a request's `payloads:` variable was rendered into the request but never bound into DSL-visible `ExtraVars`, so a `dsl:` matcher referencing its own payload variable by name (the WP-version pattern's entire premise) silently evaluated as "unknown identifier" and produced zero findings; and `yaml.v3`'s `node.Decode(&[]string{})` silently drops a `null` list entry instead of decoding it as `""`, rejecting a genuine "try a blank password" default-login template (`password: [null]`).

**Solution**: `pkg/templatesync.SupportDirs` (`["helpers"]`) sparse-checks out `helpers/` alongside `Categories` (kept separate since `Categories` also drives the per-category template-count display). `Template` gained an unexported `sourceDir`; `schema.go`'s `readPayloadFile` resolves a file-based `payloads:` value relative to it (one value per non-empty line, path-traversal guarded). `dsl.go` gained `concat()`. Payload-iteration values now merged into both requests' `ExtraVars` alongside `chainVars`. `decodeStringSequence` walks the YAML sequence node directly and decodes a `!!null`-tagged entry as an explicit empty string.

**Real result**: 1,434 → 1,183 rejected — 251 templates newly loadable, the complete file-based-only count with no shortfall.

---

**Addendum, 2026-09-04 — `body_N`/`header_N`-as-`part:`-value gap + the genuine `path:`-multi-request correlation refactor.** `pkg/template/matcher/matcher.go`, `pkg/template/extractor/extractor.go`, `pkg/template/nuclei/{schema,loader,executor}.go`. Real measurement reshaped this item entirely — the original "~220 templates, a real correlation-model refactor" estimate turned out to bundle two very different-sized, very different-risk fixes.

**Issue**: of 1,183 templates rejected at load, 246 hit "unsupported part" on an indexed name (`part: body_2`/`header_2`/`content_type_2`) and 33 hit "unknown identifier" on the equivalent `dsl:` form. 239 of the 246 were already `raw:`-based templates whose `body_N`/`header_N` correlation already worked (`tryRawIteration` already binds these into `Response.ExtraVars`) — the only gap was that `matcher.ValidPart`/`Part()` never recognized an indexed `part:` *name* as valid syntax at all. The genuine remainder — 7 `part:`-shaped + 33 `dsl:`-shaped = 40 real templates, not ~220 — are all plain `path:`-based (no `raw:`) referencing an indexed identifier across more than one `path:` entry (e.g. `CVE-2012-3153.yaml`'s Oracle Reports RCE: a benign-endpoint probe and an exploit probe whose bodies must be checked together). A third gap found after fixing the first two: several templates reference the `_1`-suffixed form on a genuinely single-path request — real Nuclei always accepts `_1` as a synonym for the bare identifier.

**Solution**: `matcher.IsIndexedPart` + `ValidPartWithContext` (accepts an indexed name only when the caller's `dsl.Context.Vars` already carries that key, the same per-request existence check `dsl:` identifier validation already does) + `Part()` falling back to `r.ExtraVars[part]` fixed the 239 with zero execution-model risk and no `executor.go` change. For the genuine 40-template gap: an opt-in `HTTPRequest.pathCorrelated` flag, set at load time only when a plain multi-path request's matchers/extractors actually reference an indexed identifier (`loader.go`'s `usesPathCorrelation`) — every other multi-path template (~9,000+) is untouched and keeps today's independent try-each-path behavior. A flagged request routes through new `runPathRequestCorrelated`/`tryPathCorrelatedIteration` (`executor.go`), a direct port of `tryRawIteration`'s per-entry binding/evaluate-once model but firing `Path` entries instead of parsing `Raw` blocks. `indexedDSLContext` widened to seed index-1 dummy vars for any `path:` request (not just >1 entries); `tryPath` binds `body_1`/`header_1`/`content_type_1`/`status_code_1`/`duration_1` directly as aliases of the bare identifiers.

**Real result**: 1,183 → 923 rejected (260 templates newly loadable). Remaining 5 `identifier_N_unknown` rejections are a distinct gap — real Nuclei's `flow:` templates number `_N` globally across separate top-level `http:` blocks, not per-block — logged separately, not chased in this pass.

---

**Addendum, 2026-09-04 — `interactsh_*`/OOB support for nuclei templates.** `pkg/oob/{interactsh,poller}.go`, `pkg/scanner/{config,engine,vars/substitute}.go`, `pkg/template/matcher/matcher.go`, `pkg/template/nuclei/{schema,loader,executor}.go`. Wires the existing `pkg/oob` Interactsh-protocol client (previously standalone-only, no consumer but the ssrf detector) into the nuclei template engine — estimated in this plan as "~350, separate infra project."

**Issue**: 532 synced-corpus templates reference `{{interactsh-url}}`/`interactsh_protocol`/`interactsh_request`/`interactsh_response` (larger than the "~350" estimate), 519 rejected at load — `matcher.ValidPart` hard-rejected these as "out-of-band, not supported," and `{{interactsh-url}}`/`{{randstr}}`/`{{RootURL}}`/`{{Host}}` were all unrenderable besides (a hyphen the vars regex couldn't match, and three entirely unimplemented builtins). Separately, a shared `oob.Client`'s `Poll()` has "everything since last poll" semantics that implicitly clears server-side state — unsafe once `nuclei.Executor` (built once per scan, shared across worker-pool goroutines) has multiple targets waiting on distinct probes concurrently, since one caller's poll can silently steal another's still-pending interaction.

**Solution**: `HTTPRequest.usesInteractsh` (load-time flag, same pattern as `pathCorrelated`) gates whether a request pays any OOB cost. `prepareOOB`/`awaitOOB` (`executor.go`) fire one fresh correlation host+nonce per request execution (shared across every entry in a correlated `raw:`/`path:` block, matching real Nuclei's per-template-execution scope) and, once every entry has fired, wait up to 6s for a callback — always returning all three `interactsh_protocol/request/response` keys (real values or `""`, never omitted), so `matcher.Part` can never fall through to the response body for them; `Part()` itself was hardened the same way regardless of caller discipline. New `oob.Poller` (`pkg/oob/poller.go`) centralizes every `Poll()` call behind one background loop + nonce→waiter channel map, started once with a long-lived `context.Background()` (never an individual request's own context, so one caller canceling can't stop polling for the rest). Registration is lazy (`sync.Once`, only once a loaded template actually needs it) and reuses `scanner.Config.OOBServers` — the same value `--oob-server`/`--no-oob` already feeds the ssrf detector, not a second config surface. Side fixes: `vars.placeholderPattern` widened to match hyphens; `randstr()`/`RootURL`/`Host` implemented as documented `BaseURL`/`Hostname` aliases.

**Verification, per the user's explicit ask**: every test registers exclusively against a local `httptest.NewServer` fake Interactsh server (`newFakeOOBServer`, reused from `detector_ssrf_test.go`) — confirmed via `git diff` grep across every changed file that no real `oast.pro`/`oast.live`/public server URL appears anywhere in code or tests, only doc-comment prose.

**Real result**: 519 → 31 rejected among the 532 interactsh_-referencing templates (488 net newly-loadable). Remaining 31 are all pre-existing, unrelated gaps (disallowed `tcp:`/`javascript:` blocks, `flow:` `if`/`set`, `location`/`set_cookie` identifiers, `xpath` extractor, absolute-URI raw requests, `internal: true` outside `flow:`, `flow:` cross-block `_N` indexing).

**Known, accepted tradeoffs**: `awaitOOB` blocks inline and serially per template (this project fires templates against one target sequentially); real Nuclei instead fires everything OOB-needing first, then does one deferred bulk-correlation pass — a materially larger change, logged in `docs/follow-up.md` rather than attempted here. `oob.Poller` also polls continuously every 2s for the scan's duration once triggered, a real increase in sustained traffic to whatever OOB server is configured vs. ssrf's poll-once-per-check pattern — also logged, unmitigated.

---

**Addendum, 2026-09-04 — P2: LLM leverage & ergonomics (P2-1 through P2-6, [docs/follow-up.md](follow-up.md)).** `pkg/registry/decisionengine.go`, `pkg/llmfallback/{leaf,resolve,planfromrecon}.go`, `pkg/templatesync/drift.go`, `cmd/hackerfive/{plan,recon,templates,scopeflag}.go`, `pkg/mcpserver/tools_plan.go`, `pkg/webui/handlers_{plan,launch}.go`.

- **P2-2/P2-3 (structured leaf context; dispatchable `use_existing_tag`).** `registry.Resolve` now returns `(*PlanTree, map[string]LeafContext)` — the originating `TechFact`/`PortFact`/endpoints for each unresolved leaf, keyed by ID. `ResolveLeaf` reads it directly instead of regexing `leaf.Rationale` (`techNameFromRationale` kept only as a fallback for a caller with no context, e.g. a cached webui tree that predates this change). `buildLeafPrompt` now lists ranked-relevant *templates* by `id: name` (new `rankRelevantTemplates`, built on P0-2's existing `rankRelevantTags`) instead of shared tags, since `RunPlan` can only dispatch a `Detector` that's a real capability name or `templatesync.Entry.ID` — a `use_existing_tag` decision naming a bare tag was undispatchable regardless of how good the decision was. `Resolve`'s signature change touches 8 call sites (cmd, mcpserver, webui ×2, 2 integration tests, 2 unit-test files) — all updated to discard or thread the second value as appropriate.
- **P2-1 (`PlanFromRecon`, 4th `llmfallback` caller).** New `pkg/llmfallback/planfromrecon.go`: one local-tier-first call per plan run proposing `{target, detector, rationale}` leaves beyond per-fact matching, merged in by `MergeLLMProposals` under two hard filters (`Target` must already be a host node `Resolve` itself produced; `Detector` must be a real capability/template ID) — an LLM-invented target or detector name is dropped, never merged as a live, dispatchable leaf. **Deliberately not wired into MCP `plan`/webui's default flow**: `pkg/llmfallback`'s package doc states I4 fires "only on a confirmed deterministic-decision-engine miss — never as a standing parallel path," and an unconditional per-plan call would be exactly that; wired only into CLI `plan --llm-assist` (itself opt-in). A real, later decision for whoever wants I4 as a standing broader-coverage pass in MCP/webui too. Redaction ended up lighter than expected: `ReconResult`'s fields already carry no raw body/header/cookie data by design (doc91 §4); only `HostFact.Notes` (WHOIS/ASN free text) is dropped from the prompt summary.
- **P2-4 (`--llm-assist` for CLI `plan`).** Calls `ResolveTreeLeaves` then `PlanFromRecon`/`MergeLLMProposals`, off by default. Not wired into `scan`: it already requires `--detector`/`--endpoint` explicitly, so there's no unresolved-leaf/field-miss for I4 to resolve there — "wire I4 into scan" had no concrete referent once checked against the real command.
- **P2-5 (index/corpus drift guard).** `templatesync.CountTemplateFiles` (a file count, not a full parse) + `IndexDriftWarning` compare `templates/index.json`'s entry count against real on-disk `.yaml`/`.yml` files across `templates index`'s own dirs; `plan` warns on a wild mismatch (the real scenario: a stale index against an emptied/re-pointed synced dir). Not wired into `scan` — it never reads `index.json` at all, always a live parse of `--templates` dirs.
- **P2-6 (`--scope` hard-fail for CLI `plan`/`recon`).** New `requireScopeOrOptOut` (`cmd/hackerfive/scopeflag.go`) refuses without `--scope` unless `--allow-no-scope` is explicit; `scan` keeps its warn-only CLI behavior (its `--targets` is already the exact host list, no discovery-driven expansion the way `recon`'s subfinder/katana waves have). **A live user-design discussion reversed Step 3's own D3 framing** (CLI-warn/MCP-hard-fail as a permanent, intentional split) for `plan`/`recon` specifically — see D3's note above and follow-up.md's P2-6 entry for the full reasoning (autonomous/unattended CLI runs need the same protection an MCP call gets; a `*.example.com` scope entry still authorizes free exploration of that whole subdomain tree, this only blocks running with *no* boundary at all). The separate MCP `plan` tool's approve-before-execute elicitation gate (Step 2 above, doc90 Decision 5/6) came up in the same discussion and was explicitly kept as-is, not touched by this item.

`go build`/`vet`/`test -race`/`golangci-lint` clean, incl. `-tags integration`.

---

## Step 3: Hard Safety Blockers + Scope-Creep Gate + Cost-Aware Prioritization (Weeks 44-45) — ⬜ not yet implemented

### Design

**D2 — program-policy pre-flight check, a hard blocker.** Before any agent-driven run against a real (non-lab) target, check the target's disclosure policy (via [22-authorized-targets.md](22-authorized-targets.md)'s registry, or a fetched `security.txt`/program policy — doc14's Wave 0 already fetches this during recon) for whether automated scanners are disallowed — refuse to proceed if so. This is the one item in doc90's whole backlog with a documented real-world cost of skipping it (XBOW's own program removal, doc90 §2) — implemented as a hard block, not a warning, unlike `--scope`'s existing softer treatment.

**D3 — hard-fail, not warn, on missing `--scope` for agent-initiated runs.** The CLI's existing "warn, don't silently proceed" behavior for a missing `--scope` (doc02 §3) is the right default for a human at a terminal who typed the command themselves; it's the wrong default for an agent-initiated `scan`/`recon` MCP tool call, where nobody read the warning. Both tools reject the call outright if `--scope`-equivalent isn't set, rather than proceeding with a stderr line nobody's watching. **Superseded in part, 2026-09-04 (P2-6 addendum below):** this CLI-warn/MCP-hard-fail split was revisited for `plan`/`recon` specifically — the CLI now hard-fails there too (with an explicit `--allow-no-scope` opt-out), since the user's stated goal (HackerFive running autonomously, unattended, without a human present to read a stderr warning) applies just as much to a human-typed CLI invocation left to run in a script/cron as to an MCP tool call. `scan` keeps the original warn-only CLI behavior — see the addendum for why the distinction still holds there.

**B4 — scope-creep gate, first implementation.** doc90's B4 requires fresh approval when a scan's own recon surfaces hosts/paths outside `--targets`/`--scope`; doc14's `ReconResult.OutOfScope` (doc91's R6) is the producer this gate has been missing. Concretely: Step 2's new executor is the actual caller — after each leaf's execution (whether that's the `recon` tool directly or a leaf-scoped re-run mid-scan), the executor checks whether that leaf's result populated `OutOfScope`; if so, it halts dispatch of that leaf's remaining siblings and a second `elicitation` round trip (reusing Step 2's `plan` mechanism) is required before anything touches the newly-found hosts. Naming the executor as the trigger point here closes what was otherwise a gate with no specified caller. Phase 7 Step 2 rounds this out with audit-trail/documentation coverage; this is where the gate first actually exists and blocks something.

**H4 — cost/attempt-aware prioritization.** A per-leaf attempt counter and running spend tracker on doc14's `PlanTree`, applying MAPTA's own measured finding as a concrete rule: rising tool-call count, dollar cost, token count, and elapsed time on one leaf are each independently correlated with *falling* odds of success (r = −0.66, −0.61, −0.59, −0.56 per doc90 §2) — "still grinding after N attempts with no confidence increase" surfaces as a stop-and-escalate signal to the coordinator (via the leaf's `Status`), not a reason to allocate more budget to the same leaf.

**`Retry-After`-aware backoff (small, from [follow-up.md](follow-up.md)).** `pkg/scanner/httpclient`'s `WithRetry` uses fixed exponential backoff and ignores a `429`/`503` `Retry-After` header. Honor it (clamped to a sane ceiling) so an unattended or agent-driven run stays inside a program's stated rate limits with nobody watching stderr — the same "an unattended run needs the protection a present operator would give" reasoning P2-6 applied to the scope hard-fail. Not agent-specific; it rides here because this is the step about respecting program constraints.

### Files (anticipated, confirm at implementation time)
- `pkg/mcpserver/tools_scan.go`/`tools_recon.go` — D2/D3 checks added at the top of each tool handler, before any request is fired.
- `pkg/mcpserver/tools_plan.go` — B4's out-of-scope check and re-elicitation trigger.
- `pkg/agenttask/` (doc14's `PlanTree` location) — `PlanNode` gains `Attempts`, `Spend`, and the stop-and-escalate signal derived from H4's rule.
- `pkg/scanner/httpclient/` — `WithRetry` honors a `429`/`503` `Retry-After` header (capped), not just fixed exponential backoff.
- `tests/unit/preflight_test.go` — D2 (policy-disallowed target rejected) and D3 (missing scope rejected, not warned) cases.
- `tests/unit/scope_creep_test.go` — a `ReconResult` fixture carrying `OutOfScope` entries triggers a fresh elicitation rather than proceeding.

### Verification
Unit tests for both hard-fail paths and the scope-creep trigger. Live verification for D2 needs a real target with a documented no-automated-scanners policy (or a synthetic one for test purposes) — confirm the block actually fires, don't assume from the code alone. Live verification for B4: a recon run against a target whose crawl surfaces a genuinely out-of-scope linked domain (doc91 Wave 3's own example) triggers re-approval before that domain is ever touched.

---

## Step 4: Approval UI — Make the Plan Preview Actionable (Week 46) — 🟡 partially implemented, 2026-09-04

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

### Done note, 2026-09-04 — shipped, deliberately narrower than "resolves the same elicitation" above

Triggered by `docs/follow-up.md`'s LT-1 ("Web UI Launch never dispatches the decision engine's own template-ranked leaves") — `pkg/webui`'s Plan Preview page computed a real, tag-ranked `PlanTree` via `registry.Resolve` but had no way to execute it; only a CLI/MCP `plan --llm-assist` run ever dispatched one.

**Shipped:**
- `pkg/planexec` (new) — `RunPlan`/`missingRequiredField`/`runLeaf` extracted from `pkg/mcpserver/executor.go` into a shared, transport-agnostic package (`ExecOptions{Notify, OnFinding, OnLog, Excluded, DetConcurrency, LLMConcurrency}`) both `pkg/mcpserver` (Step 2's `handlePlanApproval`) and `pkg/webui` now call — the exact same dispatcher, not a parallel reimplementation.
- **Approve / Reject**, whole-plan — `POST /plan-preview/execute` (`pkg/webui/handlers_plan_exec.go`), redirects to `/scans/{id}` so results stream in live via the job's existing SSE feed.
- **Edit, scoped to per-leaf inclusion** — `fragment_plan_node.html`'s "run this leaf" checkbox (default checked), submitted as `include`; an unchecked leaf is reported skipped (`ExecOptions.Excluded`), never silently run. Not full per-field editing (target/detector) — that was never concretely specified even in this doc's own Design section above, and per-leaf inclusion covers the real "I don't want that one to run" case.
- **Budget gauge** — `<progress>` against `Tree.SpendSoFar()`/`Tree.SpendCeilingUSD`, `plan_preview.html`.
- **Kill switch** — `Job.Cancel()` (new `ctx`/`cancel` on `Job`, derived from `baseCtx` via `bindParentContext`), `POST /scans/{id}/cancel`, surfaced once in `fragment_progress.html` — confirmed reachable from New Scan, Guided Scan-successor (the unified Launch flow), and a plan-execution run alike, since all three render that one fragment (the "three call sites, one control" scoping note above). `MarkDone` records a distinct `StatusCanceled` (not `StatusFailed`) for `context.Canceled`.

**Deliberately not shipped — the "resolves the same `elicitation` response... interchangeably" framing above**: `pkg/mcpserver` (`hackerfive mcpserve`) and `pkg/webui` (`hackerfive serve`) are two separate, unconnected OS processes in this codebase, with no shared pending-approval store between them — confirmed by reading `cmd/hackerfive/{mcpserve,serve}.go`. Building that would mean new cross-process infrastructure (e.g. a shared file-backed or IPC pending-approval store) this step's own "Files (anticipated)" list never named. What shipped instead is the Web UI's own complete, self-contained approval surface — real Approve/Reject/Edit/budget/kill-switch, all live-reachable from the browser — not a stub deferring to that cross-process mechanism. Revisit the interop framing specifically if a real user workflow needs it (e.g. approving a live MCP-driven agent session's plan from the Web UI while the agent's own client sits disconnected) — no such workflow has surfaced yet.

Verification: `go build`/`go vet`/`go test ./... -race`/`golangci-lint run ./...` all clean; new unit coverage in `pkg/planexec/executor_test.go`, `pkg/webui/{jobs_test.go,handlers_plan_exec_test.go}` (Approve dispatches included leaves and reopens a terminal job's SSE lifecycle; Reject executes nothing; excluded leaves are skipped not silently dropped; Cancel cancels the job's own context and `MarkDone` records `StatusCanceled`). Not yet live-verified against a real browser/lab target — that's still open, same as this step's own Verification paragraph above already called for.

---

## Step 5: Session Log + Release (Weeks 47-48) — ⬜ not yet implemented — `v0.6.0`

### Design

**C1 (minimal) — agent session log.** A structured, append-only record of every MCP tool call, the coordinator's stated reasoning for it (if the calling agent provides one — this is a courtesy field the tool schemas accept, not something HackerFive can force an agent to fill honestly), and the raw result. Persisted per job (reusing `Job`'s existing accumulation pattern from doc12). **Not yet the Web UI's live Agent tab** — that's Phase 7 Step 3's job; this step's deliverable is that the log exists, is queryable, and is complete, even if today it's only inspectable via a CLI dump or the MCP server's own `job.log` equivalent.

Full integration testing across Steps 1-4 together (a real MCP client running a recon → plan → approve → scan → findings.export round trip against a lab target), then release.

**Lab targets for this round trip, added 2026-09-02: crAPI/DVWA plus WebGoat/bWAPP (added to [20-setup-testing-targets.md](20-setup-testing-targets.md)/[20-setup-testing-targets-macos.md](20-setup-testing-targets-macos.md) the same day).** crAPI still covers the credentialed path (a `plan` proposing `idor`/`authbypass` leaves against a target `misconfig`-only lab apps can't exercise). WebGoat/bWAPP are useful for a different, complementary reason: both are `misconfig`-only today (no registry entry drives them toward `idor`/`authbypass`/`ssrf`), so a real plan against either should resolve every leaf deterministically via R8 with **zero I4 fallback calls** — a clean, live confirmation that "deterministic-first" actually means zero LLM invocation on the common case, not just zero on average. Whichever of WebGoat's Spring Boot fingerprint or bWAPP's PHP/Apache fingerprint the registry *doesn't* already have an entry for is also a candidate for live-verifying I4's registry-miss fallback path itself (Step 2's I4 paragraph) — a real, natural unresolved leaf rather than a synthetic one contrived for the test.

**Real-target confirmation, separate from the lab-target round trip above:** Step 2's I4 section records a real, live-hit gap against aalberts.com (2026-09-02) — `idor`/`authbypass`/`ssrf` all skipped, `misconfig` ran the full unnarrowed corpus. Once I4's first pieces exist, re-run that same aalberts.com scan (not a lab target, so not part of this step's own round-trip fixture set above) as the before/after confirmation that both gaps are actually resolved, per that section's commitment.

**First re-run, 2026-09-03, via the Web UI: partial confirmation, and a real scoping gap found.** `misconfig`'s corpus narrowing is confirmed — 25 templates ran, not the full ~9,652. `idor`/`authbypass`/`ssrf` still skipped, but tracing why showed the re-run wasn't exercising I4 at all: the Web UI's New-Scan launch flow (`pkg/webui/handlers_launch.go`) had no `pkg/llmfallback` wiring whatsoever — only the MCP `plan` tool did (Step 2's addendum item 2 only reached `/plan-preview`, a separate page). Closed same-day by the addendum's item 3 above — `fillReconFields` now surfaces an I4 field suggestion on a genuine miss (`idor`/`authbypass` only, per that item's scoping note), though by design the detector still skips rather than auto-running on an unreviewed guess. **The aalberts.com re-run should be repeated now that this landed**, to confirm live (with a real local model configured) that the suggestion actually appears and is genuinely not auto-applied — not yet done this session, unit-tested against a fake local server only.

### Files (anticipated, confirm at implementation time)
- `pkg/agenttask/sessionlog.go` (or peer to `Job`) — the append-only log type.
- `tests/integration/agent_e2e_test.go` — full round trip against a lab target via a real or scripted MCP client.

### Verification
The full round trip (recon → plan proposal → human approval via elicitation or the Web UI → scan execution with live findings/logs → findings.export) works end-to-end against at least one lab target (crAPI or DVWA), live-verified, not just unit-tested piecewise. Also live-verified against WebGoat and/or bWAPP specifically for the all-deterministic, zero-fallback-calls case named above.

---

## Step 6: Scan-Execution Efficiency — Corpus Scoping + Concurrency + Corpus-Once-Per-Host (added 2026-09-05) — 🟡 (a) done 2026-09-06, (b)+(c) done 2026-09-05; (d) not yet

### Design

Three compounding causes of "a scan spends most of its wall-clock on templates
unrelated to the target," from [follow-up.md](follow-up.md) LT-18 (live-measured against
`andertone.com`: one builtin leaf still running after 53+ min on ~16s CPU) and a
2026-09-06 nettix.com.pe review (`scan --detector misconfig` loaded 9,476 templates,
`0 filtered by tag`, and still hadn't finished after 2 min). Fixed cheapest-first:

- **(a) Corpus scoping — a detector-category floor plus tech-fact extras (default-on).**
  `scan --detector X` loads the *entire* ~9,476-template synced corpus regardless of `X`
  or of what recon fingerprinted, because `--narrow-by-tech` is opt-in *and* requires a
  `--recon-file`, *and* `registry.TechStackTags` returns only product-fingerprint tags
  with **no generic floor** — verified: feeding its output straight to `--tags` would
  drop every `.env`/`.git`/missing-header/CORS/backup check, i.e. exactly the templates
  that pair with `misconfig`. Fix, three parts:
  1. **`registry.DetectorTemplateTags(detector)`** — a per-detector category-tag floor,
     always applied (with or without recon): `misconfig` → `misconfig`/`exposure`/`config`/`default-login`/`panel`;
     `authbypass` → `auth-bypass`/`default-login`/`panel`/`exposure`; `ssrf` → `ssrf`/`redirect`/`oob`;
     `idor` → `idor`/`bola`/`apidocs`/`swagger`/`graphql`; `businesslogic` → none (native-only).
     Tag coverage confirmed against the real corpus (`misconfig` tag on 960/980 `misconfiguration/`
     files, `panel` on 1,591, `default-login` on 323, `exposure` on 1,406).
  2. **Scoped corpus = floor ∪ `TechStackTags(reconTechStack, index)`** (the "extras" —
     detected products' own CVE/panel/vuln templates). An OR-match, same as today's
     `--tags` semantics, so a template runs if it carries *any* floor or extras tag.
  3. **`--narrow-by-tech` default flips to `true`.** With recon data → floor ∪ extras.
     Without recon data (CLI `scan`, no `--recon-file`) → floor only, plus a one-line
     stderr note ("scoped to <detector> template categories; pass --recon-file for
     tech-matched CVE coverage, or --all-templates for the full corpus"). An explicit
     `--tags` value still always wins untouched. A new **`--all-templates`** bool forces
     today's full-corpus load. Web UI / MCP: default the narrow-by-tech checkbox/behavior
     **on**, and apply the same floor.
  Effect on the nettix.com.pe `--detector misconfig` case: 9,476 → ~3,500 with no recon
  (drops the 4,238-template `cves/` sweep `misconfig` never needed), and *with* recon
  adds back only the detected products' CVEs instead of all of them.

- **(b) No intra-target / intra-leaf concurrency.** `pkg/scanner/engine.go`'s per-target
  `Run()` loop fires every loaded template strictly sequentially against one target. Fix:
  a bounded worker pool over that loop. Safe without touching `--rate-limit`: the global
  rate limiter is shared through the HTTP middleware and is the real throttle —
  parallel execution *cannot* exceed the configured aggregate req/s, it just removes the
  per-request round-trip dead time that makes a sequential + rate-limited scan run far
  below its own configured rate. Preserve the **prompt-injection per-tag cap** (a
  prompt-injection template's request can trigger a metered LLM call on the target's
  backend — `promptInjectionSafeConcurrency = 5`, already special-cased in
  `loadTemplates`). The 531 `{{interactsh-url}}` templates' serial `awaitOOB` (up to 6s
  each ≈ 50 min worst case) collapses under this.

- **(c) `planexec.RunPlan` re-runs the whole corpus once per builtin-capability leaf,
  not once per host.** `runLeaf` (`pkg/planexec/executor.go`) clones `baseCfg` — with
  un-narrowed `TemplatePaths` — into a fresh `scanner.Engine.Run()` for every
  `idor`/`misconfig`/`authbypass`/`ssrf`/`businesslogic` leaf, even though a
  builtin-capability leaf needs none of the corpus loaded for its own native check. On
  the real `andertone.com` plan tree that's the same corpus reloaded and rerun 6 times in
  one pass. `pkg/webui/handlers_launch.go`'s own doc comment explains why `execCfg` skips
  the "first leaf keeps `TemplatePaths`, later ones get nil" optimization — sound for
  *template-ID* leaves (they need the full corpus for their one match), not for
  builtin-capability leaves. Fix: `RunPlan` runs the corpus at most once per host — attach
  `TemplatePaths` to exactly one leaf per host, pass `nil` to the rest.

- **(d) Rejected-template log hygiene ([follow-up.md](follow-up.md)).** `loadTemplates`
  prints one `warn` line per template rejected by both engines — ~200 on every
  full-corpus scan, none actionable at scan time, identical run-to-run — and also picks
  up non-template `.yml` files. Since (b) is already reworking this loop and its output:
  (1) skip non-template files (`.pre-commit-config.yml`, `helpers/*.yml` — matched only
  by `.yml` extension, always fail "template has no id"); (2) collapse the per-file lines
  into one bucketed summary by normalized reason (the LT-22 histogram is the model);
  (3) downgrade by-design refusals (`tcp:`/`ssl:`/`code:`/`javascript:`/`headless:`
  blocks, `internal:` outside `flow:`, absolute-URI raw — ~90 of ~200) below `warn`;
  keep `warn` only for genuinely malformed YAML (can signal a corrupt/partial sync);
  (4) full per-file list behind `--verbose` or `--log-rejected <file>`.

Sequenced after Step 4 (the executor and the Web UI dispatch path both exist to change)
and **before Step 5's `v0.6.0` tag** — a release whose headline feature is
approve-then-execute plans shouldn't ship with plan execution taking hours.

### Done note — part (a), 2026-09-06

Corpus scoping shipped across all three frontends:
- **`registry.DetectorTemplateTags(detector)`** (`pkg/registry/decisionengine.go`) — the
  category floor (`detectorTemplateTagFloor` map). Returns a fresh copy; nil for
  `businesslogic`/unknown. `DetectorTemplateTags` + `TechStackTags` are the two shared
  primitives; each frontend composes `floor ∪ extras` with its own small `union*Tags`
  helper (pkg/webui and pkg/mcpserver can't import `package main`).
- **`scanner.Config`** gained `DerivedTags` (the composed floor ∪ extras a frontend sets)
  and `AllTemplates` (escape hatch). `engine.loadTemplates`'s effective filter:
  explicit `Tags` if set → else `DerivedTags` unless `AllTemplates` → else none. One
  new stderr `info` line names which path was taken.
- **CLI**: `--narrow-by-tech` now defaults `true`; new `--all-templates`; `--recon-file`
  no longer errors without `--narrow-by-tech` — it just adds `TechStackTags` extras on
  top of the always-applied floor. `narrowScanConfigByTech` removed; `unionTags` +
  `describeTemplateScope` replace it.
- **Web UI**: the Launch checkbox defaults checked; unchecked = full corpus (the
  escape hatch). `applyTechStackNarrowing`/`narrowConfigsByTechStack` reworked to apply
  the per-cfg floor even with no recon result / no index / no tech match.
- **MCP `scan` tool**: `all_templates` input added; `tech_stack` now feeds extras on top
  of the floor rather than being all-or-nothing.

Live-verified against `https://nettix.com.pe` (owned): `scan --detector misconfig` with
no `--recon-file`/`--tags` loaded **3,745** nuclei templates (was 9,476 — the 4,238
`cves/` sweep dropped), scoped to `misconfig, exposure, config, default-login, panel`;
`--all-templates` restored the full 9,476 + 4 native; `--tags cve` still bypassed the
floor ("via explicit --tags"); `--narrow-by-tech=false` loaded everything. Native
templates (all `idor`-tagged) correctly drop out of a `misconfig` run and stay in an
`idor` one. `go build`/`vet`/`test ./... -race`/`golangci-lint` all clean.

Part (d) rejected-template log hygiene is still open.

### Done note — part (b), 2026-09-05

The per-target template loop, previously strictly sequential, is now a bounded
parallel fan-out (`--template-concurrency`, default 10). The shared rate limiter is
untouched and still the real throttle — parallelism only removes a sequential loop's
per-request round-trip dead time. Prompt-injection templates still cap the fan-out at
5. `ctx` cancellation stops dispatch of not-yet-started templates; in-flight ones
finish. Per-template warn-and-skip and per-batch finding callbacks are unchanged;
returned finding order is now completion order (nothing downstream depends on it).

Unit-verified (parallel timing, ctx-stop, prompt-injection cap). Not yet live-verified
against a real target — the "~1 hour → minutes" wall-clock check is folded into Step
5's lab round trip alongside the Step 4 browser/kill-switch checks (Open Issue #4).

### Done note — part (c), 2026-09-05

`planexec.RunPlan` previously re-parsed and re-fired the whole template corpus once
per builtin-capability leaf — on the `andertone.com` tree, the same corpus against the
same host 6× over. It now attaches the corpus to only the first builtin leaf per host;
the rest run their detector alone. Findings are unchanged (they deduped on `Finding.ID`
anyway); the removed passes were pure duplicate request load. A specific-template leaf
still always loads the corpus — it needs a full parse to resolve its one `id:`. No
caller change; unit-verified (once per host, once per distinct host, template-ID leaf
keeps its load).

### Files — (d), anticipated

(a), (b), (c) are done — see their Done notes above.

- **(d)** `pkg/scanner/engine.go` — `loadTemplates` skips non-template files and emits a bucketed rejection summary; full per-file list behind `--verbose`/`--log-rejected`; by-design refusals below `warn`.

### Verification
Unit: `DetectorTemplateTags` returns the right floor per detector; a `misconfig` load with
no `--tags`/`--recon-file` is scoped (not ~9.5k) and `--all-templates` restores it; the
per-target loop is parallel (timing assertion); `RunPlan` on a multi-builtin-leaf tree
loads the corpus once per host. Live: re-run the nettix.com.pe / LT-18 measurement — a
`scan --detector misconfig` completes in minutes and never loads the `cves/` sweep unless
a detected tech pulls specific CVEs in; a full-corpus `scan --all-templates` still works;
a real plan with several builtin leaves per host doesn't multiply the corpus pass by the
leaf count. Confirm the floor doesn't cost recall: a `misconfig` run still fires every
`exposure`/missing-header/`default-login` template it did before.

---

## Open Issues & Known Gaps

*(Consolidated here so they don't get lost in prose above — check this section before starting new work, and update it in place rather than re-burying a finding in a step's narrative.)*

| # | Issue | Recommendation |
|---|---|---|
| 1 | `ResolveLeaf`'s `use_existing_tag` judgment is unreliable with a small (4.3B) local model on a fuzzy-match case, and not perfectly consistent run-to-run at `temperature: 0` even with a capable frontier model. | Revisit before leaning on a single fallback decision for something higher-stakes — try a larger local model, prompt tuning, or majority-vote across >1 call. |
| 2 | An I4 `use_existing_tag` decision still can't dispatch via item 4's new template-ID path — `buildLeafPrompt` only ever shows the model *tags* (shared across many templates), never per-template IDs, so the decision rarely matches a real `Entry.ID`. Fully fixed for R8's own deterministic matches; not for I4's. | Needs its own design decision: run every template carrying the chosen tag? A second, narrower call to pick one ID? Change the catalog to show IDs instead of tags? |
| 3 | **Pre-existing, unrelated test failure**: `TestEndToEnd_StartScan_ProducesRealFindings` (`pkg/webui`) fails — confirmed via a clean worktree of the last commit that it fails identically there too, so not caused by any change in this doc. | Investigate separately; not a regression to chase down as part of this phase's own work. |
| 4 | Not yet live-verified: a real multi-leaf concurrency timing check against a lab target (elapsed time close to the slowest single leaf, confirming genuine parallelism); Step 3's B4 scope-creep trigger names the executor as its future caller, but that hook doesn't exist in `RunPlan` yet. | Timing check: do alongside Step 5's lab-target round trip. B4 hook: correctly Step 3's job, not a gap in Step 2 itself. |
| 5 | **A scan spends its wall-clock on templates unrelated to the target** ([follow-up.md](follow-up.md) LT-18 + the 2026-09-06 nettix.com.pe review). | **Step 6**: (a) detector-category floor ∪ tech-fact extras, `--narrow-by-tech` default-on — ✅ 2026-09-06; (b) bounded intra-target template fan-out (`--template-concurrency`) — ✅ 2026-09-05; (c) corpus once per host in `RunPlan` — ✅ 2026-09-05; (d) rejected-template log hygiene — open. Live wall-clock re-check + (d) gate Step 5's `v0.6.0` release. |
| 6 | **Duplicate findings for one underlying fact** ([follow-up.md](follow-up.md) LT-6): a native `misconfig-missing-header-*` finding and the nuclei `http-missing-security-headers` template both fire on the same response — 5 findings for one fact. `reporter.Dedup` is exact-`Finding.ID`-only by deliberate design (see its doc comment: cross-format semantic dedup "deliberately not attempted"). | Needs a real design decision, not a quick fix — a naive topic-level key risks over-suppressing genuinely distinct findings (the nuclei finding is one aggregate row covering *many* headers; the native ones are one-per-header — an N:1 relationship, not "same key twice"). Options: split the nuclei aggregate into per-header sub-facts before dedup; or a `(target, finding-class)` key with `finding-class` derived only for the known missing-header overlap; or accept the duplication as "two detectors agreeing" and only collapse in the report view. Do during Step 5's release-hardening pass, or defer to Phase 7 Step 3's Exporter work — not before the design is settled. |
| 7 | **SSE `/catchup` doesn't replay `#logs`/`#findings`** ([follow-up.md](follow-up.md) LT-5), only the idempotent progress/recon fragments — a late-connecting or reconnecting client permanently loses everything before connect. `CatchupData`'s doc comment records this as a *deliberate* narrow scope (blind replay would duplicate already-streamed append-list rows). | Needs a monotonic sequence/cursor on `Job`'s log/finding accumulation so catchup can replay only entries after the client's last-seen marker (and a client-side change to report it). Scheduled as a bullet on **Phase 7 Step 3** (Observability Upgrade) — that step reworks the SSE streams anyway. |

## Definition of Done (Phase 6, Weeks 41-48)

- [x] `pkg/mcpserver` exposes `scan`/`templates.list`/`templates.sync`/`findings.export`/`recon`/`tools.search`/`templates.search`/`plan` and nothing shell/exec-shaped; live-verified against a real MCP client — done 2026-09-02 (Step 1)
- [x] The `plan` tool's human approval is captured via MCP `elicitation`; live-verified against a real client — done 2026-09-02 (Step 2), via SEP-2322's `InputRequests`/multi-round-trip shape, not a synchronous `Elicit` call (that path doesn't work under this protocol version — see Step 2's Done note). No hand-rolled plan-ID *flag* the tool itself validates; the `RequestState` continuation token is SEP-2322's own mechanism, short-lived and single-use (see Done note for why this isn't the same concern the original wording named)
- [x] A coordinator's first `plan` proposal is demonstrably seeded from doc14's real decision-engine output (R8), not an empty, hand-authored, or redundantly-re-derived tree — done 2026-09-02 (Step 2), unit + live confirmed
- [x] The tiered LLM fallback (I4) fires only on a confirmed decision-engine miss — never as a standing parallel path — done 2026-09-02 (Step 2); "logged as one stateless input→output pair per leaf" is true of each `Client` call itself (no session/conversation state), but a structured, queryable session log of these calls doesn't exist yet — that's Step 5's C1
- [x] The same tiered LLM fallback also resolves a doc14 Step 7 unresolved field-suggestion miss (`idor`/`authbypass`), returning `{suggested_value, rationale}` — done 2026-09-02 (Step 2), confirmed distinct from the leaf-mutation schema; unit + live confirmed it goes through the same elicitation gate as the rest of the plan, never auto-applied to execution (see Step 2's `resolveFieldSuggestions` design note)
- [x] The same tiered LLM fallback also offers post-scan finding-triage/prioritization, returning `{ranked, escalate_to_human}`, never mutating the input `Finding` list — done 2026-09-02 (Step 2, `findings.triage`), unit + live confirmed, same elicitation gate as the other two callers
- [ ] An LLM-drafted template is confirmed, live, to go through the existing untrusted-template rejection pipeline and land in `templates-proposed/` (renamed from the original `templates/proposed/` — see Done note's safety-gap paragraph), never running against a live target without separate human promotion — **partially done**: the rejection pipeline itself is confirmed (unit test, a real disallowed-block draft is written then deleted), but no live OpenRouter call actually drafted a template in this environment (no API key configured) — the frontier-tier path is exercised only against a mocked endpoint, not a real one
- [ ] A per-job spend ceiling hard-fails a job when crossed — **implemented with a deliberately softer semantics than this literal wording**, recorded as a real design decision in Step 2's H5 note: exceeding the ceiling stops further I4 calls (remaining misses escalate) but does not fail the whole plan/execution, since already-resolved deterministic work shouldn't be discarded over an unrelated resolution-budget overrun
- [x] The PlanTree executor dispatches approved leaves into real `pkg/scanner`/`pkg/recon` calls; two concurrency tiers exist and are unit-confirmed (R8-matched vs. `use_existing_tag`-resolved, not "deterministic vs. currently-costing-LLM" — see Step 2's Done note for the corrected tier semantics) — done 2026-09-02 (Step 2); **not yet live-confirmed** with a real multi-leaf timing check against a lab target (elapsed time close to the slowest single leaf)
- [x] `pkg/agenttask.PlanTree`/`PlanNode` are confirmed race-free under concurrent `ApplyLeafUpdate` calls (`go test -race`) — done 2026-09-02 (Step 2)
- [ ] A program-policy pre-flight check (D2) hard-blocks an agent-driven run against a target whose disclosure policy disallows automated scanners
- [ ] A missing `--scope`-equivalent hard-fails an agent-initiated `scan`/`recon` tool call, distinct from the CLI's existing warn-only behavior for a human-typed command
- [ ] A discovered out-of-scope host actually populates `ReconResult.OutOfScope` and triggers a fresh `elicitation` round trip before it's touched, live-verified
- [ ] Cost/attempt-aware prioritization (H4) surfaces a stop-and-escalate signal on a `PlanTree` leaf after repeated low-yield attempts
- [ ] The scan HTTP client honors a `429`/`503` `Retry-After` header (capped) rather than only fixed exponential backoff
- [x] The Web UI's Plan-preview page supports Approve/Reject/Edit (per-leaf inclusion, not per-field), a budget gauge, and an always-reachable kill switch that actually stops a running job — and that same kill switch is confirmed on `/scans/{id}` for plain New Scan and Guided Scan-successor (unified Launch) runs too, not only the plan-execution flow — done 2026-09-04 (Step 4's Done note); not yet live-verified against a real browser/lab target, and the cross-process "same elicitation as an MCP client" interop is explicitly out of scope (see that note)
- [ ] A structured, persisted agent session log exists and is queryable per job, even without a live Web UI view yet
- [ ] A full recon → plan → approve → scan → export round trip is live-verified end-to-end against at least one lab target, plus a separate run against WebGoat and/or bWAPP confirming an all-`misconfig` plan resolves every leaf deterministically with zero I4 fallback calls
- [x] **(Step 6a)** `--narrow-by-tech` defaults on; `scan --detector X` with no `--tags`/`--recon-file` loads a detector-category-scoped subset (`registry.DetectorTemplateTags`), not the full ~9.5k corpus; `--all-templates` restores the full load; with a `--recon-file` the scoped set is floor ∪ `TechStackTags`; a `misconfig` run still fires every `exposure`/missing-header/`default-login` template (no recall loss) — done 2026-09-06 (see Step 6 Done note), all three frontends, live-verified against nettix.com.pe (9,476 → 3,745)
- [x] **(Step 6b)** the per-target template loop is a bounded parallel fan-out (`--template-concurrency`, default 10) — still `--rate-limit`-throttled, prompt-injection still capped at 5 — done 2026-09-05 (see Step 6 Done note); the "full-corpus `scan` completes in minutes, not ~1 hour" live check is folded into Step 5's lab round trip
- [x] **(Step 6c)** `planexec.RunPlan` loads/runs the template corpus at most once per host, not once per (host, builtin-capability-leaf) pair — done 2026-09-05 (see Step 6 Done note), unit-verified; a specific-template leaf still loads it for its own `id:` match
- [ ] **(Step 6d)** `loadTemplates` skips non-template `.yml` files and emits one bucketed rejection summary by default (full per-file list behind `--verbose`/`--log-rejected`); by-design refusals log below `warn`
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
