# Phase 5 Implementation Plan — Weeks 33-40 (Recon & Orchestration Foundations)

> Part of the [HackerFive documentation set](../README.md).

**New phase carved out during the 2026-08-29 recon-phase restructuring.** The original Phase 5 draft ([15-implementation-plan-ph6.md](15-implementation-plan-ph6.md), then numbered "Phase 5") bundled the MCP server together with a set of foundations — the eval harness, the frozen `Finding` schema, and the `Job.PlanTree` data model — that don't actually need the MCP server to exist first. [91-research-recon-phase.md](91-research-recon-phase.md)'s research on recon added a third, larger foundation to that list (a whole new `pkg/recon/` package) and surfaced the concrete reason to split it out into its own phase rather than compress it into Phase 6's existing week count: **doc15 Step 1 already flags the MCP Go SDK's `elicitation`/`tasks` support as unverified — an external risk this project doesn't control.** Everything in this phase is buildable and testable via CLI alone, with zero dependency on that SDK working. If it turns out to be a rocky integration, recon and the task-tree data model still ship real, standalone value on schedule; nothing here is wasted.

## Objective

Doc90's proposed agent flow (plan → approve → scan → triage) has no step that produces the facts a coordinator would actually reason from, and no data model for the plan itself to live in — doc91 §1 makes the case directly: an LLM reasoning about a target it hasn't looked at yet reasons from priors, not facts. This phase builds the three foundations everything else in Phases 6-7 depends on:

1. **A recon phase** (`pkg/recon/`) that narrows the template search space, grounds the coordinator's first plan in observed facts instead of hallucination, and produces the signal doc90's B4 scope-creep gate has been missing a producer for.
2. **A frozen `Finding` schema** an external MCP client can depend on without the wire shape changing later.
3. **A `Job.PlanTree` data model** doc90's Group H names but never gave a concrete shape or a data source to seed from.

**Real architectural finding from cross-checking doc90 against the actual codebase, not transcribed blind:** doc90's Decision 4 and its Group H items (H2/H3) assumed `Finding.Confidence` doesn't exist yet and proposed adding it as "the field the agent does get to set." **It already exists** (`pkg/detectors/types.go`): `Finding.Confidence string` — `"high"` for cross-account baseline evidence, `"low"` for a single-account heuristic needing manual triage — and it's already detector-set, not agent-writable, exactly like `Severity`. Doc90's underlying goal (agent-writable confidence, distinct from deterministic severity) is still correct, but the field must not be `Finding.Confidence` — that name is taken and already carries a different, narrower meaning (evidence quality of the match, not the agent's success-probability estimate for a candidate it hasn't run yet). This plan's Step 2 puts the agent-set, Cyber-AutoAgent-banded confidence on the task-tree leaf (`PlanTree` node, not `Finding`) instead. This is, if anything, a stronger version of Decision 4 than doc90 drafted: *two* `Finding` fields (`Severity` and `Confidence`) are already deterministic and agent-proof, not one.

**A second finding, from doc91's research, worth restating here since it grounds this whole phase's design posture:** every comparable agentic pentesting tool researched (Strix, CAI, MAPTA, PentestAgent, and functionally Cyber-AutoAgent) gives its agent a general shell/terminal for reconnaissance specifically, not a narrow tool — even HexStrike, the one project with genuinely scoped per-binary MCP wrappers, ships a raw command-execution endpoint alongside them. HackerFive's `pkg/recon/` design below (fixed waves, a schema-scoped tool, no shell) is a deliberately conservative outlier relative to the field, trading some recon completeness for keeping Decision 2's "no shell tool, anywhere in the server" boundary genuinely absolute — see doc91 §5 for the full tradeoff, stated plainly rather than glossed over.

## Scope

1. ⬜ **Foundations: ratify design decisions + eval harness stub** (Week 33)
2. ⬜ **Finding schema freeze + task-tree data model** (Weeks 34-35)
3. ⬜ **Recon package** (Weeks 36-37)
4. ⬜ **Recon + Plan-preview Web UI** (Week 38)
5. ⬜ **Integration testing + release** (Weeks 39-40) — `v0.5.0`

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step actually lands, same convention as doc09-13.)

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **A peer-agent mesh of any kind** — Decision 1 (doc90) is a permanent architectural boundary, not a v1 limitation to relax later.
- **Anything shell/exec-shaped, in the MCP tool surface or the recon tool** — Decision 2, same permanence; doc91 §5's design-tension callout explains why recon specifically doesn't get a carve-out despite the field's near-universal practice of giving recon a shell. (This governs what's exposed *to an agent*, not `pkg/recon`'s own internal use of fixed, named-binary subprocess calls per the Dependencies section above — the same distinction `pkg/templatesync`'s scoped `git` call already established.)
- **The MCP server itself, the `plan`/`elicitation` approval flow, and anything that requires an agent to actually be calling HackerFive** — that's Phase 6 ([15-implementation-plan-ph6.md](15-implementation-plan-ph6.md)); this phase produces the data (`ReconResult`, `PlanTree`) Phase 6 consumes, it doesn't consume it itself.
- **An actionable (approve/reject) version of the Plan-preview UI page** — this phase's Step 4 ships a *read-only* view of a `PlanTree`, since there's no live coordinator populating one yet, only test fixtures. Making it actionable is Phase 6 Step 4, once there's a real elicitation flow to resolve.
- **A live Web UI Agent tab with SSE-streamed reasoning** — Phase 7 Step 3; nothing to stream yet.
- **ffuf (parameter/endpoint fuzzing) and gau/waybackurls (passive historical-URL discovery)** — the 2026-08-29 tool-stack survey flagged both as reasonable Go-native additions, but ffuf's request volume needs to be reconciled with the existing rate limiter before it's safe to schedule, and neither is load-bearing for Steps 1-5 above. Backlogged for a later Step within this phase if time allows, or Phase 7, rather than silently dropped.

## Dependencies used in this plan

**Revised from this doc's earlier draft, based on a 2026-08-29 tool-stack survey across eight comparable agentic pentesting products** (XBOW, Strix, CAI, MAPTA, HexStrike AI, Cyber-AutoAgent, PentestGPT, PentestAgent): `pkg/recon/` shells out to a fixed set of prebuilt ProjectDiscovery binaries — **subfinder** (Wave 1 subdomain/DNS enum), **tlsx** (Wave 1 cert inspection), **dnsx** (Wave 2 DNS resolution), **naabu** (Wave 2 port scan), **httpx** (Wave 2 HTTP probe/fingerprint), **katana** (Wave 3 crawl) — via `exec.CommandContext` with fixed, non-agent-controlled arguments, the same scoped-subprocess precedent `pkg/templatesync` already sets for `git` (`pkg/templatesync/sync.go`). This reverses the original "Go stdlib first, reimplement everything" stance for these six specifically: the survey found they're the dominant Go-native tools across the field (each used by 3-4 of the 8 products surveyed), and reimplementing their maturity from scratch in stdlib isn't a good use of Weeks 36-37 — whereas shelling out to fixed, named binaries with fixed flags is exactly as scoped as `templatesync`'s `git` call. This does not touch Decision 2: that decision governs what's exposed *to the agent* (Phase 6's MCP tool surface), not how `pkg/recon` implements itself internally. Each binary is a new runtime prerequisite (document in [04-environment-and-testing.md](04-environment-and-testing.md), same class of requirement as `golangci-lint`'s PATH note) — verify current stable versions/install instructions for each at implementation time per this project's own version-verification rule, don't assume whatever versions were current when this survey was run are still current. If a binary is missing at runtime, that wave's facts are simply omitted with a logged warning, not a hard failure — recon stays usable in minimal environments. Wave 1's WHOIS/ASN lookup and Step 3's OOB capability (R1b, below) are the two exceptions where the survey found no dominant Go-native CLI: WHOIS/ASN stays a small first-party stdlib-only client per the original plan, verified via pkg.go.dev if a dependency turns out to be warranted; OOB reuses/extracts Phase 4's already-built first-party Interactsh-protocol client rather than adding a dependency at all — see R1b, which also documents why `interactsh-client` itself was tried and rejected (134 new go.mod lines for functionality the client use case didn't need). **Explicitly excluded, named rather than silently dropped:** nmap and sqlmap, the two most-used tools across the surveyed field (7/8 and 6/8 respectively) — both non-Go, and sqlmap's exploitation modes conflict with this project's read-only/no-target-state-mutation rule outright; HackerFive's own SQLi detector already covers that ground natively, and naabu covers the port-scan use case this project actually needs without nmap. The `PlanTree`/`Finding`-schema work is pure Go logic and JSON Schema authoring. The Web UI additions extend the existing `pkg/webui` (Go stdlib `net/http` + `html/template` + vendored htmx/SSE, per doc02 §7) — no new frontend framework, since a tree view and static approval-preview controls are well within what htmx fragments already express.

---

## Step 1: Foundations — Ratify Design Decisions + Eval Harness Stub (Week 33) — ⬜ not yet implemented

### Design

No code changes to `pkg/scanner`/`pkg/detectors` this week — this step is deliberately sequenced first per doc90's own sequencing note ("G1 first, even before A1/B1: without it, every claim this effort makes about agent quality is unfalsifiable from day one").

- **Ratify Decisions 1-4** as committed project design, recorded in this doc (not re-litigated per step): single coordinator (no peer-agent mesh), no shell/exec-shaped MCP tool (including for recon, per doc91's finding above), MCP `elicitation`/`tasks` for approval, and the corrected Decision 4 (task-tree-leaf `Confidence`, not `Finding.Confidence` — see Objective above).
- **G1 — eval harness stub.** A minimal, scriptable harness that runs the *existing* CLI (no agent yet — there's nothing to evaluate an agent against until Phase 6 exists) against the lab targets already used throughout this project (crAPI, DVWA, vAPI, Juice Shop, per [20-setup-testing-targets.md](20-setup-testing-targets.md)) and records a fixed challenge set with a binary pass/fail per challenge — modeled on the MAPTA/Cyber-AutoAgent published discipline doc90 cites, not a bespoke rubric invented here. This stub's job in this phase is narrow: prove the harness itself works and produces a baseline (today's detector-only fp/fn rate) before an agent is introduced later. Phase 7 Step 7 (G1 maturity) extends this into the actual agent-driven benchmark.

### Files (anticipated, confirm at implementation time)
- `tests/eval/` — new directory: a fixed challenge manifest (target + expected finding, per lab app) and a runner script/Go test that invokes `hackerfive scan` and checks output against the manifest.

### Verification
The stub runs against all four lab targets and produces a baseline pass/fail report with zero agent involvement — this is what Phase 7 Step 7 will later run again with an agent driving the scan, to get a real before/after delta.

---

## Step 2: Finding Schema Freeze + Task-Tree Data Model (Weeks 34-35) — ⬜ not yet implemented

### Design

**A3 — freeze and version the `Finding` JSON schema.** Publish `docs/schema/finding.schema.json` reflecting the actual current struct (`ID`, `Type`, `Severity`, `Confidence`, `Target`, `Description`, `Evidence` — `pkg/detectors/types.go`), explicitly annotated in the schema's own description fields that `Severity` and `Confidence` are both detector-set and never agent-writable (the corrected Decision 4 from this doc's Objective). This must land *before* Phase 6's MCP server ships, per doc90's own sequencing note — an external MCP client should never depend on a wire shape that changes after the fact.

**H2 — `Job.PlanTree`.** A new shared type (`pkg/agenttask/`, importable by both the future `pkg/mcpserver` and `pkg/webui` without either depending on the other) with a PTT-shaped tree: each node is a candidate `(target, detector/template)` pairing with a `Status` and a `Rationale` string (why the coordinator picked this candidate). **Mutations are restricted to leaves** — any update that changes the tree's shape (add/remove/reparent a node) is rejected, mirroring PentestGPT's own defense (doc90 §2) against a hallucinated rewrite of the overall plan. This phase only needs the data structure, its mutation-guard, and Step 4's read-only rendering to exist and be tested — populating it from a real `ReconResult` and streaming it live are Phase 6/7 concerns.

**H3 (corrected) — leaf-level `Confidence` bands, on `PlanTree` leaves, not on `Finding`.** Each leaf carries a `Confidence` value the coordinator sets and updates as it gathers evidence, banded per Cyber-AutoAgent's convention as a starting point: High (>80%), Medium (50-80%), Low (<50%). This is the agent's own success-probability estimate for *attempting* a candidate — it never touches a `Finding` once one is actually produced; `Finding.Confidence`/`Finding.Severity` stay exactly as they are today, both deterministic.

### Files (anticipated, confirm at implementation time)
- `docs/schema/finding.schema.json` — new, frozen/versioned schema.
- `pkg/agenttask/plantree.go` — `PlanTree`/`PlanNode` types, `Confidence` band type, leaf-only mutation guard.
- `tests/unit/plantree_test.go` — including a test asserting a shape-changing mutation (not touching only a leaf) is rejected.

### Verification
Unit tests: schema round-trips real `Finding` values from each existing detector (`idor`/`misconfig`/`authbypass`) without loss; `PlanTree` mutation tests cover both the allowed (leaf update) and rejected (shape change) cases.

---

## Step 3: Recon Package (Weeks 36-37) — ⬜ not yet implemented

### Design

Full design already captured in [91-research-recon-phase.md](91-research-recon-phase.md); this step schedules its Group R backlog items that don't depend on the MCP server:

**R1 — `pkg/recon/` package.** `Detector`-style construction (`New(client, opts...)`, `Option` funcs), one file per wave family (`passive.go`, `active.go`, `crawl.go`, `aggregate.go`), producing a single `ReconResult`. Implements doc91's Waves 0-4 in order — including the corrected ordering doc91's own revision fixed: the `--scope`/[22-authorized-targets.md](22-authorized-targets.md) cross-check runs immediately after Wave 1's passive enumeration, *before* Wave 2's first active probe, not deferred to Wave 4's aggregation step (doc91 §1/Wave 1 has the full reasoning — an earlier draft of that doc had this backwards). Each wave file wraps the named binaries from the Dependencies section above via a thin adapter that parses the tool's JSON/line output into that wave's fact types: `passive.go` → subfinder + tlsx (+ the first-party WHOIS/ASN client); `active.go` → dnsx + naabu + httpx; `crawl.go` → katana.

**R1b — OOB callback infrastructure, promoted from Phase 4's SSRF detector, not a second interactsh integration.** Landed here, in Phase 5, rather than as a Phase 4 change — Phase 4's SSRF detector is mid-implementation in a concurrent workstream, so this stays standalone, detector-agnostic infrastructure rather than a scope change to doc13's in-flight plan. **Updated 2026-08-29 with a real result, not the hypothetical this bullet originally described:** Phase 4 Step 2 already tried embedding `interactsh-client` directly (this bullet's original plan) and rejected it after actually running `go get` — it added 134 new go.mod lines (an embedded DB, host-introspection libraries, an embedded FTP server, all needed by the library's server-mode code paths, not its client use), a footprint pkg.go.dev's own package page gave no indication of. Phase 4 built the first-party fallback its own contingency (doc13 Step 2's Dependencies note) had already planned for exactly this outcome — a minimal HTTP polling client against the documented Interactsh server protocol, reverse-engineered from the downloaded source, preserving the non-negotiable per-client-keypair encryption property. **This step's job is not to re-attempt `interactsh-client`** — that path is closed, confirmed by evidence, not speculation. Instead: once Phase 4 Step 2 ships `pkg/detectors/ssrf/oob_client.go`, extract that first-party client into a shared `pkg/oob/` package (same "promote once a second consumer needs it" discipline as every other shared type in this project) so blind XSS/SQLi detectors can register against the same correlation-URL/callback-channel mechanism later without re-deriving the protocol or re-having this dependency conversation. If Phase 4 hasn't shipped Step 2 by the time this step starts, build the shared client fresh using the same first-party-protocol approach directly — do not re-evaluate `interactsh-client` as if Phase 4's finding didn't happen.

**R2 — `ReconResult` schema, frozen and versioned** alongside `Finding`'s (Step 2's A3) — same "publish before an external client depends on the shape" discipline. Includes `HostFact.Confidence`, which mirrors *this phase's* task-tree-leaf `Confidence` banding (Step 2's H3), not `Finding.Confidence` — doc91's first draft mislabeled this exact field, corrected in its current revision.

**R3 — `hackerfive recon` CLI subcommand**, usable standalone (no agent required) — `--recon-depth passive|active|full`, `-o recon.json`. Useful on its own for a human operator, not just as future agent infrastructure; this is the one artifact of this step a user can exercise directly without anything from Phase 6 existing.

**R4-R6** (the `recon` MCP tool, wiring `ReconResult` into `PlanTree` seeding, and wiring `OutOfScope` into the scope-creep gate) are explicitly **not** this step's job — each needs the MCP server or the `plan` tool to exist first, and are scheduled in [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Steps 1-3.

### Files (anticipated, confirm at implementation time)
- `pkg/recon/{detector,passive,active,crawl,aggregate}.go`
- `pkg/oob/interactsh.go` — the first-party Interactsh-protocol client, extracted/promoted from Phase 4's `pkg/detectors/ssrf/oob_client.go` (or built fresh, same approach, if Phase 4 Step 2 hasn't shipped yet) — correlation-ID generation, callback polling, callback-received channel, per-client-keypair decryption.
- `cmd/hackerfive/recon.go`
- `docs/schema/recon-result.schema.json`
- `tests/unit/recon_*_test.go` — including a test confirming Wave 2+ steps never fire when `--recon-depth passive` is set, a test confirming an out-of-scope host discovered in Wave 1 receives zero active probes in Wave 2/3 (the ordering fix, live-verified per doc91's own Definition of Done), a test confirming each wave degrades to a logged warning (not a hard failure) when its binary is absent, and `tests/unit/recon_oob_test.go` confirming a self-issued callback is received within the test's timeout.

### Verification
`hackerfive recon` runs standalone against a lab target and produces a `ReconResult` matching the frozen schema, with Wave 0-4 facts each carrying a source and confidence label. `--recon-depth passive` confirmed, live, to never send a single active probe to the target. The OOB infrastructure confirmed working standalone: a self-issued test request to its generated correlation URL is observed via the callback channel.

---

## Step 4: Recon + Plan-Preview Web UI (Week 38) — ⬜ not yet implemented

### Design

Two new, purely additive pages in `pkg/webui`, both read-only — the point of this step is giving a human something to look at that validates Steps 2-3's data models, before Phase 6 makes either page actionable:

- **Recon results page** (`/recon`, or a tab on an existing page) — runs/browses a `ReconResult` (via `pkg/recon` directly, same boundary doc12 already drew for `pkg/scanner`): hosts, endpoints, tech stack, and the `OutOfScope` list, each fact rendered with its source/confidence label. Useful standalone, independent of any agent — a human operator gets a recon-results browser for free out of this phase.
- **Plan-preview page** (`/plan-preview` or similar) — renders a `PlanTree` (from a test fixture or a manually-constructed tree for now, since nothing populates one from a live coordinator yet) as a tree/list view: each leaf's target, detector/template, rationale, and `Confidence` band. No approve/reject controls yet — those need a real `elicitation` flow to resolve against, which is Phase 6 Step 4's job.

Both use the existing Go stdlib `net/http` + `html/template` + htmx stack (doc02 §7) — no new dependency, no client-side framework. A `PlanTree` is a nested list with a status/confidence badge per row; htmx's existing `hx-get`/fragment-swap pattern (already used for the Templates page's tag filter, doc12) covers everything this step needs.

### Files (anticipated, confirm at implementation time)
- `pkg/webui/handlers_recon.go` — `GET /recon` (and a `POST` to trigger a new recon run).
- `pkg/webui/handlers_plan.go` — `GET /plan-preview` (read-only render).
- `pkg/webui/templates/recon.html`, `pkg/webui/templates/plan_preview.html`.
- `tests/unit/webui_recon_test.go`, `tests/unit/webui_plan_preview_test.go`.

### Verification
Live-verified against a real browser: a `hackerfive recon` run's output renders correctly on the Recon page; a `PlanTree` test fixture (including nested leaves at different Confidence bands) renders correctly on the Plan-preview page.

---

## Step 5: Integration Testing + Release (Weeks 39-40) — ⬜ not yet implemented — `v0.5.0`

### Design

Full integration testing across Steps 1-4 together — recon CLI against a real lab target, schema round-trips, `PlanTree` mutation guards, both new Web UI pages — then release. No MCP client, no agent session; that round trip is Phase 6 Step 5's job.

### Verification
`hackerfive recon` against crAPI/DVWA produces a real, schema-valid `ReconResult` with correctly-labeled facts. The Web UI's Recon and Plan-preview pages both render real data end-to-end. `go build`/`go vet`/`go test -race`/`golangci-lint` all clean.

## Definition of Done (Phase 5, Weeks 33-40)

- [ ] Design Decisions 1-4 (with the Objective's correction to Decision 4, and doc91's shell-tool finding) are recorded as committed design, not open questions
- [ ] `tests/eval/` runs a fixed, MAPTA/Cyber-AutoAgent-style challenge set against the lab targets with zero agent involvement, producing a baseline pass/fail report
- [ ] `docs/schema/finding.schema.json` is published and frozen; it documents `Severity`/`Confidence` as detector-set, never agent-writable
- [ ] `Job.PlanTree` exists in `pkg/agenttask`, mutates only at leaves, and a shape-changing mutation is rejected and tested
- [ ] Leaf-level `Confidence` bands (High/Medium/Low) exist on `PlanTree` nodes — distinct from, and never propagated into, `Finding.Confidence`/`Finding.Severity`
- [ ] `hackerfive recon` runs standalone against a lab target and produces a `ReconResult` matching a frozen, versioned schema, with Wave 0-4 facts each carrying a source and confidence label
- [ ] `--recon-depth passive` is confirmed, live, to never send a single active probe to the target
- [ ] An out-of-scope host discovered in Wave 1 is confirmed, live, to receive zero active probes in Wave 2/3
- [ ] Recon requests are confirmed to respect the existing rate-limit/concurrency defaults and host-error-cache circuit breaker
- [ ] Each wave's ProjectDiscovery binary prerequisite (subfinder/tlsx/dnsx/naabu/httpx/katana) is documented in doc04; a missing binary degrades that wave to a logged warning, not a hard failure
- [ ] OOB callback infrastructure (interactsh) generates a correlation URL and confirms a self-issued test callback is received — standalone, not yet wired into any detector
- [ ] The Web UI's Recon and Plan-preview pages both render real data end-to-end, read-only
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.5.0` tagged and released, or explicitly held with a stated reason

## See also
- [91-research-recon-phase.md](91-research-recon-phase.md) — the full recon research and Group R backlog this phase schedules the MCP-independent half of
- [90-research-hackerbot.md](90-research-hackerbot.md) — the research and backlog (Groups A-H) this plan and doc15/doc16 together schedule
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — the MCP server/approval-gate phase that consumes this phase's `ReconResult` and `PlanTree`
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — `Finding`/`Exporter`/`Engine` design and the Web UI stack this plan builds on
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-7 roadmap this plan is a slice of
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — the Web UI page/handler conventions Step 4's new pages follow
- [22-authorized-targets.md](22-authorized-targets.md) — the registry Step 3's recon Wave 1 cross-check reads from
