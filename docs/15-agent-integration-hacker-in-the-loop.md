# Agent Integration & the "Hacker-in-the-Loop" Model

> Part of the [HackerFive documentation set](../README.md).

**Status:** Discussion/proposal, not committed to [03-development-roadmap.md](03-development-roadmap.md). Builds directly on the Web UI / template-sync design ([12-implementation-plan-ph3.md](12-implementation-plan-ph3.md), shipped as Phase 3 / `v0.3.0`) and the Specialization plan ([13-implementation-plan-ph4.md](13-implementation-plan-ph4.md), scheduled as Phase 4, Weeks 25-32). Captured here, ahead of a roadmap slot, the same way the Web UI design was captured in its own doc before it had a phase number — this doc is ready to graduate into a real phase (tentatively "Phase 5" or later; no week number assigned) once scheduled.

**Last Updated:** 2026-08-28 — doc references updated after doc12/doc13 were renamed (Web UI swapped ahead of Specialization; see doc03)

## Why this doc exists

An LLM agent that drives HackerFive — reasoning about which targets/templates to run, sequencing scans through the CLI, and triaging findings — is a sound design, and it's consistent with how the field already builds this category of tool. This doc has three parts: (1) why HackerFive's *existing* architecture already leans toward the "hacker-in-the-loop" model without having been built with an agent in mind, (2) what other LLM-driven pentesting tools' designs teach about doing this well, and (3) the concrete changes HackerFive needs to make agent integration actually safe — the main content of this doc.

---

## 1. How HackerFive already aligns with "hacker-in-the-loop"

"Hacker-in-the-loop" is the term the bug-bounty industry has converged on: an AI agent may reason, execute, and reconnoiter autonomously, but a human must validate findings before they reach a program, and a human must approve any consequential action. HackerOne's own platform rules state this directly — hackbots must not operate fully autonomously, and every agent action's reasoning must be traceable, with a human required to verify any decision carrying real consequences (a submission, a payout).

HackerFive was not designed with an agent in mind, but several decisions already made in doc02/doc13 put it ahead of a typical "staple an LLM onto raw CLI tools" approach — because the guardrails already live in the *tool*, not just in whatever a prompt tells the model to do:

| Existing design decision | Where it's specified | How it already embodies hacker-in-the-loop |
|---|---|---|
| `Finding` struct + `Exporter` interface | doc02 §5 | Structured, machine-readable output an agent can reason over directly — no parsing free-form tool text |
| `--scope` "warn, don't silently proceed" | doc02 §3 / `Engine.Run` | The guardrail is enforced by the tool itself, not by trusting an agent's judgment |
| Host-error-cache circuit breaker | doc02 §3 | Bounds how hard an agent can hammer a broken/unreachable target, regardless of what it decides to do |
| `--allow-writes` opt-in gate | doc13 Step 3 | Already framed as the one sanctioned, explicit, human-consented exception to read-only — exactly the shape a "consequential action" gate needs |
| Self-hosted, user-provided OOB server | doc13 Objective §1 | No target data leaves the operator's own infrastructure no matter what an agent probes |
| Pinned-commit template sync | doc10 / doc12 | An agent can't be steered by a compromised upstream template landing between pins |
| HackerOne `Exporter` = "report-drafting, not unattended submission" | doc13 Step 4 | This *is* the platform's human-in-the-loop submission rule, already built in before any agent exists |
| Credentials via environment variable only | CLAUDE.md | An agent's own context/prompt can't leak a secret that was never hardcoded to begin with |

Two structural properties matter more than any single line item:

- **Template metadata is agent-legible.** Every template's `info:` block already carries `name`/`severity`/`tags`/`description` — natural-language metadata an LLM can match against its own recon observations ("this response shape looks like GraphQL — pull graphql-tagged templates") in a fuzzier and more capable way than Nuclei's own static tag matching.
- **The web UI's engine hooks double as agent infrastructure.** Doc12 specs `WithFindingCallback`/`WithLogCallback` on `scanner.Engine` — Phase 3 (Week 19) has since actually built and shipped them for the web UI's SSE handlers, so this is no longer a proposal, it's real code (`pkg/scanner/engine.go`) an agent orchestrator can reuse directly, live events to reason over mid-scan rather than a JSON blob only after everything finishes.

The gap, covered in Section 3, is that none of this was designed to be *called* by something other than a human at a terminal, and none of the human-approval boundaries above are currently enforced against an automated caller specifically.

---

## 2. How popular LLM pentesting tools structure themselves

| Tool | Structure / design | Human checkpoint | Key lesson for HackerFive |
|---|---|---|---|
| **XBOW** — autonomous commercial hackbot, first AI to reach #1 on HackerOne's US leaderboard | Full recon → exploit → report pipeline at scale; built its own target-scoring system by parsing program scopes/policies with an LLM plus manual curation | Human review before submission, per HackerOne's AI policy | Target/template prioritization needs its own logic layer, not just "ask the LLM every time" — and program policy has to be checked, not assumed (XBOW was removed from at least one program that disallowed automatic scanners) |
| **PentestGPT** — USENIX Security 2024, open-source | Three cooperating modules: Reasoning (maintains a Pentesting Task Tree), Generation (turns strategy into exact commands), Parsing (condenses noisy tool output) — specifically to fix LLMs losing track of a long, multi-stage engagement | Interactive mode requires human input at each step; the newer autonomous pipeline still persists a full session log | A stateful task/plan structure beats a flat chat loop for anything longer than a single request/response |
| **HexStrike AI** — open-source MCP server bridging LLM clients to 150+ existing CLI tools (nmap, nuclei, sqlmap, ffuf, etc.) | One decision engine selects tools/parameters from the existing tool catalog; explicitly lists Nuclei with thousands of templates among its integrations | Relies on prompt-level instructions ("state you're an authorized researcher") — the safety boundary lives in what the operator tells the model, not in the tool | Guardrails bolted on after release (community forks added command validation, API auth, rate limiting, and a scope validator) are a cautionary tale, not a model to copy — build the boundary into the tool from the start |
| **Google Big Sleep** (Project Zero + DeepMind) — code-level, not black-box web | Iterative hypothesis → test-case → debug loop with sandboxed tool access, mirroring how a human researcher explores a codebase | Human-reviewed disclosure to the affected project before any public writeup | Iterative, hypothesis-driven exploration — not one-shot classification — is what let it find a real SQLite zero-day fuzzing infrastructure had missed |
| **Individual bounty-hunter hackbots** (e.g. the Thacker/xssdoctor build, on top of Claude Code skills) | Recon and analysis skills loaded contextually per target; full session streamed live | A human watches and redirects live, and decides what actually gets submitted | Observability — the full reasoning-and-command trace, not just final findings — is what the builders themselves called the difference between a useful agent and "an expensive hallucination machine" |
| **HackerOne's own Hai / platform Hackbot rules** | Formal platform-wide policy: agents may reason and act multi-step, but never fully unsupervised | Human-in-the-loop mandatory for every finding validated and for any consequential decision (e.g. a payout); every agent action and its reasoning must be traceable | This isn't a design preference — it is the platform's actual, enforced rule for anyone running an automated tool against a real program |

**Common threads across every serious implementation:**

1. **A structured intermediate representation, not raw chat.** A task tree, a `Finding` schema, an exploit-flow graph — every design that works past trivial cases replaces "just keep talking to the model" with something structured the model reads and writes into.
2. **Observability is a first-class feature, not a debugging afterthought.** The tools that treat session/reasoning logging as core infrastructure produce agents people actually trust; the ones that don't produce hallucination machines with good demos.
3. **A human checkpoint sits between the agent and anything irreversible.** Submission, payout, or a production write — every credible implementation puts a person at that specific boundary, no exceptions.
4. **Target/template prioritization is its own problem, solved partly outside the LLM.** Scoring systems, policy parsing, and heuristics do real work alongside the model's reasoning, not instead of it.
5. **The safety boundary belongs in the tool, not the prompt.** The projects that had to retrofit scope validation, rate limiting, and command sanitization after shipping are the clearest evidence that "the model was told to behave" is not a design.

**Sources consulted:**
- XBOW, ["How XBOW Ranked #1 in Autonomous Penetration Testing"](https://xbow.com/blog/top-1-how-xbow-did-it) and [XBOW on HackerOne: What's Next](https://xbow.com/blog/xbow-on-hackerone-whats-next)
- GreyDGL, [PentestGPT (GitHub)](https://github.com/GreyDGL/PentestGPT); Deng et al., [PentestGPT (USENIX Security 2024 / arXiv:2308.06782)](https://arxiv.org/abs/2308.06782)
- 0x4m4, [HexStrike AI MCP Agents (GitHub)](https://github.com/0x4m4/hexstrike-ai)
- Google Project Zero, [From Naptime to Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)
- Joseph Thacker, [The Bug Bounty Singularity: Our Hackbot](https://josephthacker.com/hacking/2026/07/01/we-built-a-hackbot.html)
- HackerOne, [Code of Conduct](https://www.hackerone.com/policies/code-of-conduct); [Welcome, Hackbots](https://www.hackerone.com/blog/welcome-hackbots-how-ai-shaping-future-vulnerability-discovery); [Responsible AI at HackerOne: 2026 Update](https://www.hackerone.com/blog/responsible-ai)

---

## 3. What HackerFive needs to change — the concrete list

Grouped by concern. ⬜ = not yet designed in detail; treat this as a backlog to scope properly when it's actually scheduled, same discipline doc09-12 already apply to their own steps.

**Suggested sequencing, not just grouping** — the letter-grouping below organizes by *concern*, not by *build order*; four items carry dependencies or risk the others don't:
1. **G1 (a crude eval-harness stub) first, even before A1/B1.** Without it, every claim this whole effort makes about agent quality is unfalsifiable from day one — better to have a rough baseline before there's a body of agent-driven runs with no ground truth to check them against, than to retrofit measurement after the fact.
2. **A3 (freeze the `Finding` schema) before A1 (the MCP server) ships**, not concurrently. Once an external MCP client depends on the wire shape, changing it is a breaking change for every consumer, not an internal refactor — the schema needs to be stable *before* anything external can depend on it.
3. **B1 (`--plan-only`) before the rest of Section B**, not alongside it. B1 isn't just this list's highest-leverage item, it's load-bearing: B2, B4, and D3 all assume a plan already exists to approve, reject, or gate against.
4. **D2 (program-policy pre-flight check) treated as a hard blocker for any agent-driven run against a real target, not a nice-to-have.** It's the one item on this list with a clear, documented real-world cost of skipping it (XBOW's own program removal) — see its own bullet below, and the added Definition of Done line.

### A. Structured, tool-callable interfaces
*Make HackerFive addressable by a machine caller, not only a human at a terminal.*

- ⬜ **A1 — MCP server (`pkg/mcpserver/`)** exposing `scan`, `templates.list`, `templates.sync`, and `findings.export` as MCP tools. Calls straight into the existing `pkg/scanner`/`pkg/template`/`pkg/reporter` packages — no scan logic duplicated, the same boundary doc12 already drew for `pkg/webui`. This is what lets Claude (or any MCP client) treat HackerFive as a first-class tool the way HexStrike wraps nmap/nuclei today, except with structured JSON instead of scraped text.
- ✅ **A2 — `Engine.WithFindingCallback` / `WithLogCallback` — already landed.** Doc12 specs these; Phase 3 (Week 19) actually built them for the web UI's SSE handlers (`pkg/scanner/engine.go`), so what's left of this item is narrower than originally scoped: `pkg/mcpserver` (A1) just needs to consume the same hooks `pkg/webui` already does, not build a second live-event mechanism.
- ⬜ **A3 — Freeze and version the `Finding` JSON schema.** Publish it as `docs/schema/finding.schema.json`. Today the wire shape is implicit in Go struct tags; an external MCP client needs a documented, stable contract, not "whatever the struct currently marshals to." **Sequence this before A1 ships, not concurrently** — see "Suggested sequencing" above.
- ⬜ **A4 — `hackerfive templates list --json`.** The human-facing table doc12 designs (and Phase 3/Week 19 shipped, `templatesync.List`/`Entry`) already extracts tags/severity/category from each template's `info:` block; today it's rendered as a text table only (`cmd/hackerfive/templates.go`) — expose the same underlying data as machine-readable JSON so an agent selects templates by matching tags/description against its own recon observations, without parsing YAML or a tabwriter table directly.

### B. Explicit human-approval gates
*Turn today's implicit caution into enforced checkpoints an automated caller cannot skip.*

- ⬜ **B1 — `hackerfive scan --plan-only`.** The agent proposes a full run (targets, detectors, templates, whether writes are required) and gets back a structured plan — no request sent. This is the single highest-leverage change in this whole list: today the CLI just executes. There is currently no point where a human sees and approves a plan before traffic goes out. **Load-bearing, not just high-leverage** — B2, B4, and D3 below all assume a plan already exists to approve, reject, or gate against; build this before the rest of Section B, not alongside it.
- ⬜ **B2 — Turn `AllowWrites` into an attested approval, not a bare boolean.** e.g. `--approve-writes <plan-id>`, accepting only a plan ID a human already reviewed via B1 — so no process, including an agent, can set the flag for itself in the same breath it decided it wanted to.
- ⬜ **B3 — Document HackerOne submission as a permanent architectural invariant**, not a Phase-4-scoped decision. Doc13 already frames the exporter/API client as report-drafting-only (still unbuilt — Phase 4 Step 4); state it as a standing rule in CLAUDE.md so a future contributor — human or agent — doesn't quietly "improve" it into auto-submission later.
- ⬜ **B4 — Scope-creep gate.** If a scan's own recon phase surfaces hosts/paths outside the original `--targets`/`--scope`, require a fresh approval before probing them. Extends the existing `--scope` concept to agent-driven discovery specifically — nobody is watching each new request an agent decides, on its own initiative, to fire.

### C. Observability and auditability
*The "traceable reasoning" requirement — and the difference the field's own builders call out between a useful agent and a hallucination machine.*

- ⬜ **C1 — Agent session log.** A structured, append-only record of every tool call the agent made (which invocation, with what parameters), its stated reasoning for making it, and the raw result. Distinct from — and complementary to — the scanner's own `Job.Logs`; this logs the agent's decisions, one level above the scan's own warnings.
- ⬜ **C2 — Extend the audit trail doc12 already specifies for the Web UI's authorization checkbox** — and Phase 3 (Week 20-22) already ships as one `Job.Logs` entry per scan (`pkg/webui/handlers_scan.go`'s `startScan`) — to also capture agent-specific facts: which template/detector the agent selected and why, and every B1/B2 approval event with who granted it, timestamped.
- ⬜ **C3 — Evidence-linked claims.** Structurally require any agent-drafted report text to cite a specific `Finding.ID` and its (already redaction-aware) evidence. No claim without a `Finding` record behind it — mirrors the "ground every claim in evidence" discipline any credible report needs.

### D. Safety extensions specific to agent-driven operation

- ⬜ **D1 — Per-detector concurrency ceilings, overridable independently of the global worker-pool default.** Motivated specifically by LLM-backed-target detectors (Prompt Injection, doc13 Step 1): each probe may trigger a real, metered API call on the target's own backend. The current single global default (25) doesn't distinguish "cheap static request" from "an LLM call downstream that costs the target real money."
- ⬜ **D2 — Program-policy pre-flight check.** Before scanning, parse the target's disclosure policy (from [22-authorized-targets.md](22-authorized-targets.md), or fetched live) for automation restrictions, and refuse to proceed if it disallows automated scanners. A direct response to a real-world lesson from elsewhere in the field: XBOW's own writeup describes being removed from a program for exactly this. **Treat this as a hard blocker for any agent-driven run against a real target, not a nice-to-have** — of everything in this list, it's the one item with a clear, already-documented real-world cost of skipping it. Reflected in the Definition of Done below, not left implicit in this bullet alone.
- ⬜ **D3 — Hard-fail, not warn, on missing `--scope` for agent-initiated runs.** The existing "warn, don't silently proceed" pattern assumes a human is at the terminal to notice the warning. An agent won't be.

### E. Template ecosystem support for agent-driven selection and authoring

- ⬜ **E1 — Generated `templates/index.json`.** Tag/severity/description metadata across every loaded template (bundled + synced), refreshed on `templates sync` — one file for the agent to reason over instead of walking the template tree.
- ⬜ **E2 — Agent-proposed templates land in `templates/proposed/`**, never directly in `templates/idor/` or any trusted path. When exploration surfaces a working, reusable detection recipe, the agent can draft a template there; promoting it into the trusted set requires the same human review any human contributor's PR would get. This extends doc02's "non-engineers can contribute checks" idea to "agents can propose checks too, always staged, never trusted by default."

### F. Triage and reporting support

- ⬜ **F1 — A "triage-assist" mode on the existing `Exporter` output.** Pre-fills a likely severity/CWE mapping from `Finding` evidence, explicitly labeled as a suggestion for the human report-drafting step (doc13 Step 4), never as a determination.
- ⬜ **F2 — Structured feedback capture.** Record each human triage decision (accepted / rejected / duplicate) against the `Finding` that produced it. Lightweight ground-truth logging, not a retraining pipeline — lets agent-driven runs be measured for real precision over time, the same way every detector's own false-positive rate is already tracked.

### G. Validation for the agent layer itself

- ⬜ **G1 — An eval harness against the existing lab targets** (crAPI, DVWA, vAPI, Juice Shop) with known findings, tracking agent-driven false-positive/false-negative rate *separately* from the underlying detectors' own measured rate. Without this, a bad agent decision gets invisibly blamed on — or credited to — the deterministic scanner underneath it, and the project loses the "measure honestly, don't assume" discipline every prior phase applied to itself. **Despite being listed last alphabetically, this shouldn't ship last** — even a crude stub running before A1/B1 ship gives agent-driven false-positive rate a real baseline from day one, rather than retrofitting measurement after a body of ungrounded agent-driven runs already exists. See "Suggested sequencing" above.

---

## Definition of Done ("Hacker-in-the-Loop Ready")

- [ ] An agent can call `scan` / `templates list` / `templates sync` via MCP, consuming structured JSON — no shelling out to parse raw CLI text
- [ ] Live findings and logs stream to the agent mid-scan, not only as a final batch
- [ ] No path exists for an agent to set `AllowWrites` or submit a HackerOne report without a separate, human-granted approval step
- [ ] Every agent tool call and its stated reasoning is captured in a persisted, reviewable session log
- [ ] A missing `--scope` hard-fails an agent-initiated run rather than warning and continuing
- [ ] An agent-driven run against a real (non-lab) target refuses to proceed when the target's disclosure policy disallows automated scanners (D2) — treated as a hard blocker, not a soft warning
- [ ] Agent-proposed templates land in a staging directory and require human promotion before they're trusted
- [ ] Agent-driven false-positive/false-negative rate is measured against the lab targets, separately from detector-level rate

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — vulnerability classes an agent would be reasoning about
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — the `Finding`/`Exporter` design and existing guardrails Section 1 builds on
- [03-development-roadmap.md](03-development-roadmap.md) — where this would eventually get a phase/week number
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — the `WithFindingCallback`/`WithLogCallback` engine hooks this doc reuses, and the audit-trail precedent for the authorization checkbox
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the `--allow-writes` gate and HackerOne exporter design this doc extends
- [22-authorized-targets.md](22-authorized-targets.md) — the registry Item D2's policy pre-flight check would read from
