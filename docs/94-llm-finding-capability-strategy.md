# LLM Finding-Capability Strategy: Where the Model Should Earn Its Keep

> Part of the [HackerFive documentation set](../README.md).

**Status:** Proposal, not scheduled. Extends [92-research-llm-orchestrator.md](92-research-llm-orchestrator.md) and [93-implementation-plan-agent-orchestrator.md](93-implementation-plan-agent-orchestrator.md); does not change Decisions 5/6 of [90-research-hackerbot.md](90-research-hackerbot.md) (see §5).

**Last Updated:** 2026-09-21. Written after the LT-168/171/172 branch (`fix/agent-orchestrator-lt168-171-172`) and a source-level read of Strix, Cyber-AutoAgent and HexStrike (files named in §2, not launch-week claims).

## 1. Diagnosis: what the live runs actually showed

LT-171/172 made the agent cheaper and less blind. They did not make it find more. The 2026-09-20/21 runs say why:

1. **Three of four labs no longer call the model at all** (DVWA, vAPI, Juice Shop: every leaf is a parameter-free sweep, so the fast lane runs it). Findings came from the detector catalog, not from reasoning.
2. **Where the model does run (crAPI), it only orders a pre-built list.** Its action space is six tools over leaves that recon and `pkg/registry` already created. It cannot form a hypothesis nobody enumerated. The one open-ended route, `script.explore`, is heavy (sandbox + human approval per script) and the model reaches for it rarely.
3. **The misses were upstream of the model.** crAPI's missed endpoint was a recon miss (LT-164). Leaves the model picked and could not run were missing fields (LT-180). Better ordering fixes neither.
4. **Its inputs are counts, not meaning.** Recon keeps URL, method, status, body length, content type, title, and spec body-param keys ([pkg/recon/types.go](../pkg/recon/types.go) `EndpointFact`). Nothing says "this endpoint returns user-owned orders" or "this ID param is a foreign key". Semantic classification is exactly what deterministic code cannot do and an LLM can.
5. **Nothing checks a finding before it surfaces, and nothing records what was looked at and cleared.** A run that finds nothing is indistinguishable from a run that tested nothing.
6. **The existing LLM steps are closed-set.** `ResolveField` picks among candidates recon already found; `PlanFromRecon` picks `{target, detector}` from a catalog and (per its doc comment) runs only under `plan --llm-assist`; `TriageFindings`/`Suggest` reorder and annotate. None proposes a new parameter, endpoint role or test.

So the leverage is not a smarter `NextAction`. It is putting the model at the points where a human hacker's reasoning does work that deterministic code cannot, and keeping every consequential step behind a deterministic validator.

## 2. What the three tools actually do (verified against source)

| Tool | What it does that is LLM-shaped | What is not there | Take / skip |
|---|---|---|---|
| **Strix** ([usestrix/strix](https://github.com/usestrix/strix), read: `strix/skills/*`, `strix/report/dedupe.py`, `strix/tools/{coverage,reporting,threat_model}`, `agents/prompts/system_prompt.jinja`) | (a) **Shared threat model** the root agent writes before testing (`get/amend/save_threat_model`), amended by workers with attributed addenda. (b) **Coverage ledger**: every surface gets one of `reported / no_issue_found / ruled_out / not_applicable / needs_follow_up`; `ruled_out` and `needs_follow_up` require evidence; root reconciles open rows before finish. (c) **Closure discipline** (`skills/analysis/counterevidence.md`): three closure states, an explicit list of what does *not* rule a candidate out (generic library trust, a control on a sibling path, missing information, difficulty), and a mandatory "argue the other side" pass whose result is stored in the report as `counterevidence` + `confidence_rationale`. (d) **`severity_calibration.md`**: rubric, "downgrade, don't delete". (e) **LLM dedup judge** at report time: same root cause + same location + same fix, "when uncertain, lean towards NOT duplicate". (f) **60+ knowledge-pack skills** (`skills/vulnerabilities/idor.md` etc.) loaded on demand by `load_skill`: identifier forms, expansion knobs (`include`/`expand`), pagination/cursor leaks, duplicate-key parsing, type juggling. (g) Context **compaction** into a structured checkpoint. | No per-action human approval in the OSS CLI. Independent eval (arXiv 2605.10834, cited in doc92) shows higher precision at measurably lower recall. | **Take** (a), (b), (c), (d), (e), (f). **Skip** the agent graph (doc90 Decision 1) and shell/proxy/browser tools. |
| **Cyber-AutoAgent** ([westonbrown/Cyber-AutoAgent](https://github.com/westonbrown/Cyber-AutoAgent), archived; read: `system_prompt.md`, `operation_plugins/general/execution_prompt.md`, `docs/{memory,prompt_optimizer}.md`) | (a) **Explicit hypothesis before every action**: `[OBSERVATION] suggests [HYPOTHESIS]. Testing: X. Expected: Y`, with expected-if-true and expected-if-false. (b) **Observation is not a vulnerability** list (public anon keys, client-side API keys, permissive CORS, version banners, generic 500s → INFO until behaviour is proven with a negative control). (c) **Direct-first chaining**: found credentials → log in, do not crack; found SSRF → try metadata, do not scan. (d) **Reflection triggered by events** (critical/high finding, N findings, phase change), not on a timer. (e) Plan with per-phase success criteria and checkpoints. (f) `stop()` forbidden until objective met or budget ≥95%. | `[CONFIDENCE]` is the model's own report; no independent recomputation. `--confirmations` defaults off. Its prompt optimizer lets the model rewrite its own execution prompt every 20 steps. Maintainer archived the project (Nov 2025). Its 81-85% XBOW figures are the project's own; I could not open the Medium write-up (403) and did not verify them. | **Take** (a), (b), (c), (d), and the plan/checkpoint idea as a *hypothesis ledger*. **Skip** self-reported confidence as a gate, the self-rewriting prompt (unauditable), mem0 cross-run memory (doc91 rejected; revisit only as a diff-scan mode). |
| **HexStrike AI** ([0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai), read: `hexstrike_server.py`, 735 KB) | Nothing LLM-shaped. **The server contains zero LLM-client code** (no openai/anthropic/litellm references). "IntelligentDecisionEngine", "AIExploitGenerator", "AIPayloadGenerator", "VulnerabilityCorrelator" are static tables, hard-coded payload lists, and a `success_probability` that is a product of hand-set constants (`VulnerabilityCorrelator.find_attack_chains` is commented "This is a simplified implementation" and "Limit for demo"). The model is whichever MCP client connects. | Scope enforcement, confirmations, spend caps (doc92 §2). | **Skip for LLM ideas.** Its deterministic pieces (target profile → tool + parameter choice) are what `pkg/registry` already is. One adjacent item is worth a look as plain code: classifying tool failures (rate-limit / WAF block / timeout) and adapting, which relates to LT-179. |

Net: the field's finding yield, where it is real, comes from **structured artifacts around the model** (threat model, coverage ledger, closure discipline, skills, PoC gate), not from the loop itself. That fits HackerFive's constraint better than any of the three's loops.

## 3. The approach: six LLM jobs, each behind a deterministic validator

Design rule for every job below: the model **proposes, structured and schema-validated; deterministic code disposes.** A proposal can only bind to something HackerFive already executes (a detector with parameters, a template ID, or a `script.explore` spec that already goes through the sandbox + human gate). A model output can never create a `Finding` and can never raise severity or confidence (LT-157). Every job carries a per-call deadline, a spend cap and an attempt cap, degrades to the deterministic result on failure, and uses lab-neutral prompt wording (CLAUDE.md).

| # | Job | Model input | Model output (schema) | Deterministic validator | Inspired by |
|---|---|---|---|---|---|
| **J1** | **App model**: understand what the target *is* | Recon endpoints, spec routes + body-param keys, JS routes, and (new) **response-shape skeletons** (JSON key names and types, never values) | Resources (object types), which endpoints read/write each, ownership relation (owner-scoped vs global), roles seen, auth scheme, ID-like params, sensitive-data-bearing endpoints, state-changing flows. Each element cites recon endpoint IDs | Every cited endpoint exists in recon; unknown citations dropped; unlabelled inference marked `inferred` | Strix threat model, CAA plan phase |
| **J2** | **Hypothesis engine**: what would a hacker try here | J1 model + on-demand **skill packs** (per vuln class / per detected tech) + already-tested set | Ranked hypotheses `{endpoint, class, test, expected_if_vulnerable, expected_if_safe (negative control), needs (second account, protected path, …)}` where `test` is a **detector + filled parameters** (e.g. idor endpoint template, authbypass protected paths, ssrf param, sqli param) or a `script.explore` spec | `detector` ∈ registry; parameters validated by the detector's own field rules; template IDs ∈ synced corpus; hypotheses become `PlanTree` leaves (leaf-only mutation, doc90 §2) | Strix skills, CAA hypothesis format, PentestGPT PTT |
| **J3** | **Follow-up on findings**: what does this unlock | A confirmed finding's evidence (bounded, redacted) + J1 model | 0-3 follow-up hypotheses (same schema as J2) | Same as J2. Fires only when a finding ≥ medium is confirmed (event, not per-turn) and is capped per run | CAA direct-first chaining and event-triggered reflection |
| **J4** | **Skeptic**: argue the finding is not real | Finding + evidence + the negative control the detector ran (or could run) | `counterevidence` (checked/found), `named_control` or `open_proof_gap`, and a *recommended* confidence | The model may only **lower** confidence/severity or add `needs_review`, never raise (LT-157 gate reused). Where a control request is possible (other account, benign variant) it is re-issued by `pkg/orchestrator`'s own client, as `reconfirmScriptCandidates` already does for script findings, extended to detector findings | Strix counterevidence + severity calibration; CAA control-case rule |
| **J5** | **Coverage and stop**: what was looked at and cleared | Ledger of `{endpoint × class}` rows | Suggested closure per row (`ruled_out` needs a named control, else `open_proof_gap`) | The **run may not stop while a high-priority row is unreconciled** unless budget/attempt cap hit. This replaces the `MinIterations` floor (LT-162's workaround) with a state-based stop, and answers doc92's open "stop condition" question | Strix coverage ledger + reconcile-before-finish |
| **J6** | **Report grouping and draft** | Confirmed findings | Root-cause groups (9 IDOR hits on one endpoint → 1 report), CVSS rationale, repro steps | Draft only. `report create` stays a private unsubmitted draft; only `report submit --yes` submits (CLAUDE.md invariant) | Strix dedup judge, HackerOne policy |

**Skills (cross-cutting content, not a job).** J2/J3/J4 improve most from curated playbooks, not from a bigger model: identifier forms and expansion knobs for IDOR, JWT confusion, mass assignment, GraphQL, race conditions, plus a per-class **"observation is not a vulnerability"** list for the skeptic. Author them lab-neutral as embedded markdown, selected deterministically by detected tech / API kind / hypothesis class (the registry already knows both), so token cost stays bounded. Strix's skills are Apache-2.0 per its repo; adapt with attribution and re-check the license before copying any text.

**Model tiers.** Reuse `pkg/llmfallback`'s tiered client. J1, J2 and J6 run rarely (once per target, or per report), so they can afford the stronger tier. J3/J4/J5 are per-finding or per-run and should default to the flash tier. This matches doc90 Decision 5's "frontier only where rare and high-stakes".

## 4. Measure first, or none of this is provable

The labs cannot currently tell us whether an LLM step helps: three never invoke the model, and the deterministic baseline already saturates their fixtures. Without a harness that isolates the model's marginal value, J1-J6 would be tuning by anecdote (one crAPI run is exactly that today).

**Phase 0, before any J-job:**
1. **Ablation harness** on `tests/eval`: arms = deterministic-only, +J1/J2, +J4, +J5. Metrics per arm: expected-finding recall, **false positives against the lab's documented vulnerability list**, $/confirmed finding, model turns, wall-clock. Labs validate the mechanism; prompts stay lab-neutral.
2. **Reliability envelope for every new call** (LT-173): `max_tokens`/reasoning cap, per-call deadline shorter than the 4-minute stall that killed vAPI and crAPI runs, and graceful degradation to the deterministic result. New LLM jobs multiply the exposure to that failure.
3. **Response-shape capture in recon** (shape only): J1's input does not exist yet. Key names and types keep doc91 §4's "no raw response bodies in agent context".

## 5. Consistency with existing decisions

- **Decision 5/6 (LLM only where the registry cannot decide):** J1-J6 all sit at points the registry structurally cannot cover: semantic classification, app-specific hypotheses, adversarial review. They are opt-in under `hackerfive agent` (default off in Web UI), capped and schema-bound. doc90 should gain a cross-reference when implementation starts, per its own reopening discipline.
- **PoC required / no model-created findings:** unchanged. J2 fills detector parameters; the detector's own structural check still decides.
- **Human gates:** unchanged (`--allow-writes`, `--auto-provision-account`, script approval, `report submit --yes`). A hypothesis that needs a second account or a mutation is surfaced as `needs`, not run.
- **Single coordinator (Decision 1):** unchanged. The shared artifacts Strix needs for its agent graph (threat model, ledger) are used here by one process.

## 6. Suggested order

| Step | What | Why here |
|---|---|---|
| 0 | Ablation harness, LT-173 envelope, response-shape recon | Nothing after this is measurable without it |
| 1 | **J1 + J2 + first skill packs** (IDOR/BOLA, auth/JWT, mass assignment) | Largest expected gain: turns a closed-set orderer into a hypothesis generator, and fills the leaf fields that LT-180/LT-164 show are the actual misses |
| 2 | **J4 skeptic + negative-control re-issue** | Largest precision gain; serves the <5% FP target and "reports that survive triage" |
| 3 | **J5 ledger + state-based stop** | Replaces the iteration-floor workaround; makes clean areas distinguishable from unvisited ones |
| 4 | J3 finding-driven follow-up | Needs J2's schema and J4's validated findings to be safe |
| 5 | J6 grouping and drafting | Bounty-facing polish once findings are trustworthy |

## 7. Open questions

- **Recall cost of J4.** Strix's own published result is higher precision at lower recall. J4 is designed to annotate/downgrade rather than drop; the ablation must show whether that holds.
- **Is response-shape capture enough for J1?** If not, the next step is a bounded, redacted sample of response bodies for the model, which needs its own privacy review.
- **Skill-pack maintenance.** Who curates them, and how do we stop them drifting toward whichever lab was used to validate them?
- **Second-account hypotheses.** Many high-value BOLA tests need `--auto-provision-account`; J2 should propose them as `needs`, but the UX for surfacing that in an unattended run is undecided.

## Sources

- Strix: [repo](https://github.com/usestrix/strix); files read via the GitHub API: `strix/skills/analysis/{counterevidence,severity_calibration}.md`, `strix/skills/coordination/root_agent.md`, `strix/skills/vulnerabilities/idor.md`, `strix/report/dedupe.py`, `strix/tools/{coverage,reporting,threat_model}/`, `strix/llm/compaction.py`, `strix/agents/prompts/system_prompt.jinja`
- Cyber-AutoAgent: [repo (archived)](https://github.com/westonbrown/Cyber-AutoAgent); `src/modules/prompts/templates/system_prompt.md`, `src/modules/operation_plugins/general/execution_prompt.md`, `docs/memory.md`, `docs/prompt_optimizer.md`; [Medium write-up](https://medium.com/data-science-collective/building-the-leading-open-source-pentesting-agent-architecture-lessons-from-xbow-benchmark-f6874f932ca4) (not opened; 403)
- HexStrike AI: [repo](https://github.com/0x4m4/hexstrike-ai); `hexstrike_server.py` searched for LLM-client references (none) and read at `IntelligentDecisionEngine`, `VulnerabilityCorrelator`, `AIPayloadGenerator`
- [92-research-llm-orchestrator.md](92-research-llm-orchestrator.md) §2 for the earlier guardrail and weaponization findings; [90-research-hackerbot.md](90-research-hackerbot.md) Decisions 1, 2, 4, 5, 6
- [follow-up.md](follow-up.md): LT-157 (evidence gate), LT-162, LT-164, LT-166, LT-171/172, LT-173, LT-179, LT-180

## See also
- [93-implementation-plan-agent-orchestrator.md](93-implementation-plan-agent-orchestrator.md) — the shipped `hackerfive agent` this builds on
- [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — `pkg/coveragegap`, `suggest`, and the eval harness J5 and the Phase 0 ablation extend
