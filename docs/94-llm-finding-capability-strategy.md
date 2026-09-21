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

### 2a. Which of them let the model write and run Python or shell

All three do, and none of them puts a scope check or a human approval between the model's code and the network the way HackerFive does. Verified from source (2026-09-21):

| Tool | Model-written code | How | What contains it |
|---|---|---|---|
| **Strix** | **Yes, general.** | One `exec_command` tool (plus `write_stdin` for TTY sessions) runs any CLI in a per-run Docker sandbox. There is no separate Python executor: the model writes a `.py` file and runs `python3` through `exec_command` (`skills/tooling/python.md`). Shell traffic is routed through the Caido proxy via `http_proxy`. | Docker isolation. The sandbox is started with `NET_ADMIN`/`NET_RAW` capabilities added. **I found no egress allowlist** in the files read, and doc92 found no per-action human approval in the OSS CLI. |
| **Cyber-AutoAgent** | **Yes, general, including tools it writes itself.** | `shell`, `python_repl` and `editor` tools, plus `load_tool`, which loads model-authored Python tools at runtime ("meta-tooling"). It installs missing packages with `apt`/`pip` through the shell. A `BeforeToolCall` hook in `cyber_autoagent.py` **routes any unknown tool name to the shell tool**, so an invented tool name becomes a shell command. | Docker is recommended, not enforced: the README says to use it "only in authorized, safe, sandboxed environments", and its compose file documents a `--user root` option. `--confirmations` defaults off (doc92). |
| **HexStrike AI** | **Yes, unconfined, on the host running the server.** | `POST /api/command` ("Execute any command provided in the request"), `POST /api/python/execute` (writes the supplied script to a file and runs it with a virtualenv's interpreter), `POST /api/python/install`. | A virtualenv isolates packages, not behaviour. No scope allowlist, no approval, no spend cap (doc92; the Check Point report of Storm-1575 is the field evidence). |
| **HackerFive** | **Yes, narrowly**: `script.explore`, Python or shell. | Only inside `hackerfive agent`, only with `--allow-agent-scripts`, and only after a human approves the exact script text, every time. `scan`, `plan` and the MCP surface have no such tool (doc90 Decision 2 stands there). | Three independent layers ([pkg/scriptexec](../pkg/scriptexec/scriptexec.go)): (1) an AST precheck, run before a human sees the script, rejects further subprocess/interpreter spawning, raw sockets, filesystem access outside scratch and out-of-scope host literals; (2) per-script human approval; (3) a Docker sandbox with a read-only root filesystem, all capabilities dropped, a non-root user, 256 MB and a PID limit, whose only network route is an egress proxy that allows in-scope hosts. A script's output is never a finding by itself: the orchestrator re-issues any request it names through the normal client (LT-157). |

Two consequences for this strategy:

1. **HackerFive is the only one of the four that enforces scope on the code's network access.** That is a real cost as well as a safeguard: `script.explore` is heavy and rarely chosen, which is part of why the model's reach is narrow today (§1).
2. **The Phase 0 harness never measures it.** Runs are unattended and never pass `--allow-agent-scripts`, so an approval prompt would auto-deny. The J1-J6 jobs below mostly avoid the question by binding proposals to existing detectors with parameters; the `script.explore` route in J2 would need its own approved-script arm before its value can be claimed.

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

### Phase 0 status (2026-09-21, branch `feat/llm-finding-capability-phase0`)

| Item | State |
|---|---|
| LT-173 reliability envelope | **Done.** Decision calls run under `max_tokens` 2048 + reasoning effort `low` + a 120s deadline; a truncated-empty response is an error; after two consecutive failed calls the run degrades to the fast lane and ends cleanly with `Result.Degraded`. Live probe on two models: valid decisions in every trial, deepseek about 40% faster and cheaper. The 4-minute stall itself was **not reproduced**, so prevention is unproven; the degrade path is the guarantee. |
| Response-shape capture | **Done and live-verified**, but **nothing reads it yet** (J1's input). One real bug found by running it: crawl facts have no content type, so the first version captured nothing on a real crawl. |
| Miss attribution (LT-185) | **Built and run once on crAPI (1 run per arm).** `pkg/coverage` classifies each known vulnerability by the pipeline stage where it was lost; the agent's result event now carries recon's endpoint list (values stripped); the harness prints a per-arm table. First result below: none of the five misses is a selection problem. |
| LT-184 spurious idor leaves | **Fixed** (recon's JS-join step crossed every `?key=` literal with every route). 12 `idor` leaves became 1; the run-every-leaf arm went from 194 s to 44 s with the same findings. |
| Second lab (vAPI) and documentation-page routes (LT-189) | **Ground truth written, measured, and a recon gap found and fixed.** At the pinned `active` depth recon saw 1 endpoint and every known vulnerability was lost at stage 0; at `full` depth, with routes read from the served docs page, recon saw 23 and the BOLA is found (0 of 3 to 1 of 3). The two misses left have no evidence anywhere the target serves. See "A second lab". |
| Deterministic gaps (seed, protected paths, SSRF field) | **Built and measured on crAPI: known vulnerabilities 3 of 7 to 5 of 7 with `--recon-auth`, 4 of 7 without.** Vehicle-location (harvested id) and JWT alg-none (derived protected path) are now found with no model. SSRF is now dispatched at the right endpoint but still not found (detector oracle, agent OOB). The model arm again equals the run-everything arm. See "Closing the deterministic gaps". |
| LT-187 recon authentication | **Built as an opt-in `--recon-auth` and measured.** On crAPI it adds observed endpoints (55 to 69) but no findings: the same 20 findings and 3 of 7 known vulnerabilities with and without it. See "Authenticated recon (LT-187)". |
| LT-186 recon route extraction | **Fixed for placeholder routes and the route cap; measured.** Shop-orders BOLA moved from stage 0 to found (known vulnerabilities 2 of 7 to 3 of 7). Vehicle-location is now dispatched but still not found (no UUID seed); the SSRF body field is untouched. See "After the LT-186 fixes". |
| Ablation harness | **Built and run once (crAPI, 3 runs per arm, 12 of 12 completed).** `--no-model` control arm, four arms (the fourth, `no-model+all-leaves`, added and run 2026-09-21), two ground-truth lists, JSONL per run, min-max ranges, never merged across models, harness overrides recorded per result. Ground truth exists for crAPI only (7 entries). See the baseline below and LT-183. |

### First baseline: crAPI, 2026-09-21

Bundled templates (`./templates/`), `--rate-limit 60`, `--recon-depth full`, two accounts, model `openai/gpt-5.6-luna`, 3 runs per arm, identical settings for every arm. The first three arms took about 25 minutes and $0.10; the fourth arm was run later the same day (about 10 minutes, $0) with the same settings.

| Arm | Findings | Expected prefixes | Known vulns | Model turns | Cost / run | Wall / run |
|---|---|---|---|---|---|---|
| no-model (control) | 6 | 1 of 2 | 1 of 7 | 0 | $0 | 22 s |
| model-every-turn | 15 | 2 of 2 | 2 of 7 | 20 | $0.020 | 255 s |
| fast-lane + model | 15 | 2 of 2 | 2 of 7 | 15 (13-17) | $0.017 | 240 s |
| **no model, every runnable leaf** (`--no-model --run-every-leaf`) | 15 | 2 of 2 | 2 of 7 | 0 | $0 | **194 s** (191-198) |

Results were identical across the three runs of each arm (same findings, same recall); only cost and time varied. Reading it:

1. **The model adds one thing: the `mechanic_report` BOLA (9 `idor-*` findings).** The control leaves 15 leaves undispatched because they "need a decision": 12 `idor` leaves, an `authbypass` leaf, a `businesslogic` leaf and one unresolved leaf. The model picked the real one of twelve near-identical `?report_id={{id}}` leaves.
2. **That is selection, not discovery, and the fourth arm shows it does not need a model here.** `no-model+all-leaves` (no model; every runnable leaf dispatched, 25 leaf scans against the fast lane's 11) reproduced the model arms on every measure the harness stores: 15 findings, 2 of 2 expected, the same 2 of 7 known vulnerabilities, in 194 s (191-198) for $0, against 240-255 s and $0.017-0.020. On this lab the model's choice of leaf is worth nothing that running everything does not already deliver, and it costs about 25% more wall time. **Limits, so this is not over-read:** 14 endpoint-specific leaves is a small tree (about 12 s each here), so "run them all" is cheap on crAPI and would not be on a target with hundreds; this shows selection is *unproven*, not that it never matters. The harness stores finding counts, not finding IDs, so "same findings" rests on equal counts and equal known-vulnerability hits (LT-183 (i)). What it does settle is where to look: if the model is going to earn its cost, it has to be by *creating* leaves and hypotheses that do not exist (J1/J2), not by ordering the ones that do.
3. **Five of seven known vulnerabilities were missed by every arm, and the reasons are all upstream of choice:** no leaf exists for the shop-orders BOLA, the vehicle-location BOLA or the `contact_mechanic` SSRF (recon never produced them); no arm produced an `authbypass-jwt` finding although an `authbypass` leaf exists (LT-180's missing `protected_paths` is the likely cause, not verified here); the DELETE-video BFLA is unreachable by design. This is the population the J1/J2 jobs target, and it is what the strategy predicted.
4. **Fast lane vs model-every-turn: same findings, about 15% cheaper, about 6% faster, 5 fewer model turns.** A real but small gain on this lab.
5. **Caveats.** Bundled templates and a raised rate limit, so wall-clock is not comparable with the LT-172 tables; n = 3 and one lab; `unlabeled` (4 in every arm) is the four `misconfig-missing-header-*` findings, which are true but absent from this fixture, so it overstates candidate false positives; the known-vulnerability baselines are dated 2026-09-08.

### Miss attribution and the LT-184 fix: crAPI, 2026-09-21, 1 run per arm

Same settings as the baseline (bundled templates, `--rate-limit 60`, `--recon-depth full`, `openai/gpt-5.6-luna`), one run per arm, run after the LT-184 fix. Findings and recall did not move; time and cost did:

| Arm | Findings | Expected prefixes | Known vulns | Model turns | Cost / run | Wall / run |
|---|---|---|---|---|---|---|
| no-model (control) | 6 | 1 of 2 | 1 of 7 | 0 | $0 | 24 s |
| no model, every runnable leaf | 15 | 2 of 2 | 2 of 7 | 0 | $0 | 44 s (was 194 s) |
| fast-lane + model | 15 | 2 of 2 | 2 of 7 | 6 (was 15) | $0.0057 (was $0.017) | 67 s (was 240 s) |

Where each known vulnerability was lost (`pkg/coverage` stages; the two arms that dispatched everything agree):

| Known vulnerability | no-model | every-leaf / model | Why |
|---|---|---|---|
| `mechanic_report` BOLA | 3 not dispatched | **7 found** | the control never dispatches a leaf that needs a decision |
| `.env` exposed | 7 found | 7 found | a host-wide misconfig sweep |
| shop-orders BOLA | **0 not observed** | **0 not observed** | no recon endpoint contains `/workshop/api/shop/orders/` |
| vehicle-location BOLA | **0 not observed** | **0 not observed** | no recon endpoint contains `/location` |
| `contact_mechanic` SSRF | **1 no leaf** | **1 no leaf** | the endpoint was observed, but no `ssrf` leaf covers it |
| `authbypass-jwt` | 3 not dispatched | **2 blocked** | `skipped — no --protected-paths given and recon/I4 found no usable candidate` |
| DELETE-video BFLA | 6 gated | 6 gated | `mutatebfla` has no agent route by design |

Reading it:

1. **The LT-184 fix is confirmed on the live lab.** The tree now has one `idor` leaf, on `mechanic_report`, where it had twelve; `download_report` correctly keeps its own `?filename=` instead of borrowing `?report_id=`. That is a 4x speed-up for run-everything and a 3x cost cut for the model arm, from one recon bug. It is a before/after on the same harness (3 runs before, 1 after), not a controlled experiment, but the gap is far outside the run-to-run spread.
2. **None of the five misses is a selection problem.** Two are lost at stage 0 (recon never saw the route), one at stage 1 (route seen, no leaf built), one at stage 2 (leaf built, blocked on a field), one is gated. A better chooser among existing leaves cannot recover any of them. This is the evidence the strategy needed for putting J1/J2 ahead of any work on leaf ordering.
3. **Stage 0 is the largest loss, and its cause is deterministic and upstream of any model** (checked 2026-09-21 against the bundle crAPI serves). Recon on this lab has no API spec (a separate direct run recorded 45 endpoints from `httpx` 1, `katana-crawl` 4, `js-static` 26, `js-static-joined` 14), but both missing routes are in the client bundle as string literals, `"api/shop/orders/<orderId>"` and `"api/v2/vehicle/<carId>/location"`, and the extractor discards them twice over. The bundle holds 41 `api/` route literals. 15 became join bases; 18 were cut by `maxJSPathBases` (the candidates are sorted alphabetically and capped at 15, so everything from `api/shop/orders/all` onward, all of `api/v2/*` included, was never considered); 8 were rejected because a `<orderId>`-style placeholder fails `IsPlausibleURLPath` (angle brackets count as JavaScript syntax). **26 of 41 never became endpoints.** No authenticated crawl is needed to reach either route. The join step also cannot verify a placeholder route as written: a GET on the literal `<orderId>` path answers 404, the same as the canary. Downstream the detector is fine: given the orders leaf, `idor` produces the 5 known high findings (`scan --detector idor --endpoint '/workshop/api/shop/orders/{{id}}'`, 5 minutes at 60 requests a minute). The vehicle route is a second, separate problem: its UUID-keyed check needs a real vehicle UUID as a seed, and that value only appears in the authenticated response of `GET /identity/api/v2/vehicle/vehicles`; recon keeps response shapes, not values, so no seed exists. So **shop-orders is a pure extractor fix; vehicle-location needs the extractor fix plus id harvesting from a list response**, which is the privacy question in section 7. Nothing here needs a model, so for crAPI J1's route-probe idea is not the first tool; it stays for routes that appear in no client artifact, which no lab here exhibits. Logged as LT-186.
4. **Stage 1 names J2's job.** `/workshop/api/merchant/contact_mechanic` was observed (via the JS join), but body-field names only come from an API spec (`BodyParamKeys`), so no `ssrf` leaf was built. Proposing the body field is exactly the "fill a leaf parameter the registry cannot derive" job, validated by the detector's own check.
5. **Stage 2 settles LT-180.** The `authbypass` leaf exists and was dispatched by the every-leaf and model arms; it skipped for want of `--protected-paths`, so the JWT check never ran. That was "likely, not verified" in the baseline; it is now measured.
6. **Endpoint mode sizes the population.** Of 46 recon endpoints, 2 are static assets and are excluded; of the other 44, 42 have no endpoint-specific leaf and 2 have a finding. That is an upper bound on what leaf-building could reach: many are UI routes (`/orders`, `/past-orders`) that no vulnerability class applies to, which is why J1's applicability judgement matters.

Caveats: 1 run per arm; one lab; the stage of a known vulnerability depends on the fixture's `endpoint_contains` and finding-ID prefixes, so a wrong fixture entry reads as a pipeline loss (stage 5, "mismatch", is the hint for that); the leaf-to-endpoint match is by path shape and parameter name, so it cannot tell two leaves on the same host apart when neither names a path.

### After the LT-186 fixes: crAPI, 2026-09-21, 1 run per arm, recon authenticated

Two changes to the JS join step (`<name>` route placeholders are accepted as `{name}`; the 15-route cap became an 80-route cap with a probe budget and a warning), plus one found while testing them (a route that answers 500 to a parameterless request now counts as existing). The harness ran with `HACKERFIVE_ABLATION_RECON_AUTH=1`, which also sends the owner token to recon: `agent --auth-token` alone does not reach recon (LT-187), and without it identity's `api/v2/*` routes cannot be told from that service's blanket 401. **This run is therefore not like-for-like with the tables above**; two things changed at once.

| Arm | Findings | Known vulns | Model turns | Cost | Wall |
|---|---|---|---|---|---|
| no model, every runnable leaf | 20 (was 15) | 3 of 7 (was 2) | 0 | $0 | 410 s (was 44 s) |
| fast-lane + model | 20 | 3 of 7 | 10 | $0.0101 | 447 s |

| Known vulnerability | Before | After | Why |
|---|---|---|---|
| shop-orders BOLA | 0 not observed | **7 found** | the `<orderId>` route is emitted under `workshop/` (borrowed from its verified sibling `api/shop/orders`) and `idor` finds the 5 known cases |
| vehicle-location BOLA | 0 not observed | 5 mismatch | the route is observed and dispatched, but the leaf has no UUID seed, so the integer strategy cannot reach a UUID-keyed route. The stage-5 label is the classifier's hint; the precise stage is 4 (see below) |
| `contact_mechanic` SSRF | 1 no leaf | 1 no leaf | body-field derivation (LT-186 item d) is not done |
| `authbypass-jwt` | 2 blocked | 2 blocked | no `--protected-paths` (LT-180) |
| `mechanic_report` BOLA, `.env` | found | found | unchanged |
| DELETE-video BFLA | 6 gated | 6 gated | unchanged |

Reading it:

1. **The extractor fix converts one stage-0 loss into a finding with no model involved**, and the model arm again reproduces the run-everything arm exactly (20 findings, 3 of 7) at a cost of 10 turns and $0.0101. With six `idor` leaves in the tree rather than one, the model still adds nothing the deterministic policy does not.
2. **What it cost.** Wall time went from 44 s to 410 s because the tree now holds six `idor` leaves, each enumerating an id range, instead of one; finding more is not free. This is the case the selection question was always about: run-everything is fine at 6 leaves and would not be at 60.
3. **The recon call count is modest.** Authenticated recon recorded 38 joined routes (23 without a token) from 41 bundle literals, with about one probe per route once a service prefix is known; before, it verified 14. Two of the 41 stay uninferred by design (no verified sibling to borrow a prefix from), and each such route is reported in a recon warning.
4. **A route that returns 500 on a parameterless request was silently lost.** `mechanic_report` (the known BOLA) answers 500 to an authenticated GET with no `report_id`. The first version of the fix lost it as soon as recon carried a token; that regression is why 500 is now a verifying status, with 502/503/504 deliberately excluded.
5. **Vehicle-location is now a two-part problem with a known second half.** The route and its `idor` leaf exist; what is missing is a real vehicle UUID as a seed. The only place one appears is the authenticated `GET /identity/api/v2/vehicle/vehicles` response, and recon keeps shapes, not values (LT-186 item c, gated by the privacy question in section 7).
6. **The stage-5 label is only a hint.** Same-class findings exist elsewhere (14 `idor` findings on other routes), so the classifier cannot separate "detector limit" from "ground-truth mismatch". Here the cause is the missing seed.

Caveats: 1 run per arm; recon authentication and the code change are confounded in the totals (separated in "Authenticated recon (LT-187)" below: authentication added no findings) (the direct recon dumps separate them: without a token the orders leaf and the community-posts leaves appear after the fix, and only with a token do the identity `api/v2/*` routes and `vehicle/{carId}/location`); one lab.

### Authenticated recon (LT-187): `agent --recon-auth`, crAPI, 2026-09-21, 1 run per arm

`hackerfive agent --auth-token` reached the leaf dispatches but not recon. `--recon-auth` (opt-in) now sends that same header on recon's own requests to the target's host. The harness knob `HACKERFIVE_ABLATION_RECON_AUTH` adds the flag, so the measurement is the product path. Same code, same settings (`--rate-limit 60`, bundled templates, `openai/gpt-5.6-luna`); the only difference between the two rows of each arm is the flag.

| Arm | Recon | Recon endpoints | Findings | Known vulns | Model turns | Cost | Wall |
|---|---|---|---|---|---|---|---|
| no model, every runnable leaf | unauthenticated | 55 | 20 | 3 of 7 | 0 | $0 | 382 s |
| no model, every runnable leaf | `--recon-auth` | 69 | 20 | 3 of 7 | 0 | $0 | 409 s |
| fast-lane + model | unauthenticated | 56 | 20 | 3 of 7 | 10 | $0.0099 | 427 s |
| fast-lane + model | `--recon-auth` | 69 | 20 | 3 of 7 | 12 | $0.0122 | 457 s |

Reading it:

1. **On crAPI, authenticated recon adds coverage but not findings.** It observes 14 more endpoints (identity's `api/v2/*` family and `vehicle/{carId}/location`), and the vehicle-location vulnerability moves from stage 0 (not observed) to stage 5 (dispatched, not found). Every finding-level number is unchanged. **This corrects the LT-186 run above**, whose caveat left open how much of the change came from authenticating recon: none of the finding gain did. The shop-orders find comes from the route extractor alone.
2. **The reason is the seed, not the token.** The location route needs a real vehicle UUID and recon does not harvest one (LT-186 item c). Authenticated recon is a precondition for that fix (the UUID only appears in an authenticated response), not a substitute for it.
3. **Its cost is small and its risk is real.** About 7% more wall time here; the endpoints it adds also become leaves. The risk is that a crawl carrying a live session can reach a state-changing GET, which is why it is opt-in.
4. **The model arm again matches the deterministic arm** (20 findings, 3 of 7), with or without recon authentication.

How the credential is kept from leaking (tested): recon's HTTP client gets the header through a middleware that keys on the target's host and port, works on a clone of the request, and so never passes it to another host or across a redirect (`net/http` copies a redirect's headers from the original request, and strips only `Authorization`/`Cookie`, so a custom header name would otherwise follow the redirect). The katana crawl carries it only when every seed is on the target's origin and is then pinned to the exact hostname (`-fs fqdn`); httpx, which probes many hosts, never receives it. Caveats: 1 run per arm, one lab.

### Closing the deterministic gaps (LT-186 c and d, protected paths), crAPI, 2026-09-21, 1 run per arm

The three misses the stage table left were each given a deterministic first step before any model design:

- **The seed (LT-186 c).** The response-shape probe already reads authenticated list responses, so it also lifts one object id (a UUID that is the object's own `uuid`/`id`) from each list and matches it to a templated route by resource name (`.../vehicle/vehicles` seeds `.../vehicle/{carId}/location`). The id lives in `EndpointFact.SeedID` and `PlanNode.HarvestedSeedID`, both `json:"-"`: it is in no stream, result, session log, coverage ledger or prompt, and the only thing that reads it is the idor dispatch. The ledger records a fact only: `Templated` and `Seeded`. A finding's own evidence still names the id it tested, as it must (the vehicle-location finding's URL carries the UUID).
- **Protected paths (LT-180 in part).** A route the JS bundle names and verification confirmed used to lose its status. It now keeps it, and a route that turns away an anonymous request (401/403) is marked `AuthRequired`, which `SuggestAuthBypassPathsFromRecon` already turns into an authbypass protected path. When recon is signed in, one credential-free GET per verified route asks the anonymous question.
- **The SSRF body field (LT-186 d).** From the bundle's own request code (`fetch(url,{body:JSON.stringify({...})})` or `.post(url,{...})` whose URL resolves to a route constant): the route, its body field names, and which field is built from a route constant or the page origin (`mechanic_api`). Names only.

| Arm | Recon | Recon endpoints | Findings | Known vulns | Model turns | Cost | Wall |
|---|---|---|---|---|---|---|---|
| no model, every runnable leaf | unauthenticated | 56 | 25 | 4 of 7 | 0 | $0 | 383 s |
| fast-lane + model | unauthenticated | 56 | 25 | 4 of 7 | 8 | $0.0078 | 414 s |
| no model, every runnable leaf | `--recon-auth` | 69 | 27 | 5 of 7 | 0 | $0 | 413 s |
| fast-lane + model | `--recon-auth` | 69 | 27 | 5 of 7 | 10 | $0.0102 | 446 s |
| no model, every runnable leaf, after the SSRF path and SQLi fan-out fixes | `--recon-auth` | 69 | 27 | 5 of 7 | 0 | $0 | 488 s |

| Known vulnerability | Before (previous section) | Unauthenticated | `--recon-auth` |
|---|---|---|---|
| shop-orders BOLA, mechanic-report BOLA, `.env` | found | found | found |
| JWT alg-none | 2 blocked (no protected path) | **found** | **found** |
| vehicle-location BOLA | 0 not observed (5 with recon-auth) | 0 not observed | **found**, with the harvested id |
| `contact_mechanic` SSRF | 1 no leaf | 4 dispatched, nothing raised | 4 dispatched, nothing raised |
| DELETE-video BFLA | 6 gated | 6 gated | 6 gated |

Reading it:

1. **Two more misses closed with no model.** JWT alg-none needed only that the verified routes keep their status, so it is found even without recon authentication. Vehicle-location needs both a token (the route and the list are behind login) and the harvested id, so it needs `--recon-auth`.
2. **The model arm equals the deterministic arm in every pair** (25/4 of 7 and 27/5 of 7), at 8 and 10 turns. It is the fourth consecutive comparison with that result on crAPI.
3. **The SSRF leaf was aimed at the host root.** A leaf's target is only the host, and the ssrf leaf named parameters but not the endpoint, so its probes went to a path where the field does not exist. Leaves now carry `SSRFPath`, one per endpoint. The tree's dedup key had also collapsed every endpoint-driven ssrf leaf into one, and, found by checking, the same for sqli (two candidate paths produced one leaf); both are fixed and tested.
4. **SSRF is still not found, for two reasons that are not recon.** (a) The detector posts only the SSRF field. Live: crAPI answers `400 "Could not connect to mechanic api."` to that, which the detector's markers do not recognise, while the full body returns `{"response_from_mechanic_api": "<fetched content>", "status": 500}`, a plain in-band SSRF whose oracle is the field name. (b) `hackerfive agent` never runs the blind out-of-band check that `scan` runs by default, because the agent configures no OOB server. Both are logged as LT-188. (a) is a good J2 case: the hypothesis "this route reflects what it fetched" comes from reading a response shape, and its oracle is checkable.
5. **Cost.** Wall time for the deterministic arm is 383 to 488 s, up from 44 s before LT-186, because more routes are found and each becomes a leaf; selection at scale is still unproven.

Caveats: 1 run per arm, one lab, and the last row is a single run of one arm.

**Correction.** The previous section's follow-up text said `--recon-auth` reached the response-shape probe "through the same client". It did not: that probe builds its own HTTP client, so it ran unauthenticated and would have read every route's anonymous 401 body. It now wraps its transport with the credential, and a test that would fail otherwise (an identity-style service that answers 401 to everything anonymous) covers it. The status probe for robots/sitemap paths also builds its own client and is left anonymous on purpose: a 401 there is what marks a path as protected.

### A second lab (vAPI) and what it says about J1/J2, 2026-09-21, 1 run per arm

vAPI (roottusk/vapi) has a ground-truth file (`tests/fixtures/known-vulns/vapi.json`: BOLA on `api1/user/{id}`, SSRF via `serversurfer`, JWT alg-none on `jwt/user`), each with the recorded scan that verified it. It is a poor fit for crawl-driven recon on purpose: a JSON API, no served spec, a custom `Authorization-Token` header (`--auth-header-name Authorization-Token --auth-header-format {token}`), one auth module per exercise.

| Arm | Depth | Recon | Recon endpoints | Findings | Known vulns | Model turns | Cost | Wall |
|---|---|---|---|---|---|---|---|---|
| both arms | `active` (the scenario's old pin) | either | 1 | 10 | 0 of 3 | 0 | $0 | ~132 s |
| no model, every leaf | `full` | unauthenticated | 23 | 17 | 1 of 3 | 0 | $0 | 847 s |
| fast-lane + model | `full` | unauthenticated | 23 | 17 | 1 of 3 | 3 | $0.0022 | 851 s |
| no model, every leaf | `full` | `--recon-auth` | 23 | 17 | 1 of 3 | 0 | $0 | 852 s |
| fast-lane + model | `full` | `--recon-auth` | 23 | 17 | 1 of 3 | 3 | $0.0022 | 848 s |

Reading it:

1. **The first result was a stage-0 collapse, and it was a depth setting.** At `active`, recon skips the application-layer wave (crawl, JS analysis, response shapes, and the new documentation step) and saw one endpoint. The model arm made **0 turns**: with no vAPI route in the tree there was nothing for a model to choose among. `hackerfive agent`'s own default is `--recon-depth active`, so an operator who does not know this gets the same result on a real target (LT-189).
2. **The documentation page was the missing evidence.** vAPI's front page only says, in prose, "Browse http://localhost/vapi/ for Documentation". That page is a Redoc rendering whose link anchors spell out 21 routes with their methods (`#tag/API1/paths/~1vapi~1api1~1user~1{api1_id}/get`). Recon now follows same-host URLs a page mentions (never another host or port), tries `/docs`, `/redoc`, `/api-docs` and `/documentation`, and reads those anchors: 1 endpoint to 23, and the BOLA is found by the idor leaf with no model.
3. **The model arm equals the deterministic arm again** (17 findings, 1 of 3, 3 turns, $0.0022), with and without recon authentication, which changes nothing here (the docs page is anonymous).
4. **The two misses left have no served evidence.** `serversurfer` and `jwt/user` are not in the docs page's 21 routes, not linked, not in a spec. The only way to find them is a prior (knowing vAPI) or a wordlist; a model reading what the target serves has nothing to reason from. (Real routes answer 403 and unknown ones 500 under `/vapi/`, so a canary-differential sweep could confirm a guess cheaply, but the guess has to come from somewhere.)

**What the ten known vulnerabilities on the two labs say about J1/J2.** Six are found, all by deterministic work. Of the four left: DELETE-video is gated on a mutating flag by design (not a model problem); crAPI's SSRF needs a better detector oracle (LT-188: the tell is a response field that echoes what was fetched, which a differential check between two payloads can also see); and vAPI's two have no evidence to derive them from. Not one is a case where evidence the target served exists in unstructured form and only a model can read it. Each stall so far was a deterministic gap (a dropped status, an unread list, an unfetched docs page, a leaf without its endpoint), and closing them took less code than J1/J2 would.

So J1/J2 as written (an app model, then a hypothesis engine) is **not yet justified by any measured miss**, and building it now would be scored against a baseline that has not been exhausted. What would justify it: a target where the served evidence exists but is unstructured or ambiguous (prose API docs, an undocumented-but-linked admin surface, a business flow spanning several routes), a larger tree where selection matters (the 6 to 20 leaf trees here cannot show it), and an oracle a rule cannot express. Until one appears, the next work is the cheaper deterministic set: LT-188, more ground truth (Juice Shop), and the depth default. If J2 is built at all, the narrow form is the one to try first: given one leaf's endpoint, body field names and a response shape, propose the request body and the expected-if-vulnerable / expected-if-safe pair the detector then checks, capped and gated as everywhere else.

Caveats: 1 run per arm, two labs, and both are intentionally vulnerable applications whose routes were public knowledge before the fix (the fixes are generic, but they were found on these targets).

Two things this turned up that change how to read everything above (the fourth arm's flag, `--run-every-leaf`, is a deterministic policy, not a recommended default: it runs endpoint-specific leaves blind and does not resolve unresolved ones):

1. **The control arm is nearly free to run and answers the first question.** `--no-model` needs no API key, so "what does the deterministic path alone reach on crAPI" can be measured before spending on any model arm.
2. **The configured model changed without any code change** (`deepseek/deepseek-v4.1-flash` in the LT-162/171/172 runs, `openai/gpt-5.6-luna` now). Any before/after across those sessions is across models, which is why the harness records the model and refuses to average across it.

## 5. Consistency with existing decisions

- **Decision 5/6 (LLM only where the registry cannot decide):** J1-J6 all sit at points the registry structurally cannot cover: semantic classification, app-specific hypotheses, adversarial review. They are opt-in under `hackerfive agent` (default off in Web UI), capped and schema-bound. doc90 should gain a cross-reference when implementation starts, per its own reopening discipline.
- **PoC required / no model-created findings:** unchanged. J2 fills detector parameters; the detector's own structural check still decides.
- **Human gates:** unchanged (`--allow-writes`, `--auto-provision-account`, script approval, `report submit --yes`). A hypothesis that needs a second account or a mutation is surfaced as `needs`, not run.
- **Single coordinator (Decision 1):** unchanged. The shared artifacts Strix needs for its agent graph (threat model, ledger) are used here by one process.

## 6. Suggested order

| Step | What | Why here |
|---|---|---|
| 0 | Ablation harness, LT-173 envelope, response-shape recon | Nothing after this is measurable without it |
| 0b | **Miss attribution** (LT-185, **built; first result above**): for each known vulnerability, the pipeline stage where it was lost | Turns "5 of 7 missed" into a per-stage number, so step 1 is aimed at a measured gap and scored by it; the same classifier becomes step 3's coverage ledger |
| 0c | **Recon route extraction** (LT-186, **placeholders and the cap done; measured above**): placeholder routes and the 15-base cap in the JS join | Measured cause of two of the five crAPI misses, fixable without a model; doing it first means J1 is scored on what deterministic recon genuinely cannot reach |
| 1 | **J1 + J2 + first skill packs** (IDOR/BOLA, auth/JWT, mass assignment), **deferred 2026-09-21 (see "A second lab"): no measured miss on two labs is beyond deterministic work; a narrow J2 is the form to try first** | Largest expected gain: turns a closed-set orderer into a hypothesis generator, and fills the leaf fields that LT-180/LT-164 show are the actual misses |
| 2 | **J4 skeptic + negative-control re-issue** | Largest precision gain; serves the <5% FP target and "reports that survive triage" |
| 3 | **J5 ledger + state-based stop** | Replaces the iteration-floor workaround; makes clean areas distinguishable from unvisited ones |
| 4 | J3 finding-driven follow-up | Needs J2's schema and J4's validated findings to be safe |
| 5 | J6 grouping and drafting | Bounty-facing polish once findings are trustworthy |

## 7. Open questions

- **Recall cost of J4.** Strix's own published result is higher precision at lower recall. J4 is designed to annotate/downgrade rather than drop; the ablation must show whether that holds.
- **Is response-shape capture enough for J1?** If not, the next step is a bounded, redacted sample of response bodies for the model, which needs its own privacy review.
- **Resolved (2026-09-21): ids read from a response.** Held in memory only, never in a stream, result, log, ledger or prompt; the ledger says whether a route was seeded, not with what. A finding's evidence naming the id it tested is the finding, not a leak. The same rule should govern any value J1/J2 could ever want to read from a response.
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
