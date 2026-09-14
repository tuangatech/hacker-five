# `hackerfive agent` — LLM-Orchestrated Scan Loop + Sandboxed Script Tool

> Part of the [HackerFive documentation set](../README.md).

**Status:** Planned, not yet implemented. Branch: `feat/hackerfive-agent-orchestrator`.

**Last Updated:** 2026-09-14 — implementation plan for the scoped Decision-2 reopening [92-research-llm-orchestrator.md](92-research-llm-orchestrator.md) §5b/§7 authorized.

## Context

[92-research-llm-orchestrator.md](92-research-llm-orchestrator.md) reopened [90-research-hackerbot.md](90-research-hackerbot.md) Decision 2 ("no shell/exec tool, anywhere"), scoped narrowly: after real engineering investment across `pkg/detectors`/`pkg/registry`/the ~9.6k-template corpus, v1's fully-deterministic dispatch still hasn't produced a live, program-actionable finding, and the specific gap is exploration a fixed matcher/template genuinely cannot do (JWT algorithm-confusion, non-numeric IDOR ID-space decoding, custom request-signing reverse-engineering, GraphQL introspection-driven query generation, business-logic state-sequencing, timing side-channels — doc92 §5b's full list). The user confirmed the concrete decisions this plan builds: command name `hackerfive agent`; a Web UI "Use LLM agent" checkbox, default unchecked; reuse `pkg/llmfallback`'s existing model client as-is; a human approves the exact script text before every execution, no batch pre-approval; validate against lab targets (crAPI/DVWA/Juice Shop/vAPI) for FP/FN before this mode ever points at a real program. `docs/90/14/15/91-*.md` already carry the scoped cross-reference note — this doc is the implementation plan doc92 §7 called for.

**This is not a replacement for v1.** `hackerfive scan`/`plan`/`triage`/`suggest` and the MCP server's tool surface are unchanged. `pkg/mcpserver` still exposes nothing shell/exec-shaped — the new script tool lives only inside this new, separately-named, opt-in mode.

**Non-negotiable properties carried over from doc92 §5/§5b** (verified against the actual codebase this session, not assumed): the PoC-required rule, a per-run spend/iteration ceiling that defaults safe, no bypass of `--allow-writes` for mutating actions, and a script-execution gate that pairs HITL approval with an independent static pre-check and a sandboxed runtime — because HITL-approving raw code text alone is a materially weaker gate than approving a structured plan (most reviewers can't reliably eyeball a script for a hidden `subprocess.Popen` or an unscoped host).

## Reused infrastructure (confirmed via codebase research this session — no reinvention)

- **CLI conventions**: `cmd/hackerfive/plan.go`/`triage.go`/`suggest.go` — `newXCmd(root *rootFlags) *cobra.Command`, `llmfallback.New(llmfallback.WithLogCallback(...))` construction idiom, `"<cmd>: ... spent $%.4f\n"` stderr cost idiom, `cmd.OutOrStdout()`/`root.output` for JSON output. `scan.go`'s `--allow-writes`/`--auto-provision-account` pattern (independently-scoped, default `false`, warn-and-skip when absent) is the template for the new `--allow-agent-scripts` flag.
- **`pkg/agenttask.PlanTree`**: `ApplyLeafUpdate(nodeID, patch)` is the *only* legal mutation surface (leaf-only, rejects shape changes) — the orchestrator loop never touches the tree any other way. `RecordLeafAttempt`/`ShouldEscalate` (existing `MaxLeafResolveAttempts=3`/`MaxLeafResolveSpendUSD=0.05` per-leaf grind caps) and `SpendCeilingUSD`/`AddSpend`/`SpendSoFar` (tree-wide budget) are reused as-is.
- **`pkg/llmfallback.Client`**: `New()`/`ErrNoTierAvailable`/`completeBestAvailableLabeled`, the two independent spend ceilings (global process-lifetime `HACKERFIVE_SPEND_CEILING_TOTAL_USD`, per-call `HACKERFIVE_SPEND_CEILING_USD`), and the degrade-never-fabricate pattern (`decodeJSONResponse` + allow-list validation, e.g. `ResolveLeaf`'s `EscalateToHuman` default, `Suggest`'s `validSuggestedActions` drop) are the model directly for the new `NextAction` call — no new client, no new tier.
- **`pkg/webui.Job`**: `AppendFinding`/`AppendLog`/`BeginAgentActivity(tool, reason, params) func(resultSummary, err)`/`Ctx()`/`Cancel()` and the `EventAgent` SSE stream already exist and already do exactly what an orchestrator turn needs to report — reused unmodified. `LaunchFormData.AllowWrites`'s checkbox convention (`r.PostFormValue("x") == "on"`, implicit-false, excluded from LT-122's `localStorage` prefill `FIELDS` array) is the template for the new checkbox.
- **`tests/eval/agent_run.go`**: `AgentScenario{Name, ExpectedFile, Target, ...}` + `tests/fixtures/expected-findings/*.json` (`ExpectedIDPrefixes`) is the exact fixture set and comparison methodology (`matchesAnyPrefix`) to reuse for a three-way FP/FN comparison (deterministic `TestEvalHarness` vs. existing MCP-plan `TestAgentEvalHarness` vs. this plan's new orchestrator mode).
- **`pkg/scanner/scope.Scope`** (`Parse`/`New`/`Allowed(target string) bool`) is reused by the egress proxy below — confirmed no existing HTTP-client-layer scope check exists (`httpclient.Client` has none), so the proxy is the first thing to add one at that layer.

## Gap found and closed by this plan

`pkg/agenttask.SessionLogEntry` (shared by `pkg/mcpserver` and `pkg/webui`) has **no field distinguishing an agent-decided turn from a human-requested one** — both `Job.BeginAgentActivity` and MCP's `sessionLog.Begin` write the same shape. Fix: add `Actor string` (json `actor`) to `SessionLogEntry`; add `SessionLog.BeginActor(actor, tool, reason string, params any) func(resultSummary string, err error)`; make the existing `Begin` a thin wrapper calling `BeginActor("human", ...)` so every current call site's meaning is unchanged. The orchestrator loop calls `BeginActor("agent", ...)` for every turn — this is what makes the audit trail doc90's C1/Definition-of-Done actually distinguishable, not just present.

## Milestones

### M1 — Foundations (no loop yet; the safety-critical primitives everything else depends on)

- `pkg/agenttask`: `Actor`/`BeginActor` per the gap above (`pkg/agenttask/sessionlog.go`).
- `pkg/llmfallback/orchestrate.go` (new file, same placement discipline as `leaf.go`/`suggest.go`/`triage.go`): `func (c *Client) NextAction(ctx, tree *agenttask.PlanTree, catalog []ToolSpec, history []TurnRecord) (Action, float64, error)`. `Action{Kind string, NodeID string, Params json.RawMessage, Rationale string}` — `Kind` validated against a fixed allow-list (`recon.refresh`, `registry.lookup`, `scan.leaf`, `triage.rank`, `script.explore`, `stop`); an unrecognized `Kind` or malformed response degrades to `Action{Kind: "stop"}` with the reason logged, never fabricated or retried silently — same contract as `ResolveLeaf`/`Suggest`.
- `pkg/scriptexec/` (new package) — the sandboxed script tool, per the design below.
- New `orchestrator.Config` fields (see M2): `Budget float64`, `MaxIterations int`, `AllowAgentScripts bool`.

**`pkg/scriptexec` design:**
- **Sandbox: Docker, not bare `os/exec`.** This codebase has zero existing Go code shelling out to Docker (only documentation tells a human to run `docker compose` for lab targets), but the daemon is already a confirmed dependency in both dev paths (WSL2 + Docker Desktop, macOS + Docker) since it's required for the lab targets anyway — so this is new *usage*, not a new *environment* dependency. A bare `os/exec` sandbox gives no namespace/network isolation at all, which would leave "no exploit, no damage" resting entirely on the static pre-check — the single-weak-gate problem this design explicitly avoids. Container: `--read-only` rootfs, a size-capped `tmpfs` scratch dir, non-root `--user`, `--cap-drop=ALL`, `--pids-limit`, `--memory`/`--cpus` limits, hard wall-clock kill via `context.WithTimeout` around `docker run` (mirroring `pkg/recon/exec.go`'s existing `errWaveTimeout` pattern — same "kill on deadline, report partial/blocked" shape, not a new idiom).
- **Egress control: a first-party allowlisting forward proxy** (`pkg/scriptexec/egressproxy`, new), reusing `scope.Scope.Allowed` on every request/CONNECT. The container's only network route is to this proxy (`docker network create --internal`, proxy on the shared bridge); the script's runtime gets `HTTP_PROXY`/`HTTPS_PROXY` env vars — no other network configuration needed for Python `requests`/shell `curl`, which honor these by default. The proxy additionally rejects any resolved IP that's loopback/link-local/RFC1918-unless-explicitly-in-scope (closing a DNS-rebinding gap `scope.Allowed`'s hostname-string-match doesn't cover on its own — a rebound in-scope hostname pointing at `169.254.169.254` needs this second check). The proxy wraps its own outbound calls through `httpclient.New` with the same rate-limit/retry middleware, so a script's traffic doesn't get an unbounded side channel outside the rest of the scan's throttling.
- **Static pre-check (second gate, runs before a human ever sees the script — reject-on-match never reaches the reviewer):** a real AST walk, not a token deny-list (a deny-list on raw text is trivially defeated by string concatenation/`getattr`/`__import__`). Python: shell out to a small, fixed, first-party, reviewed `python3 -c` checker using stdlib `ast` (an explicit exception since Go has no Python AST library — the checker itself is trusted, fixed code, never the untrusted script). Shell: an AST-based parse — **check the real transitive footprint of `mvdan.cc/sh` before adopting it** (CLAUDE.md's dependency-footprint rule); if disproportionate, fall back to a stricter regex/token check for shell specifically while keeping Python's real AST check. Blocks: further subprocess spawning (`subprocess`/`os.system`/`os.popen`/`os.exec*`/`pty`/`multiprocessing`), raw `socket`/`ssl` use (env-var proxying can't route a raw socket, so this must be blocked outright, not just left to the network topology), filesystem access outside the declared scratch dir, and any bare hostname/IP literal in the source that isn't the run's own target (defense-in-depth beyond the proxy).
- **API** (`pkg/scriptexec/scriptexec.go`):
  ```go
  type Language string // LangPython, LangShell
  type ScriptRequest struct {
      Language     Language
      Source       string
      Scope        *scope.Scope
      Timeout      time.Duration
      ApprovalGate func(ctx context.Context, req ScriptRequest, pre PrecheckResult) (approved bool, err error)
  }
  type PrecheckResult struct { Blocked bool; Reasons []string }
  type ScriptResult struct { Stdout, Stderr string; ExitCode int; Truncated bool }
  func Precheck(req ScriptRequest) (PrecheckResult, error)
  func Execute(ctx context.Context, req ScriptRequest) (ScriptResult, error) // Precheck -> ApprovalGate -> container run, in that order
  ```
- **New flag: `--allow-agent-scripts`** (bool, default `false`), same independently-scoped convention as `--allow-writes`/`--auto-provision-account` — never folded into either. Absent: the orchestrator treats a proposed `script.explore` action as `StatusUnresolved` (same semantics as a registry miss) with a stderr warning, never a hard-fail of the whole run.
- **Attack-scenario check** (verify in tests): metadata-IP curl → stopped by the egress proxy's IP-class check; write outside scratch → Docker read-only rootfs + pre-check; reverse shell/`subprocess` → pre-check import/call block + `--cap-drop=ALL`; infinite CPU loop → `--cpus`/`--pids-limit` + hard timeout, independent of the pre-check.
- **Evidence rule** (closes the "self-reported confidence" flaw named in doc92 §2's Cyber-AutoAgent finding, and ties in [follow-up.md](follow-up.md) LT-157's evidence-gating item): a script's own stdout/exit code is never sufficient by itself to become a `Finding`. When a script's output demonstrates a structural condition (e.g., a forged JWT that got a 200 with sensitive data), the orchestrator must independently re-issue the discovered request via the normal `pkg/scanner/httpclient` path (read-only, already in scope) to confirm the response outside the sandbox before packaging it as `Finding.Evidence` — the confirmation request/response pair, not the script's self-report, is what ships.

### M2 — `pkg/orchestrator` (new package): the loop itself

- `Config{Targets []string, Scope *scope.Scope, Budget float64, MaxIterations int, AllowAgentScripts bool, DetectorFlags ..., ApprovalGate func(...)}`.
- Builds the initial `PlanTree` by reusing `pkg/llmfallback/planfromrecon.go`'s existing recon→tree population (the same logic `plan.go` already calls) — no new tree-seeding logic.
- Fixed, schema-validated tool catalog (consistent with Decision 2's "narrow, CLI-shaped" rule even for this closed set — `script.explore` is the sole, deliberate, doubly-gated exception): `recon.refresh` (targeted re-probe via `pkg/recon`), `registry.lookup` (advisory query into `pkg/registry` — per doc92's resolved open question, the orchestrator's prompt should weight/prefer these answers rather than discard v1's tuned precision), `scan.leaf` (execute one target+detector/tag leaf via `pkg/scanner` — the only path to a real `Finding`, PoC-required, unchanged from v1), `triage.rank` (existing `llmfallback.TriageFindings`), `script.explore` (M1's `pkg/scriptexec`), `stop`.
- Loop: while `tree.SpendSoFar() < tree.SpendCeilingUSD` and iteration `< MaxIterations` and pending/unresolved leaves remain: call `fb.NextAction`, dispatch the chosen tool, `tree.ApplyLeafUpdate`/`RecordLeafAttempt`, `sessionLog.BeginActor("agent", action.Kind, action.Rationale, action.Params)(resultSummary, err)`. Both ceilings default to a safe, non-zero value (mirrors `PerCallDefaultSpendCeilingUSD`'s existing $0.10-style default, scaled up for a whole run — exact number TBD in implementation, not zero and not unbounded).
- Every `Finding` still only comes from `scan.leaf`'s real detector match or `script.explore`'s independently-reconfirmed evidence (M1) — never from `NextAction`'s own assertion.

### M3 — `cmd/hackerfive/agent.go`

- `newAgentCmd(root *rootFlags) *cobra.Command`, flags mirroring `scan.go`'s target/`--scope`/output handling plus `--budget`, `--max-iterations`, `--allow-agent-scripts` (all following M1's default-safe convention).
- HITL for `script.explore`: print the full script text and the `Precheck` result, block on a stdin y/N prompt before calling `scriptexec.Execute`'s `ApprovalGate` — no batch/blanket approval, matching the user's explicit "every time" instruction.
- Cost/iteration summary printed via the existing `"agent: spent $%.4f of $%.2f budget, N iterations\n"` idiom (same family as `plan.go`/`triage.go`/`suggest.go`).

### M4 — Web UI wiring

- `LaunchFormData.UseLLMAgent bool` / form field `use_llm_agent`, parsed identically to `AllowWrites`, **excluded from LT-122's `FIELDS` localStorage-prefill array** (same deliberate exclusion as `allow_writes`/`authorized`).
- When checked, `runLaunchJob` routes to `pkg/orchestrator.Run` instead of `scanner.Engine` directly, passing `job.AppendFinding`/`job.AppendLog`/`job.BeginAgentActivity`/`job.Ctx()` as-is — no new Job fields needed beyond what M1's `Actor` tagging already threads through `BeginAgentActivity`.
- Script approval: extend the existing Plan-Preview approve/reject pattern (`pkg/webui/handlers_plan_exec.go`) with a blocking "pending script approval" state — reuse the `EventAgent` SSE shape with an action-required flag rather than inventing a new event type; the existing kill switch (`Job.Cancel()`) remains the override that works regardless of this new state.

### M5 — Eval harness integration + lab validation (gates any real-target use)

- Add an orchestrator-mode driver to `tests/eval/` alongside `TestEvalHarness` (deterministic baseline) and `TestAgentEvalHarness` (existing MCP-plan mode) — same `AgentScenario` list (DVWA/Juice Shop/vAPI/crAPI), same `tests/fixtures/expected-findings/*.json`, same `matchesAnyPrefix` comparison, same three metrics already logged (cost, tool-calls, wall-clock).
- Deliverable: a three-way FP/FN/cost/wall-clock table. This is the actual test of the premise behind this whole feature — whether LLM-driven exploration finds something the deterministic layer's real, measured gap actually closes. **Do not point this mode at a real program until this table exists and shows a genuine improvement**, matching the user's own "test first with local test targets" instruction and doc90's G1 eval-harness discipline.

## Verification

- `wsl.exe -e bash -lc "cd /mnt/c/ML-Projects/Weekend-Projects/hacker-five && go build ./... && go vet ./... && go test ./... -race && PATH=\$PATH:\$HOME/go/bin golangci-lint run ./..."` clean after each milestone.
- Unit tests per package: `pkg/scriptexec` (Precheck rejects each attack scenario in M1's table; Execute enforces the sandbox against a real Docker daemon in CI/WSL2), `pkg/llmfallback/orchestrate_test.go` (malformed/unrecognized `NextAction` response degrades to `stop`, mirroring `leaf_test.go`/`suggest_test.go`'s existing pattern), `pkg/orchestrator` (loop respects `MaxIterations`/`Budget`, never mutates the tree outside `ApplyLeafUpdate`), `pkg/agenttask` (`BeginActor`/`Actor` field, `Begin` back-compat).
- Manual: `hackerfive agent --targets <lab-target> --scope <file>` with `--allow-agent-scripts` unset first (confirms scripts never run without the flag), then with it set against a lab target, approving one real script interactively and confirming the sandbox/proxy/pre-check behave as designed (try one of M1's attack scenarios deliberately and confirm it's blocked at the stated layer).
- Web UI: launch a scan with "Use LLM agent" checked against a lab target, confirm SSE streams orchestrator turns via the Agent tab, confirm a proposed script blocks for approval and the kill switch still works mid-run.
- M5's eval harness run is the final gate before this doc's premise is considered validated.

## See also
- [92-research-llm-orchestrator.md](92-research-llm-orchestrator.md) — the research and scoped Decision-2 reopening this plan implements
- [90-research-hackerbot.md](90-research-hackerbot.md) — Decision 2's original text and this session's inline reopening note
- [follow-up.md](follow-up.md) LT-157 — the evidence-gating item M1's "Evidence rule" directly extends to script-sourced findings
