# Architecture & Technology Stack

> Part of the [HackerFive documentation set](../README.md).

## Design Principles

The hybrid direction the project commits to, stated once here rather than left implicit across doc90/doc14/doc15.

1. **Deterministic-first, LLM-as-fallback, never LLM-first.** Every dispatch decision (which detector/tool/template applies to a fingerprinted target) goes through a static, versioned registry (`pkg/registry`) before anything touches an LLM. An LLM is invoked *only* when the registry has no entry for what recon found — never as a parallel path a model can reach for whenever it "judges" the deterministic answer insufficient.
2. **LLM calls are stateless, per-`PlanTree`-leaf, tiered by model class — never a persistent agent.** A small local model handles cheap/frequent judgment; a frontier model via OpenRouter handles the rare expensive case (principally drafting a new template). Each call is one schema-in/schema-out function — no chat history, no long-lived agent process. This also bounds what leaves the machine: only the rare frontier call talks to a third party.
3. **Reuse published designs from comparable open-source tools before inventing one.** HexStrike AI, Cyber-AutoAgent, and Strix were read as source for fingerprinting, decision-table, and skill patterns (doc90 Group I). Prior art is adapted, not re-derived — but still goes through this project's own scrutiny.
4. **A capability is described once, in one registry entry — never re-explained per consumer.** The same entry that documents a detector/tool/template for a human in doc01 is the entry `tools.search`/`templates.search` serves to an LLM.

## Technology Stack

### Language: Go 1.21+

Single static binary, goroutine concurrency, fast startup, built-in HTTP/DNS/TCP clients. Architectural capacity is ~150 req/sec against lab targets; the real-target operating rate is 5-10 req/sec (see [05-hackerone-and-legal.md](05-hackerone-and-legal.md)). CLI via **Cobra**.

### Detection templates: YAML, two engines

The scanner splits into a generic **engine** (Go, built once — knows how to send a request, read a response, check it against rules) and **templates** (YAML recipes that supply the meaning of one specific weakness). Adding a check is writing a YAML file, not new Go code. Two parallel template engines, both loaded and run additively for every target:

- **`pkg/template/nuclei`** — Nuclei-compatible YAML (matchers, extractors, request chaining, a hand-rolled DSL).
- **`pkg/template/native`** — HackerFive's own richer format for cases with no Nuclei equivalent (e.g. `idor`-tagged two-account baseline comparison, `{{RangeInt(min|max)}}` enumeration).

See [template-writing-guide.md](template-writing-guide.md) for the format and [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) for the sync design.

**The synced corpus is bounded to what's on disk at decision time — never a live download.** `pkg/templatesync` (`hackerfive templates sync`) does a `git` sparse-checkout of a **pinned upstream commit** (never `HEAD`) for 7 curated categories (`http/` exposed-panels, misconfiguration, technologies, vulnerabilities, cves, exposures, default-logins — widened from 4 on 2026-09-03) plus `helpers/` wordlists, into a persistent per-user config dir that survives binary upgrades. `--templates` loads that directory *and* the small `go:embed`-ed example set together. Re-pinning or widening categories is a deliberate, human-reviewed action, not a runtime toggle — a fingerprint the corpus doesn't cover surfaces as a visible `unresolved` `PlanTree` leaf, never silent expansion. Latest measured load success after the Phase 6 template-engine work: **~9,363 of ~9,683 templates load (~96.6%)**; the remaining rejections are `xpath`, `flow:` cross-block indexing, and disallowed (`code:`/`javascript:`/`headless:`/`tcp:`) blocks — see [follow-up.md](follow-up.md)'s Template Engine backlog.

`registry.Resolve`'s template-tag matching only ever searches `templates/index.json` (`hackerfive templates index`), itself only ever built from what's already synced.

### HTTP client: Go stdlib + middleware

`net/http` wrapped with rate limiting, retry-with-backoff, proxy support (Burp/mitmproxy), header/UA control, and request/response logging. A **per-host error circuit-breaker** (`pkg/scanner/hosterrors`) skips a host after it crosses a consecutive-error threshold rather than hammering an unreachable target for the rest of a run.

### Concurrency: goroutines + bounded worker pool

Two fan-out axes, both bounded and both throttled by one global rate limiter shared across the whole scan: a cross-target worker pool (`pkg/scanner/workerpool`, `--concurrency`) and, within each target, a bounded template fan-out (`Engine.runTemplates`, `--template-concurrency`, default 10; auto-capped to 5 when a prompt-injection template is loaded) — doc15 Step 6b. Plan execution (`pkg/planexec`) loads the template corpus once per host, not once per builtin-capability leaf — doc15 Step 6c. Plus progress tracking and graceful cancellation.

### Result storage & reporting

One `Exporter` interface (`Export(w io.Writer, findings []detectors.Finding) error`), one implementation per format — JSON, Markdown, HTML (auto-escapes attacker payload text), and HackerOne-JSON (an offline `report_intent` *draft*). Dispatched by `ExporterFor(format)`. `reporter.Dedup` suppresses exact-`Finding.ID` duplicates only (cross-format semantic dedup is deliberately not attempted). Optional SQLite for local finding history.

### Web UI: local-only embedded server (optional)

`hackerfive serve` — a loopback-first Go stdlib `net/http` + `html/template` server over the *same unmodified* Scanner Engine, interactivity via vendored **htmx** (`go:embed`-ed into the one binary), live findings/logs via **Server-Sent Events** backed by `Engine`'s `WithFindingCallback`/`WithLogCallback`. CSRF via a hand-rolled double-submit cookie; a non-loopback bind needs a bootstrap token. Never a substitute for the CLI.

One unified **Launch page** (`GET /`) superseded the earlier separate New Scan / Recon / Guided Scan pages: a target field, an always-on recon phase, and CSS-only detector tabs. Recon is a phase of the one `Job` type, not a separate job. Recon-fillable detector fields left blank (`idor`'s endpoint, `authbypass`'s paths) are deferred past submission-time validation (`Config.ValidateWithOptions`) and filled from the real `ReconResult` once recon finishes — a still-empty field skips that one detector with a visible log line, mirroring an `unresolved` `PlanTree` leaf. `GET /plan-preview` is the Web UI's own plan-approval surface (below).

### MCP server: a frontend for LLM agents

`pkg/mcpserver` (`hackerfive mcp-serve`, Phase 6) is a third frontend over the same engine — `scan`, `recon`, `templates.list`/`sync`, `findings.export`, `findings.triage`, `tools.search`, `templates.search`, and `plan`. No shell/exec-shaped tool (a permanent boundary): the agent selects targets/templates, every `Finding` still comes from the deterministic matcher engine. Dependency: `github.com/modelcontextprotocol/go-sdk` (official). Human approval uses MCP's `elicitation` primitive via SEP-2322's multi-round-trip shape (a handler returns `InputRequests` and is retried once the client answers) — a synchronous mid-request `Elicit` is not available in the current protocol. A client that doesn't advertise elicitation support gets the plan back **unexecuted**, not a failure.

### Dependencies (minimal)

```
github.com/spf13/cobra                          CLI
gopkg.in/yaml.v3                                YAML
github.com/json-iterator/go                     fast JSON
github.com/santhosh-tekuri/jsonschema/v5        finding + recon-result schema validation (zero transitive deps)
github.com/modelcontextprotocol/go-sdk          MCP server (11 modules, 2 already pinned)
(no new dep) pkg/llmfallback                    tiered LLM client — plain net/http, OpenAI-chat-compatible
(no new dep) pkg/oob                            RSA-OAEP+AES-256-CTR Interactsh client
(optional)   github.com/chromedp/chromedp       browser-based XSS validation
```

Regex uses stdlib `regexp` (RE2) — arm64-native, no cgo, reproducible cross-compiled builds. Reach for `github.com/dlclark/regexp2` only for a specific matcher that needs PCRE-only features.

**Dependency-footprint discipline (the "interactsh-client lesson," Phase 4):** importing `interactsh-client` pulled in ~134 unrelated go.mod lines (embedded DB, FTP server) from its server-mode code — discovered only by running `go get` and reading the `go.mod` diff, not by reading the package page. Repeat that check before committing to any new dependency; if the footprint is disproportionate, implement the needed protocol subset first-party (as `pkg/oob` does).

**`pkg/llmfallback` config — environment variables only** (`cmd/hackerfive/dotenv.go` loads `.env` once at startup; a real exported var always wins). `env.example` documents every variable. The load tier points at an OpenAI-chat-compatible local runtime; the frontier tier is OpenRouter (new-template drafting only). **Two spend ceilings, both USD not token counts:** a per-call ceiling on `agenttask.PlanTree` (default `$0.10`) and a process-lifetime cumulative ceiling (default `$2.00`, `pkg/llmfallback/spend.go`). Crossing either stops further LLM calls for that pass (remaining leaves escalate to a human) but never discards already-resolved deterministic work. If neither tier is reachable, `llmfallback.New()` fails outright and every fallback call escalates to a human rather than silently doing nothing.

### Development & testing

| Area | Tooling |
|---|---|
| Test | Go `testing` + testify; `testing.F` fuzz targets for the HTTP client / response parsers |
| Vulnerable targets | crAPI, vAPI, DVWA, Juice Shop, WebGoat, bWAPP (Docker Compose) |
| Recon binaries | subfinder, tlsx, dnsx, naabu, httpx, katana — installed via `hackerfive recon setup` (`pkg/toolsync`), no Go toolchain needed |
| Lint | golangci-lint | 
| Build / release | `Makefile` (`build`/`test`/`lint`/`fuzz`/`integration`/`eval`); goreleaser cross-compiles Linux/macOS/Windows; the Web UI is `go:embed`-ed into that same binary |
| CI | GitHub Actions |

Errors are wrapped with `fmt.Errorf("...: %w", err)` and inspected with `errors.Is`/`errors.As` — no custom error package.

## The Agent Pipeline

The full flow, `recon → decision engine → approval → scan → triage`. **Steps 1-4 and 6-10 are built and live-verified; the LLM fallback and both approval surfaces are built; the hard safety blockers (D2/D3/B4) and the live session log are Phase 6 Step 3/5.**

```
1. Recon — escalating waves 0-3                              ✅ pkg/recon
   zero-touch → passive (subfinder/tlsx) → active
   (dnsx/naabu/httpx +tech-detect) → bounded crawl (katana)
   Output: ReconResult { Hosts, Endpoints, TechStack,
   APISpec, OutOfScope, Warnings } — schema-frozen, each
   fact carrying Source + Confidence. 100% deterministic;
   no LLM ever sees a raw response.
          │
2. Fingerprint — header/body/favicon/port signature table   ✅ pkg/fingerprint
   enriches TechStack on top of httpx's own -tech-detect
          │
3. Decision engine — registry.Resolve, per host, per fact   ✅ pkg/registry
   TechFact / EndpointFact / PortFact / APISpecFact
      ├─ techRules match          → capability leaf (misconfig/idor/…)
      ├─ template-tag match       → specific-template leaf (id-scoped)
      │   (ranked: primary-product tag > generic hit; canonical
      │    tech→tag map; version/CVE-recency scoring; static-asset
      │    and non-actionable-tech denylists)
      └─ no match                 → tiered LLM fallback      ✅ pkg/llmfallback
                                     local tier: use_existing_tag /
                                       needs_new_template / escalate
                                     frontier tier (only on needs_new):
                                       drafts YAML → templates-proposed/
                                       (validated, never executed —
                                        human promotion required)
                                   still nothing → visible `unresolved`
                                   leaf, never dropped, never silently
                                   escalated
          │
4. PlanTree — leaf-mutable-only, spend-ceiling-bearing      ✅ pkg/agenttask
   (2+3 BUILD the tree; review happens on the tree, not before)
          │
5. Approval — human approves the plan                       ✅ MCP elicitation
   either the MCP client's own dialog, OR HackerFive's         + Web UI Plan Preview
   Web UI Plan Preview (Approve/Reject/per-leaf include,        (Phase 6 Step 4)
   budget gauge, always-reachable kill switch)
          │  scope hard-fail on agent-initiated calls           ✅ MCP (Step 1) + CLI plan/recon
          │  D2 program-policy pre-flight (automated-scan ban)  ⬜ Phase 6 Step 3
          │  B4 scope-creep re-elicitation on OutOfScope        ⬜ Phase 6 Step 3
          │
6. Scoped execution — approved leaves via pkg/planexec.RunPlan  ✅ pkg/planexec
   the SAME dispatcher for MCP and Web UI. Two trust tiers:      (shared, extracted
   R8-matched leaves at full concurrency; use_existing_tag-       from mcpserver)
   resolved leaves at a lower cap. Leaf Status/Confidence
   updated continuously (mutex-guarded ApplyLeafUpdate).
          │
7. Triage — findings.triage ranks an existing []Finding      ✅ I4's 3rd caller
   never adds a finding, never changes Severity/Confidence
          │
8. Result interpretation → human final review               ⬜ Phase 7 (live Agent tab)
          │
9. Report — JSON / MD / HTML / HackerOne draft              ✅ pkg/reporter
          │
10. HackerOne submission — separate explicit `--yes` gate,   ✅ permanent invariant
    never bundled into reporting, never agent-automated          (CLAUDE.md / doc90 B3)
```

**Boundaries worth stating explicitly:**

- **Template reuse (Decision 6) is bounded to whatever's synced+pinned on disk** — never a mid-scan download, and neither the decision engine nor the LLM fallback expands coverage on its own. A drafted template from the frontier tier lands in `templates-proposed/` — a *sibling* of `templates/`, never a subdirectory, because every loader walks `templates/` recursively; it is validated by the same load-time pipeline as any template and is **never executed** by the plan run that produced it. Promotion is a manual step.
- **The decision engine reasons over the whole `ReconResult`, not just `TechStack`.** `resolveEndpointFacts`/`resolvePortFacts`/`resolveAPISpecFact` turn observed endpoints, open ports, and discovered API specs into leaves too (P1-1/P1-2, LT-3). A port with no loadable check (`tcp:` templates are structurally rejected today) still emits a visible `unresolved` leaf — the real network-service detector is [Phase 8](17-implementation-plan-ph8.md) Step 1.
- **Recon-derived *field* suggestions** (`pkg/recon/suggest.go`) are deterministic candidate-derivation from `ReconResult.Endpoints`, shared by the Web UI Launch flow and the MCP `plan` tool. Only a genuine zero-/multiple-candidate miss reaches the LLM fallback's second caller — same "deterministic first, visible on a miss" shape as leaf resolution.
- **Optional tech-stack template narrowing** (`registry.TechStackTags`, LT-16/17): derives a tag allowlist from a target's detected `TechStack`. Opt-in only — Web UI checkbox / CLI `--recon-file … --narrow-by-tech` / MCP `tech_stack` input — and only ever narrows an *empty* `--tags`, degrading to the full corpus (logged) when nothing actionable was detected.

## System Architecture

### Module map

```
┌───────────────────────┬───────────────────────┬────────────────────────┐
│   CLI (hackerfive …)   │  Web UI (serve, htmx  │  MCP server (mcp-serve, │
│                        │  + SSE, Plan Preview) │  elicitation approval)  │
└───────────┬────────────┴───────────┬───────────┴────────────┬───────────┘
            └────────────────────────┼────────────────────────┘
                                     │  (three frontends, one engine — no scan logic duplicated)
        ┌────────────────────────────┼────────────────────────────┐
        │                            │                            │
   pkg/recon                  pkg/fingerprint               pkg/templatesync
   waves 0-3, ReconResult     signature table               pinned git sync + index.json
        │                            │                            │
        └──────────────┬─────────────┴────────────────────────────┘
                       │
                pkg/registry (decision engine)  ──▶  pkg/agenttask (PlanTree)
                registry.Resolve, tech→tag map        leaf-only mutation, spend ceiling
                       │                                     │
                       │  (registry miss)                    │  (approved)
                       ▼                                     ▼
                pkg/llmfallback                        pkg/planexec (RunPlan)
                local + frontier tiers,               shared dispatcher for MCP + Web UI
                3 stateless callers                          │
                                                             ▼
                                         pkg/scanner/engine  ─runs─▶  pkg/detectors/*
                                         scope, workerpool,           idor, misconfig,
                                         httpclient, hosterrors       authbypass, ssrf,
                                                             │        businesslogic
                                                             ▼        (+ Phase 8: netservice, tls)
                                         pkg/template/{nuclei,native}  +  pkg/oob (Interactsh)
                                                             │
                                                             ▼
                                         pkg/reporter  ─▶  JSON / MD / HTML / HackerOne draft
```

### Detectors (one package each, `New(...)` + `Run(ctx, …) ([]Finding, error)`)

- **IDOR** — swap the object ID, see what comes back. Runs as a two-account baseline comparison (Account A's token against Account B's resource) where possible, which is what keeps false positives low.
- **Misconfiguration** — request a fixed list of known-bad paths/headers (`/.env`, `/.git`, missing CSP, wildcard CORS). Deterministic, lowest-FP, runs mostly on upstream nuclei templates. `rejected()` excludes 404/405 and 502/503/504 (a plain 500 is still real signal).
- **Auth Bypass** — state-based checks: no-credentials call, JWT tampering (`alg:none`, stripped signature), cross-user token reuse, rate-limit-signal probe.
- **SSRF** — scheme-based redirection probes (`file://`, `gopher://`) plus a blind out-of-band check via `pkg/oob`'s Interactsh client. `--oob-server` defaults to 2 public servers; `--no-oob` or a self-hosted server for a real third-party engagement.
- **Business Logic** — the one detector with mutating checks (coupon self-mint/apply, apply race), gated behind `--allow-writes` — CLAUDE.md's sole permanent exception to read/enumerate-only; absent, those checks are skipped with a stderr warning.
- **Planned ([Phase 8](17-implementation-plan-ph8.md)):** a `tcp:` protocol executor + `netservice` detector (anonymous-FTP / unauth-DB / open-Elasticsearch, read-only), a `tls` detector (expired/weak certs, sub-1.2 protocols), JS static analysis (secrets + endpoints in served JS, folded into `ReconResult.Endpoints`), and OOB blind-RCE verification.

Detector-specific logic sits on top of the shared **Template Runner** (YAML parse → request via the worker pool → matcher/extractor engine) rather than each detector reimplementing HTTP handling.

### `Finding` and `PlanTree` — two agent-proof fields

`Finding.Severity` (closed 4-value enum) and `Finding.Confidence` (closed 2-value enum: evidence quality of the match) are both **detector-set, never agent-writable** — the frozen `docs/schema/finding.schema.json` says so in its field descriptions. The agent's own success-probability estimate for a candidate it hasn't run yet lives on the `PlanTree` *leaf* instead (`agenttask.Confidence`, Cyber-AutoAgent-banded), never on a `Finding`.

## Code Walkthrough

A tour of the main files, for orienting in the codebase rather than these diagrams.

### Entry point & CLI (`cmd/hackerfive/`)
- [`main.go`](../cmd/hackerfive/main.go) → Cobra root ([`root.go`](../cmd/hackerfive/root.go)); [`dotenv.go`](../cmd/hackerfive/dotenv.go) loads `.env` once for every subcommand.
- [`scan.go`](../cmd/hackerfive/scan.go) — flags → `scanner.Config` → `scanner.Engine` → `reporter.Dedup`/`ExporterFor`. The clearest map of "what a scan does." `--recon-file … --narrow-by-tech` applies LT-16's tech-stack narrowing.
- [`serve.go`](../cmd/hackerfive/serve.go) / [`mcpserve.go`](../cmd/hackerfive/mcpserve.go) — the Web UI and MCP frontends.
- [`recon.go`](../cmd/hackerfive/recon.go) / [`plan.go`](../cmd/hackerfive/plan.go) — standalone recon, and recon → `registry.Resolve` → `PlanTree` as JSON (`plan --llm-assist` adds the fallback pass). `--verbose` streams wave progress to stderr.
- [`templates.go`](../cmd/hackerfive/templates.go) — `sync|list|index`; `index` generates `templates/index.json`.
- [`report.go`](../cmd/hackerfive/report.go) — `weaknesses|scopes|create|submit`; only `submit --yes` can make a report visible (permanent invariant).

### Scan orchestration (`pkg/scanner/`)
- [`engine.go`](../pkg/scanner/engine.go) — `Engine.Run`: load scope, load templates (nuclei + native), worker pool, per target run the built-in detector then every loaded template *additively*. `WithFindingCallback`/`WithLogCallback` are the SSE hooks the Web UI uses.
- [`config.go`](../pkg/scanner/config.go) — `Config` + `Validate()` / `ValidateWithOptions()` (the latter lets the Web UI defer a recon-fillable field's requiredness check).
- Supporting: `httpclient`, `ratelimit`, `workerpool`, `scope` (with `scope.New` for in-memory entries, used by MCP), `hosterrors`.

### Detectors & templates
- [`pkg/detectors/types.go`](../pkg/detectors/types.go) — the shared `Finding` struct.
- `pkg/detectors/{idor,misconfig,authbypass,ssrf,businesslogic}/` — one package each.
- `pkg/template/{nuclei,native}/` — the two engines; `native/` has `dsl/`, `extractor/`, `matcher/`.
- `pkg/templatesync/` — `git` sync + `LoadIndex`/`WriteIndex` (`index.go`, consolidated once a third consumer needed it).
- `pkg/oob/` — the Interactsh client and its shared `Poller` (one registration across the whole `Executor`, one background poll loop, a nonce→waiter map; idle-skips the network poll when nobody's waiting).

### Recon, fingerprint, decision engine
- [`pkg/recon`](../pkg/recon) — `recon.go` (`Run`), `passive.go`/`active.go`/`crawl.go` (waves 1/2/3), `aggregate.go` (merge/dedup, `NormalizeHost`), `wpplugins.go` (WordPress plugin/theme slugs from crawl URLs), `suggest.go` (recon-derived field candidates), `types.go` (frozen schema shape). `recon.ClientConfig` forces `InsecureSkipVerify` for recon's own client (matching katana/httpx).
- [`pkg/fingerprint`](../pkg/fingerprint) — ~20-entry signature table over header/body/favicon/port signals.
- [`pkg/registry`](../pkg/registry) — `Capabilities` (`registry.go`, doc01's table in `tools.search` shape); `Resolve` (`decisionengine.go`) → `PlanTree` leaves + a `map[string]LeafContext` of originating facts. Ranked tag matching, `canonicalTechTags`, `nonActionableTech`, `hostnameProductHints`, `TechStackTags`.
- [`pkg/agenttask`](../pkg/agenttask) — `PlanTree`/`PlanNode`, mutex-guarded, leaf-only `ApplyLeafUpdate` (shape-change rejected), spend ceiling.

### Agent frontends
- [`pkg/mcpserver`](../pkg/mcpserver) — `server.go` (tool registration), `scope.go` (`requireScope` D3 hard-fail, `clientSupportsElicitation`), `tools_*.go`, `planstate.go` (TTL-bounded cache bridging the two elicitation rounds), `executor.go` (thin — delegates to `pkg/planexec`).
- [`pkg/planexec`](../pkg/planexec) — `RunPlan`/`runLeaf`/`missingRequiredField`, transport-agnostic (`ExecOptions{Notify, OnFinding, OnLog, Excluded, DetConcurrency, LLMConcurrency}`). The single dispatcher both `pkg/mcpserver` and `pkg/webui` call.
- [`pkg/llmfallback`](../pkg/llmfallback) — `client.go` (tiered `net/http`), `leaf.go` (`ResolveLeaf` + `rankRelevantTemplates`), `field.go` (`ResolveField`), `triage.go`, `spend.go` (process-lifetime ceiling).
- [`pkg/webui`](../pkg/webui) — `server.go` (routes), `jobs.go` (`Job` carries recon waves + `ReconResult` + `Cancel`), `handlers_launch.go` (the unified page + `fillReconFields`), `handlers_plan_exec.go` (`POST /plan-preview/execute` → `pkg/planexec`), `handlers_scan.go` (`/scans/{id}` + SSE + `/catchup`).

**To trace one scan end-to-end:** [`scan.go`](../cmd/hackerfive/scan.go) → [`config.go`](../pkg/scanner/config.go) → [`engine.go`](../pkg/scanner/engine.go) → a detector → [`exporter.go`](../pkg/reporter/exporter.go). For the agent path: [`plan.go`](../cmd/hackerfive/plan.go) or `pkg/mcpserver/tools_plan.go` → `registry.Resolve` → `pkg/planexec/executor.go`.

## Future Considerations (Not Yet Scoped)

Deferred until a trigger condition occurs, not on a fixed date.

- **In-memory template cache** — only pays off for a long-running service re-parsing the same templates across jobs; no persistent service mode is planned.
- **Template signing** — relevant once a community template repo accepts third-party submissions; no such milestone exists.
- **Auto-generated syntax reference (docgen)** — the hand-written [template-writing-guide.md](template-writing-guide.md) covers this until there's a scale-of-contributors problem.

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — the detectors this architecture supports (Capabilities at a Glance)
- [03-development-roadmap.md](03-development-roadmap.md) — build order, Phases 1-8
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — full Web UI and template-sync design
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — recon / fingerprint / decision engine / `PlanTree` foundations (built)
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) / [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — MCP server, approval gate, `pkg/planexec`, hardening
- [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) — detector/protocol coverage expansion (TCP, TLS, JS static analysis, OOB-RCE, semver gating)
- [90-research-hackerbot.md](90-research-hackerbot.md), [91-research-recon-phase.md](91-research-recon-phase.md) — the research behind the agent-integration design
- [follow-up.md](follow-up.md) — the open backlog, including the decision-engine precision work and template-engine gaps referenced above
