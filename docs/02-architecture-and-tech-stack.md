# Architecture & Technology Stack

> Part of the [HackerFive documentation set](../README.md).

## Design Principles

*(New section, 2026-08-30 — the hybrid direction the user set, made explicit rather than left implicit across doc90/doc14/doc15.)*

1. **Deterministic-first, LLM-as-fallback, never LLM-first.** Every dispatch decision (which detector/recon-tool/template applies to a fingerprinted target) goes through a static, versioned decision-engine registry (`pkg/registry` — [90-research-hackerbot.md](90-research-hackerbot.md) Decision 6, Group I) before anything touches an LLM. The registry pattern is the same shape HexStrike AI's own internal dispatch code uses (`TechnologyDetector`/`IntelligentDecisionEngine`, confirmed by reading its source) — built first-party in Go here, not pulled in as a dependency. An LLM is invoked only when the registry has no entry for what recon found; it is never a parallel path available whenever a model "judges" the deterministic answer insufficient.
2. **LLM calls are stateless, per-`PlanTree`-leaf, tiered by model class — never a persistent agent.** doc90 Decision 5: a small local model handles cheap/frequent judgment calls; a frontier model via OpenRouter handles the rare, expensive case (principally authoring a new template). Each call is one schema-in/schema-out function from the deterministic orchestrator's point of view — no chat history, no long-lived "agent process" spawned and held open across a scan. This also bounds how much scan data ever leaves the local machine: only the rare frontier-tier call talks to a third party, the same reasoning behind keeping OOB self-hosted (doc13 Objective §1).
3. **Reuse published designs from comparable open-source tools before inventing one.** HexStrike AI, Cyber-AutoAgent, and Strix were read directly (source code, not marketing) for fingerprinting, decision-table, and skill-content patterns — see doc90 Group I5 for the specific reuse-vs-reject call on each. Prior art gets adapted, not re-derived from a blank page, but every adopted pattern still goes through this project's own scrutiny (e.g. HexStrike's live-per-scan NVD query was rejected as fragile in favor of a periodically-refreshed local cache).
4. **A capability, once it exists, is described once, in one registry entry — never re-explained per consumer.** The same entry that documents a detector/tool/template for a human reading doc01's capability list is the entry `tools.search`/`templates.search` (doc15) serves to an LLM — one source of truth, not a human-facing doc and a machine-facing catalog drifting independently.

## Technology Stack

### Core Components

#### 1. **Language: Go (Golang)**
- **Why?**
  - Compiles to single static binary (no dependencies, easy distribution)
  - Concurrent request handling via goroutines (150+ req/sec architectural capacity, demonstrated against local lab targets — not a recommended operating rate against a real program; see [05-hackerone-and-legal.md](05-hackerone-and-legal.md)'s "Rate Limits & Concurrency Against Real Targets" for the actual real-target guidance, 5-10 req/sec absent other constraints)
  - Fast startup and low memory footprint
  - Built-in HTTP/DNS/TCP clients
  - Production-proven by Nuclei, Nmap, Docker, Kubernetes

- **Minimum Version:** Go 1.21+

#### 2. **Detection Templates: YAML**
- **Why, in plain English:** the scanner splits into two separate things — an engine (the Go code) and templates (YAML files). The engine is generic and only gets built once: it knows how to send a web request, read the response, and check it against a set of rules. It has no idea what "IDOR" or "exposed `.env` file" actually means. A template is what supplies that meaning — a short, readable recipe for one specific weakness on one kind of app: which URL to hit, what a "vulnerable" response looks like, what a "safe" response looks like. So the intuition is correct: build the tool once, then add a new template whenever we want to check for a new weakness or adapt to a new app — no rebuild, no new release, no code change.

  Why that split is worth the extra layer, rather than just hardcoding every check into the engine:
  - **New checks ship fast.** Adding a check is writing a YAML file, not writing and testing new Go code — turnaround for "can we also check for X" drops from a code change + release cycle to editing a text file.
  - **We don't have to invent detection knowledge from scratch.** The security community already maintains a large, actively updated library of these recipes (Nuclei's `nuclei-templates` project) covering thousands of known exposed panels, misconfigurations, and technology fingerprints. Because our engine speaks a compatible template format, we can pull in that existing, vetted work directly instead of re-researching and re-writing detection logic ourselves for everything that's already publicly known. Concretely, via `pkg/templatesync` and `hackerfive templates sync`/`list`: a `git`-based sparse-checkout of a maintainer-curated, deliberately **pinned commit** (never `HEAD`/latest — a compromised upstream commit landing between pins can't silently reach a scan) into a persistent per-user config directory (`os.UserConfigDir()`) that survives a binary upgrade with zero manual copying. `--templates` loads both this synced directory and the project-authored `templates/` bundled with each release, together — see [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md)'s "Template sync command" for the full design.
  - **Non-engineers can contribute checks.** A template is a readable text file, not a pull request against the scanner's internals — a security researcher who knows *what* to check for doesn't need to know Go, or how the scanner is built, to add *how* to check for it.
  - **One engine, many apps and many bug types.** The same underlying request/compare logic works for crAPI's IDOR bug, DVWA's exposed paths, or a future customer's app — what changes between them is only which template file is loaded, not the program itself.

- **Template Structure Example:**
  ```yaml
  id: idor-user-profile
  info:
    name: IDOR in User Profile Endpoint
    author: YourName
    severity: high
    description: Test if user IDs are sequentially enumerable
  tags:
    - idor
    - api

  variables:                    # global scope — set once, available to every request below
    base_path: /api/users

  requests:
    - method: POST              # request 1: log in, extract the token for request 2
      path: /api/auth/login
      body: '{"email":"{{Email}}","password":"{{Password}}"}'
      extractors:
        - type: json
          name: auth_token      # becomes {{auth_token}} in later requests — request-chain scope
          path: token           # JSON path into the response body

    - method: GET
      path: "{{base_path}}/{{RangeInt(1|100)}}"
      headers:
        Authorization: Bearer {{auth_token}}
      matchers:
        - type: status
          status: [200]
        - type: word
          words:
            - "email"
            - "name"
      condition: auth_token != ""   # skip this request if the login request above didn't produce a token
  ```
  - **Extractors** pull a value out of one request's response (regex, JSON path, header) and bind it to a name; later requests in the same template reference it as `{{name}}`. This is what makes request chaining (login → use token) work — see `pkg/template` in [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) for where this lands in the build order: the native YAML engine step in Phase 1b (see [03-development-roadmap.md](03-development-roadmap.md) for current week numbers), out of scope for Phase 1a's Weeks 1-4.
  - **Variable scope:** `variables:` at the template's top level is global (visible to every request); anything bound by an `extractors:` entry is chain-scoped — visible only to requests *after* the one that produced it, not before, and not across separate template files.
  - **Conditionals:** an optional `condition:` on a request is evaluated against already-bound variables before the request fires; a false condition skips that request entirely rather than sending it with an empty/broken value.
  - **Correction (Phase 1b Step 3, implemented):** the `tags: [idor, api]` on this example doesn't mean what it looks like it means once the engine actually exists. An `idor`-tagged template routes through the existing `idor.Detector` (baseline two-account comparison, tokens supplied externally via `--auth-token`/`--other-auth-token`, `{{RangeInt(min|max)}}` marking the enumerated ID) — it does **not** run its own login request or custom matchers; those are rejected at load time on an `idor`-tagged template instead of silently ignored. The login-then-probe pattern shown above is real and works, but only for a template **without** the `idor` tag (see `templates/idor/example.yaml`, and [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) Step 3 for the full reasoning) — `{{RangeInt(...)}}` enumeration specifically is `idor`-tagged-only machinery, not available to a generic template like this one.

  **In plain English, this template does the following:**
  - Step 1: log in with the credentials supplied on the command line (`{{Email}}` / `{{Password}}`) and pull the auth token out of the login response.
  - Step 2: pick a random ID between 1 and 100 (`RangeInt(1|100)`) and request that user's profile using the token from step 1 — i.e., "am I, as this logged-in user, able to view someone else's profile by guessing their ID?"
  - It only counts as a finding if the response comes back `200 OK` **and** contains fields like `email`/`name` — a redirect to a login page or an empty body doesn't match, which is what keeps false positives low.
  - The `condition` guard on request 2 means: if login failed and there's no token, skip the probe instead of sending a broken/unauthenticated request that could look like a false finding.
  - Nothing here writes or deletes target data — it's a read-only probe, consistent with the project's scan-only rule.

#### 3. **HTTP Client: Go Standard Library + Custom Middleware**
- Use Go's `net/http` for base functionality
- Add custom middleware for:
  - Request rate limiting
  - Automatic retry with backoff
  - Proxy support (for routing through Burp, MitmProxy)
  - Custom headers (User-Agent rotation, API keys)
  - Request/response logging
- **Host error cache:** track consecutive errors per host across a scan; once a host crosses an error threshold, skip further requests to it rather than continuing to hammer an unreachable or broken target for the rest of an ID-enumeration run

#### 4. **Concurrency Framework: Go Goroutines + Worker Pool**
- Implement configurable worker pool (default: 25 concurrent requests)
- Queue-based job distribution for targets and templates
- Progress tracking and cancellation support

#### 5. **Result Storage & Reporting**
- **Output Formats:**
  - JSON (for programmatic use)
  - Markdown (for GitHub issue templates)
  - HTML (for stakeholder reports)
  - HackerOne JSON schema (for platform integration)
- **Exporter interface:** one `Exporter` interface (`Export(w io.Writer, findings []detectors.Finding) error`) with one implementation per format above, dispatched by `ExporterFor(format string)` — justified since multiple concrete formats are already planned (rule of three), not a speculative abstraction. No separate `Tracker`/issue-creation interface (GitHub, Jira, etc.) — HackerOne is the only external integration target (see [01-overview-and-strategy.md](01-overview-and-strategy.md)), and even that's report-drafting export, not live issue tracking.

- **Optional:** SQLite for local finding history

#### 6. **CLI Framework: Cobra (Go)**
- Standard command structure
- Flag parsing and validation
- Help documentation auto-generation

#### 7. **Web UI: Local-Only Embedded Server (Optional)**
- `hackerfive serve` runs a local, loopback-only-by-default web server (Go stdlib `net/http` + `html/template`, no separate frontend build/toolchain) over the same, unmodified Scanner Engine below — a second interface to the engine, not a second implementation of it. Never a substitute for the CLI: CI/scripted use and full-flag-control power users keep using `hackerfive scan` directly.
- Interactivity via **htmx** (vendored, `go:embed`-ed alongside the CLI into the same cross-compiled binary — no separate install step, no hosted/cloud mode) rather than a hand-rolled JS layer or a full SPA framework: server-rendered HTML stays the source of truth, form submits/live updates swap DOM fragments instead of full page reloads.
- Live findings/logs stream to the browser via Server-Sent Events, backed by `Engine`'s `WithFindingCallback`/`WithLogCallback` hooks (see Scanner Engine, below) — this is what "Callback-based streaming results," formerly listed under Future Considerations, actually became once something needed it.
- CSRF via a hand-rolled double-submit cookie (no third-party framework, consistent with the Minimal Dependencies stance below); a non-loopback bind requires a one-time bootstrap token, exchanged on first use for an `HttpOnly` session cookie.
- Full design in [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md).
- **A third frontend for LLM agents — MCP server (`pkg/mcpserver/`), Phase 6 Steps 1-2 now built.** [90-research-hackerbot.md](90-research-hackerbot.md) researched how other LLM-driven pentesting tools structure themselves and resolved the open design questions (a single coordinator, no shell/exec-shaped tool, MCP `elicitation` for human approval, and — per the Design Principles above — a deterministic decision engine with a tiered LLM fallback, never an LLM-first design); [91-research-recon-phase.md](91-research-recon-phase.md) added the recon-phase design that feeds it. [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md), [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md), and [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) schedule it as Phase 5-7 (recon/data-model/decision-engine foundations, then the MCP server plus the tiered LLM fallback and `tools.search`/`templates.search`, then hardening). Like the Web UI, it's a third frontend over this same unmodified Scanner Engine (an MCP server in `pkg/mcpserver/`, not a second implementation of it) — the diagram below is now mostly built, marked ✅/⬜ per step rather than treated as all-or-nothing.

  **What "elicitation" and "approval" actually mean here, in plain terms:** the `plan` MCP tool proposes a `PlanTree` (a set of target+detector pairs, resolved deterministically where possible) and then asks the *connected MCP client* — Claude Desktop, Claude Code, or any other MCP host, not HackerFive itself — to show a human a yes/no prompt ("approve this plan for execution?") before any request goes out. That prompt-and-answer exchange is MCP's own `elicitation` primitive; the human's answer is the "approval/reject." **Real mechanism, corrected 2026-09-02 after live-testing (see [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Step 2's Done note):** a tool handler can't just call the client synchronously mid-request under the current MCP protocol version — it has to return an `input_required` result and get retried once the client answers (SEP-2322's "multi-round-trip" pattern); this is handled transparently by the SDK on both ends, not something HackerFive's own code drives directly. **"Client does not declare elicitation support"** refers to MCP's own capability negotiation: some MCP clients (e.g. non-interactive/scripted ones) never advertise that they can show a human a prompt at all. Fixed 2026-09-02 (same day, a real gap found on user review): `plan`/`findings.triage` now check this *before* attempting to elicit (`clientSupportsElicitation`, `pkg/mcpserver/scope.go`) and degrade to a clean "returned unexecuted" result instead of the whole call failing — see [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Step 2's addendum.

  **Planned end-to-end flow (diagrammed 2026-08-31, updated 2026-09-02 — ✅ = built and live-verified today, 🟡 = partially built, ⬜ = designed, not yet built):**

  ```
  1. Recon, escalating waves 0-3                                          ✅ pkg/recon (Phase 5 Step 3a)
     (zero-touch → passive → active → bounded crawl)
             │
  2. Fingerprint (header/body/favicon/port signals)                       ✅ pkg/fingerprint (Step 3b, I2)
             │
  3. Decision engine: TechFact → registry match                          ✅ pkg/registry (Step 3b, I1/I3)
             │  deterministic dispatch first (capability + template-tag
             │  reuse against the already-synced+pinned corpus — never
             │  a live/dynamic template download, see note below)
             │
             ├─ matched? ─────────────────────────────────────────────▶  pending leaf(ves)
             │
             └─ no match ──▶ tiered LLM fallback (Decision 5/6)          ✅ I4 (Phase 6 Step 2) — pkg/llmfallback
                                   │
                                   ├─ still no coverage? ──▶ visible     ✅ unresolved-leaf rendering
                                   │   `unresolved` leaf (never dropped)    (Step 3b/4, live-verified)
                                   │
                                   └─ frontier tier authors a NEW
                                      template ──▶ templates-proposed/  🟡 written + rejection-pipeline-
                                      (untrusted until promoted)            checked; E2's own promotion UI is
                                                                             still ⬜ (Phase 7) — see path note
             │
     [2+3 together are what BUILD the PlanTree — plan review happens
      ON the tree they produce, never before it exists]
             │
  4. PlanTree — read-only preview                                        ✅ pkg/agenttask + Web UI (Step 2/4)
             │
  5. Human approves the plan (MCP `elicitation`)  ◀────────────────┐     ✅ B1 (Phase 6 Step 2) — see the
             │                                                     │        plain-terms note above for what
             │                                                     │        this actually does today
  6. Scoped execution — approved leaves run, fanned out             │
     across scanner.Engine's existing worker pool                  │      ✅ doc15 §2's Executor — two tiers
     (parallel across independent leaves; a leaf whose detector    │         are really "R8-matched" vs.
     was picked by the LLM fallback, not R8, stays more            │         "LLM-assigned" (not "currently
     conservative — smaller blast radius on its first live run,    │         costing LLM calls" — execution
     not an ongoing LLM-cost concern at this stage)                │         itself makes no further LLM call)
             │                                                     │
             ├─ new out-of-scope host/path discovered? ────────────┘      ⬜ B4 scope-creep loop — still not
             │                                                              wired up; Step 3's job
  7. Leaf Status/Confidence updated continuously during execution        ✅ H2's `ApplyLeafUpdate`, leaf-only —
     (not a single late step)                                                `PlanTree` mutex added Step 2,
             │                                                               confirmed race-free under `-race`
             │
  8. Result interpretation → human final review                          ⬜ not yet built
             │
  9. Report (JSON/MD/HTML/HackerOne draft)                               ✅ pkg/reporter Exporter (Phase 4)
             │
  10. HackerOne submission — separate, explicit `--yes` gate,            ✅ permanent invariant (CLAUDE.md/B3),
      never bundled into "reporting" itself                                  not yet wired to an agent flow
  ```

  **Two boundaries worth stating explicitly, since they're easy to blur:**
  - **"Reuse existing templates before creating new ones" (Decision 6) is bounded to whatever's already on disk at decision time — never a live download.** `pkg/templatesync` syncs 4 pinned categories (`http/exposed-panels`, `http/misconfiguration`, `http/technologies`, `http/vulnerabilities/generic`) from one fixed upstream commit into a persistent per-user directory, entirely decoupled from the release binary (only a small, hand-authored example set under `templates/` is `go:embed`-ed). The decision engine's template-tag matching only ever searches `templates/index.json` — itself only ever built from whatever `hackerfive templates sync` has *already* pulled down. Re-pinning or widening the synced categories is, by the sync code's own doc comment, *"a rare, deliberate, human-reviewed action... not a runtime toggle"* — so there is no safe middle ground where the decision engine or the LLM fallback expands template coverage on its own mid-scan; a fingerprint the synced corpus doesn't cover surfaces as a real, visible `unresolved` leaf instead. **A real gap found and fixed while drafting this diagram (2026-08-31):** this dev machine's synced directory held only a single leftover test fixture, not the real corpus — every earlier "live-verified template-tag match" claim in doc14 (Steps 3b/4) was true but exercised only the ~29 bundled example templates, not the intended corpus. Running `hackerfive templates sync` for real (1560+980+910+19 = 3469 templates pulled, 3194 indexed) and re-running `hackerfive plan` against crAPI raised the real template-tag-matched leaf count from 1 (`php-detect`) to 11 (nginx/php/phpldapadmin/etc. panel and technology templates) — the reuse-first mechanism works as designed, it just hadn't been exercised against the real corpus size until now.
  - **Parallel leaf execution (step 6) — built 2026-09-02, doc15 §2's Executor (`pkg/mcpserver/executor.go`).** Leaves under different hosts have no declared dependency on each other (`registry.Resolve` builds them as flat siblings), and `scanner.Engine`'s worker pool already parallelizes multiple templates/detectors against a target today — running several approved leaves concurrently reuses that same primitive, dispatched per-leaf; doesn't conflict with Decision 1 (a single coordinator dispatching scoped, disposable tool calls concurrently is exactly Cyber-AutoAgent's validated pattern, not a peer-agent mesh). `pkg/agenttask.PlanTree`'s mutex (added the same day) makes `ApplyLeafUpdate` safe from the executor's parallel leaf goroutines, confirmed via a `go test -race` run exercising concurrent calls, not just a single-goroutine assertion. **Not yet live-verified**: a real multi-leaf timing check against a lab target (elapsed time close to the slowest single leaf, confirming genuine parallelism rather than accidental serialization) — deferred, honestly, rather than assumed from the unit tests alone.
  - **`templates-proposed/`, not `templates/proposed/`.** A drafted template from the frontier tier lands in a directory named `templates-proposed/` at the repo root — a sibling of `templates/`, not a subdirectory of it. Real gap found wiring this up: `templates/` is walked *recursively* by every existing template loader (`scanner.Engine`, `templates.list`/`search`, `hackerfive templates`), so a subdirectory would have put an untrusted, LLM-drafted template directly into the live scan corpus the moment one was written — exactly what "never running against a live target without separate human promotion" is supposed to prevent. Fixed before any code exercised it.

#### 8. **Dependencies (Minimal)**
```
- github.com/spf13/cobra (CLI)
- gopkg.in/yaml.v3 (YAML parsing)
- github.com/json-iterator/go (fast JSON parsing)
- github.com/santhosh-tekuri/jsonschema/v5 (validates docs/schema/finding.schema.json and recon-result.schema.json — Phase 5; checked for real transitive footprint before adding, per this list's own discipline below: zero transitive dependencies, confirmed via a scratch-module `go get`)
- github.com/modelcontextprotocol/go-sdk (`pkg/mcpserver`, MCP server — Phase 6 Step 1; official SDK, maintained with Google; checked for real transitive footprint before adding: 11 new modules, two already pinned in this project at identical versions — see [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Step 1's Done note for the full verification)
- (No new dependency) `pkg/llmfallback` (Phase 6 Step 2's tiered LLM fallback client for a local model runtime + OpenRouter) is a plain `net/http`/`encoding/json` REST client — both APIs are OpenAI-chat-completions-compatible, confirmed zero new `go.mod` entries at implementation time, not just predicted — see [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Step 2's Done note
- (Optional) github.com/chromedp/chromedp (for browser-based XSS validation)
```

**`pkg/llmfallback` configuration — environment variables only, per CLAUDE.md's credential-handling rule.** `cmd/hackerfive/dotenv.go` (added 2026-09-02, no new dependency — a few lines of stdlib code) loads a `.env` file from the current working directory once at startup, for every subcommand (`scan`/`serve`/`mcp-serve`/...) on Windows and macOS/Linux alike; a real environment variable you've already exported always wins over `.env`. See `env.example` at the repo root for every variable with its default and a one-line explanation (named without the leading dot — a permission rule in the dev environment that produced this doc blocks writing `.env`-prefixed files directly; copy it to `.env` yourself). The full list:
- `HACKERFIVE_LOCAL_MODEL_URL` — local model runtime's base URL, OpenAI-chat-completions-compatible (e.g. Ollama). Default `http://localhost:11434`.
- `HACKERFIVE_LOCAL_MODEL_NAME` — the local model to request. Default `llama3.1` — a placeholder, not a verified recommendation; set explicitly to whatever model is actually pulled locally (`ollama list`).
- `OPENROUTER_API_KEY` — OpenRouter API key. Absent means the frontier tier (new-template drafting only) is unavailable; the local tier still works on its own.
- `HACKERFIVE_OPENROUTER_MODEL` — the OpenRouter model ID to request. Default `openrouter/auto` — also a placeholder per CLAUDE.md's "don't rely on your own knowledge of library/framework versions" discipline, which applies just as much to a model catalog that changes on its own schedule; pick a real, current model ID from OpenRouter's own catalog and set this explicitly.
- `HACKERFIVE_OPENROUTER_PRICE_PER_1M_INPUT_USD` / `HACKERFIVE_OPENROUTER_PRICE_PER_1M_OUTPUT_USD` — override the per-1M-token USD prices used to compute a call's real cost against the spend ceilings below (defaults are placeholders, not current OpenRouter pricing — confirm the real rate for whatever model is actually configured). The local tier is always costed at $0 (self-hosted, no metered API).
- `HACKERFIVE_SPEND_CEILING_USD` — default per-*call* spend ceiling (see below). Default `$0.10`.
- `HACKERFIVE_SPEND_CEILING_TOTAL_USD` — process-lifetime cumulative spend ceiling (see below). Default `$2.00`.

If neither the local tier is reachable nor `OPENROUTER_API_KEY` is set, `llmfallback.New()` fails outright and every I4 call for that `plan`/`findings.triage` invocation escalates to a human rather than silently doing nothing.

**Spend ceiling is a dollar amount, not a token count, and — added 2026-09-02, real user feedback — there are two of them, not one.** A token budget means something different per model/tier (a frontier-model token costs orders of magnitude more than a local one), so USD is what actually bounds spend regardless of which tier answered a given call. Cost per call is computed from the real `usage.prompt_tokens`/`usage.completion_tokens` OpenRouter returns, multiplied by the two price-per-1M-token env vars above; local-tier calls always cost $0.
- **Per-call ceiling** — `planInput.SpendCeilingUSD` (an argument to the `plan` tool call itself, falling back to `HACKERFIVE_SPEND_CEILING_USD`, default `$0.10`), tracked on `agenttask.PlanTree.SpendCeilingUSD`/`SpendSoFar()`. Scoped to one `plan`/`findings.triage` call's own resolution pass — once crossed, remaining unresolved leaves/fields for *that call* escalate to a human instead of issuing more LLM calls.
- **Process-lifetime cumulative ceiling** — `llmfallback.GlobalSpendCeilingUSD()`/`GlobalSpendSoFar()` (`HACKERFIVE_SPEND_CEILING_TOTAL_USD`, default `$2.00`), checked in `Client.complete` before every frontier-tier call, independent of which `plan`/`findings.triage` call made it. This is the guard that actually matters once a server is expected to field many separate calls over its lifetime — the per-call ceiling alone doesn't bound that aggregate.

Matcher/regex matching uses the standard library `regexp` (RE2) — it's arm64-native, avoids cgo, and keeps cross-compiled CI builds reproducible. (An earlier draft of this list named `github.com/valyala/fastregexp`, which does not exist as a published package — do not add it.) Only reach for a third-party engine such as `github.com/dlclark/regexp2` if a template genuinely needs PCRE-only features RE2 can't express (backreferences, lookahead).

**Lesson (Phase 4, 2026-08-29):** the same "verify before trusting the package page" discipline applies beyond version numbers — `interactsh-client`'s own pkg.go.dev listing gave no indication that importing it pulls in ~134 new go.mod lines (an embedded database, host-introspection libraries, an embedded FTP server), all needed by the library's server-mode code paths, not the client use HackerFive actually needed. Discovered by actually running `go get` and reading the resulting `go.mod` diff, not by reading the package's doc page — that's the verification step to repeat before committing to any new dependency in a plan doc, not an isolated incident. [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)'s R1b has the follow-up: the first-party fallback this forced is reused there rather than re-attempting the same dependency.

The misconfig detector's templates are pulled from upstream `nuclei-templates`, whose own engine is Go's stdlib `regexp` — so every regex matcher that ships there is already RE2-safe by construction; no audit needed. The one place a PCRE-only pattern could actually show up is the HackerFive-native IDOR baseline-comparison format (no Nuclei equivalent, see template example above) — if a future IDOR regex matcher needs a backreference or lookahead, that's the trigger to add `regexp2` for that matcher only, not switch the whole engine.

#### 9. **Development Tools**
- **Testing:** Go's built-in `testing` package + testify for assertions; native `testing.F` fuzz targets for the HTTP client and response parsers (the scanner parses untrusted target responses, which is attack surface for the tool itself, not just the target)
- **Build:** a `Makefile` wrapping `build`/`test`/`lint`/`fuzz`/`integration` targets, so the commands used throughout this doc set have one canonical entry point instead of being copy-pasted per doc
- **Error handling:** wrap errors with context via stdlib `fmt.Errorf("...: %w", err)` and inspect with `errors.Is`/`errors.As` — no custom error-context package; that solves a debugging-at-scale problem this project doesn't have yet
- **Linting:** golangci-lint
- **Documentation:** MkDocs (similar to Nuclei docs)
- **CI/CD:** GitHub Actions
- **Docker:** Multi-stage build for production image
- **Releases:** goreleaser for cross-compiled Linux/macOS/Windows binaries, backing the installation guide in the Phase 1b packaging step. The Web UI's templates/CSS/JS are `go:embed`-ed into that same cross-compiled binary (see Web UI, above) — "update the web UI" and "update the CLI" are the same release action, no separate frontend deploy.

### Development & Testing Stack

| Component | Tool | Purpose |
|-----------|------|---------|
| **Vulnerable Targets** | crAPI, vAPI, DVWA, Juice Shop, WebGoat, bWAPP | Safe testing environment |
| **HTTP Interception** | Burp Suite Community, MitmProxy | Debug requests/responses |
| **API Testing** | Postman, Insomnia | Template development |
| **Fuzzing** | ffuf, OWASP ZAP | Discover endpoints |
| **Recon** | subfinder, tlsx, dnsx, naabu, httpx, katana (real, shipped `pkg/recon` toolchain — installed via `hackerfive recon setup`, not a dev-only aid) | Asset discovery, live in every `--recon-depth active`/`full` run |
| **Version Control** | GitHub | Code, templates, issues |
| **Automation** | GitHub Actions | CI/CD, template validation |

## System Architecture

### High-Level Overview

```
┌───────────────────────────────┐   ┌──────────────────────────────────┐
│         HackerFive CLI         │   │   HackerFive Web UI (optional)    │
│  (hackerfive scan -t ...)      │   │  (hackerfive serve — htmx + SSE)  │
└────────────────┬────────────────┘   └────────────────┬───────────────┘
                 │                                      │
                 └──────────────────┬───────────────────┘
                                    │
      ┌──────────────┼──────────────┐
      │              │              │
   ┌──▼──┐       ┌───▼────┐    ┌───▼─────┐
   │Input│       │Recon   │    │Template │
   │Parse│       │Phase   │    │Parser   │
   └──┬──┘       └───┬────┘    └───┬─────┘
      │              │              │
      └──────────────┼──────────────┘
                     │
      ┌──────────────▼──────────────┐
      │   Scanner Engine (Core)     │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ IDOR Detector       │   │
      │  │ - ID enumeration    │   │
      │  │ - Response compare  │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Misconfiguration    │   │
      │  │ - Path matching     │   │
      │  │ - Header checks     │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Auth Bypass         │   │
      │  │ - JWT validation    │   │
      │  │ - Rate limiting     │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Template Runner     │   │
      │  │ - Matcher engine    │   │
      │  │ - Extractor engine  │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Worker Pool         │   │
      │  │ - Concurrency ctrl  │   │
      │  │ - Rate limiting     │   │
      │  └─────────────────────┘   │
      └──────────────┬──────────────┘
                     │
      ┌──────────────┴──────────────┐
      │                             │
   ┌──▼──────┐            ┌────────▼──┐
   │Finding  │            │Reporter   │
   │Store    │            │(JSON/MD)  │
   └─────────┘            └───────────┘
```

**This diagram predates Phase 4 (SSRF/Business Logic detectors) and Phase 5 (the recon waves, `pkg/fingerprint`, `pkg/registry`'s decision engine, `pkg/agenttask`'s `PlanTree`) — illustrative of the original shape, not a literal current picture.** Not redrawn here since the Code Walkthrough below and the Web UI section's "Planned end-to-end flow" diagram both already carry accurate, current detail on what those additions actually look like; a full redraw is real work worth its own pass rather than a quiet approximation folded into this one.

### Key Modules

#### 1. **Input Parser**
- Accepts targets: `-t http://example.com` or `-l targets.txt`
- Supports templates: `-t IDOR_*.yaml` or `-t /path/to/templates`
- Options: rate limit, concurrency, proxy, headers, authentication

#### 2. **Recon Phase** (`pkg/recon` — built and live-verified, Phase 5) — escalating, scope-checked waves
- **Wave 0** (zero-touch): `security.txt`/policy fetch via the existing `httpclient.Client`.
- **Wave 1** (passive): `subfinder` (subdomain enum), `tlsx` (cert inspection) — the explicit target itself is checked against `--scope` *before* this wave fires, not after, so an out-of-scope target gets zero active probes anywhere downstream.
- **Wave 2** (active, `--recon-depth active`+): `dnsx` (resolution), `naabu` (port scan), `httpx` (HTTP probe + `-tech-detect` + `-favicon -irr`, feeding `pkg/fingerprint`'s header/body/favicon/port signature matching — not just HTTP headers).
- **Wave 3** (bounded crawl, `--recon-depth full`): `katana`, plus `probeCommonPaths` (`/swagger.json`, `/.well-known/openapi.json`, etc.) populating `ReconResult.APISpec` when one's exposed.
- Real ProjectDiscovery binaries via fixed `exec.CommandContext` calls (not Nmap/Masscan) — same scoped-subprocess precedent as `pkg/templatesync`'s `git` call; installed via `hackerfive recon setup` (`pkg/toolsync`), no Go toolchain required. All rate-limit/concurrency numbers pass through to each binary's own native flag, since a separate OS process can't route through `pkg/scanner/httpclient`'s Go middleware.
- Output is `ReconResult` (`docs/schema/recon-result.schema.json`, frozen/versioned): `Hosts`/`Endpoints`/`TechStack`/`APISpec`/`OutOfScope`/`Warnings`, each fact carrying a `Source`/`Confidence`. A missing recon binary degrades that wave to a logged warning, never a hard failure.

#### 3. **Scanner Engine**
- **Detector Modules:** IDOR, Misconfiguration, Auth Bypass, etc.
- **Template Runner:** Parses YAML, executes requests, applies matchers
- **Matcher Engine:** Regex, word, status code, size, JSON extraction
- **Extractor Engine:** Pull dynamic values from responses for chaining requests
- **Streaming hooks:** optional `WithFindingCallback`/`WithLogCallback` on `Engine` — additive; the CLI's batch behavior (`Run` returning `([]Finding, error)` only once everything finishes) is unchanged when unset. The Web UI (below) is what actually consumes these, for live SSE updates mid-scan.

**Detector solutions, in plain English:**

- **IDOR Detector — "swap the ID, see what comes back."** Log in as one account, note what a normal response looks like, then request the same endpoint with a different object ID (another user's order, document, profile). If the response looks like real, authorized data (200 status, expected fields present) rather than a rejection (401/403, empty body, redirect to login), that's an access-control failure. Where possible this runs as a **two-account baseline comparison** (Account A's token accessing Account B's resource) rather than single-account ID guessing, which is what keeps the false-positive rate low — see the IDOR template example above and [01-overview-and-strategy.md](01-overview-and-strategy.md#prioritization-rationale).
- **Misconfiguration Detector — "check known-bad paths and settings."** No guessing or fuzzing: it requests a fixed list of paths/headers (`/.env`, `/.git`, missing `Content-Security-Policy`, wildcard CORS, etc.) and matches on status code + keyword/header presence. Because the checks are deterministic (a path either exposes `.env` or it doesn't), this is the lowest-effort, lowest-false-positive detector, and it runs almost entirely on templates pulled from the upstream `nuclei-templates` repo rather than custom Go code.
- **Auth Bypass Detector — "does the API enforce what it claims to enforce?"** A family of state-based checks rather than one technique: call an endpoint with no credentials at all (should reject, does it?), tamper with a JWT (strip the signature, flip `alg` to `none`), reuse one user's token against another user's session, or hammer a login endpoint to see if rate limiting actually kicks in. These require sequencing multiple requests and comparing outcomes, which is why this detector is rated medium-high automation difficulty in the roadmap.
- **SSRF Detector — "will the target fetch a URL I control?"** Probes any parameter that accepts a URL for scheme-based redirection (`file://`, `gopher://`) and a blind out-of-band check via an Interactsh-protocol callback (`pkg/oob`, extracted as its own package in Phase 5 so `pkg/recon`'s own OOB-verification path can reuse the same client). `--oob-server` (CLI) / the Web UI's OOB servers field defaults to 2 of ProjectDiscovery's public servers as of 2026-09-02 (a real, informed leak tradeoff — [discussions.md](discussions.md)); a self-hosted server or `--no-oob`/a cleared field are the ways to avoid that tradeoff, the latter appropriate for a real third-party engagement.
- **Business Logic Detector — "does the app's own workflow rules hold up?"** The one detector with real mutating checks (coupon self-mint/apply, a concurrent-fire apply race), gated behind `--allow-writes` — CLAUDE.md's one explicit, permanent exception to this tool's read/enumerate-only default; omitted, those checks are skipped with a stderr warning rather than silently run.
- **Template Runner (shared by all detectors)** — the common execution engine: it reads the YAML request/matcher/extractor definitions, fires the HTTP requests through the worker pool, and hands each response to the matcher engine. Detector-specific logic (IDOR's two-account diffing, auth bypass's multi-step sequencing) sits on top of this shared runner rather than each detector reimplementing HTTP handling from scratch.

#### 4. **Concurrency Manager**
- Worker pool with configurable size
- Request queue with priority support
- Progress tracking and ETA calculation
- Graceful shutdown and signal handling

#### 5. **Result Aggregator**
- Deduplicates findings
- Severity scoring
- CVSS calculation (if applicable)
- Output formatting

## Code Walkthrough: Main Files & Flow

A guided tour through the main files, for orienting in the actual codebase rather than this doc's diagrams.

### 1. Entry point
[`cmd/hackerfive/main.go`](../cmd/hackerfive/main.go) — sets up signal handling, hands off to Cobra's root command (`newRootCmd()` in [`root.go`](../cmd/hackerfive/root.go)).

### 2. CLI commands (`cmd/hackerfive/`)
- [`scan.go`](../cmd/hackerfive/scan.go) — the `hackerfive scan` command. Parses flags into a `scanner.Config`, validates it, builds a `scanner.Engine`, runs it, and dedups + exports the result via `reporter.Dedup`/`reporter.ExporterFor` (`--format json|markdown|html|hackerone-json`). This is the clearest map of "what a scan does": targets → templates → detector → auth → scope → output.
- [`serve.go`](../cmd/hackerfive/serve.go) — `hackerfive serve`, starts the embedded web UI (`webui.New(...).ListenAndServe(...)`).
- [`templates.go`](../cmd/hackerfive/templates.go) — `hackerfive templates sync|list|index`, wraps `pkg/templatesync`; `index` (Phase 5, R9) generates `templates/index.json`, the decision engine's template-tag-reuse lookup.
- [`recon.go`](../cmd/hackerfive/recon.go) — `hackerfive recon`, standalone entry point into `pkg/recon` (Phase 5); `recon setup` installs the 6 real recon binaries via `pkg/toolsync`, no Go toolchain needed.
- [`plan.go`](../cmd/hackerfive/plan.go) — `hackerfive plan`, runs recon then `registry.Resolve` and prints the resulting `PlanTree` as JSON (Phase 5) — a CLI-only preview of the same decision-engine output the Web UI's Plan-preview page renders.
- [`report.go`](../cmd/hackerfive/report.go) — `hackerfive report weaknesses|scopes|create|submit` (Phase 4), drafts a HackerOne `report_intent` from one scan finding via `pkg/hackerone`; `submit` is the one command that can make a report visible to a program, gated behind an explicit `--yes` (CLAUDE.md's permanent report-drafting-only invariant).

### 3. Scan orchestration (`pkg/scanner/`)
- [`engine.go`](../pkg/scanner/engine.go) — the core. `Engine.Run` loads scope (`scope.Parse`), loads templates (`nuclei.LoadDir`/`native.LoadDir`), spins up a `workerpool`, and per target: runs the selected built-in detector (`runDetector` → idor/misconfig/authbypass/ssrf/businesslogic) then runs every loaded template on top (templates are *additive*, not an alternative). `WithFindingCallback`/`WithLogCallback` are the hooks `pkg/webui` uses for live SSE streaming — the CLI path never sets them, so CLI behavior is unaffected.
- [`config.go`](../pkg/scanner/config.go) — `Config` struct + `Validate()`/`ValidateWithOptions()` (the latter added Phase 5 Step 7, letting a caller defer a specific detector's requiredness check — used only by the Web UI's recon-fill path, CLI behavior via `Validate()` unchanged), the single source of truth for what a scan needs (e.g. `idor` requires `--endpoint` + an auth token via the CLI's own `Validate()`, though the Web UI can defer/skip both when recon can fill the gap; `authbypass` requires `--protected-paths`).
- Supporting subpackages: `httpclient` (retry/rate-limit-wrapped HTTP client), `ratelimit`, `workerpool` (bounded concurrency), `scope` (target allow-list), `hosterrors` (circuit-breaker per host).

### 4. Detectors (`pkg/detectors/`)
- [`types.go`](../pkg/detectors/types.go) — the shared `Finding` struct every detector emits and the reporter/web UI consume.
- `idor/`, `misconfig/`, `authbypass/`, `ssrf/`, `businesslogic/` — one package each, each exposing `New(...)` + `Run(ctx, ...) ([]Finding, error)`.

### 5. Templates (`pkg/template/`)
Two parallel engines, both loaded and run by the engine for every target:
- `nuclei/` — parses/executes Nuclei-compatible YAML templates.
- `native/` — HackerFive's own richer template format (used for e.g. tagged IDOR checks), with `dsl/`, `extractor/`, `matcher/` as its building blocks.
- `templatesync/` — `git`-based sync of the community template corpus into a persistent OS config dir (survives binary upgrades — see [`sync.go`](../pkg/templatesync/sync.go)). `List` (extended Phase 5, R9) also flattens the bundled + synced corpus into `templates/index.json` for the decision engine's tag-reuse lookup.

### 6. Output (`pkg/reporter/`)
`Dedup` (exact-`Finding.ID` suppression) then `ExporterFor(format)` dispatches to one of four `Exporter` implementations — `jsonExporter` (wraps the original `WriteJSON`), `markdownExporter`, `htmlExporter` (`html/template`, auto-escapes evidence containing attacker payload text), and `hackerOneJSONExporter` (an offline, best-effort `report_intent` draft — placeholders for team/weakness/scope IDs, meant for manual review or as input to `hackerfive report create`). All Phase 4.

### 7. Recon, Fingerprinting & the Decision Engine (Phase 5 — new since this doc's last full pass)
- [`pkg/recon`](../pkg/recon) — the escalating-wave recon package described under "Recon Phase" above. [`recon.go`](../pkg/recon/recon.go) is the entry point (`Run`); `passive.go`/`active.go`/`crawl.go` are Waves 1/2/3; `aggregate.go` merges/dedups facts (tech-stack merge-not-append, API-spec first-hit-wins) into the final `ReconResult`; [`types.go`](../pkg/recon/types.go) is the frozen, schema-backed data shape; [`suggest.go`](../pkg/recon/suggest.go) is the recon-derived field-suggestion heuristics described under Web UI below.
- [`pkg/fingerprint`](../pkg/fingerprint) — a static signature table (`detector.go`/`signatures.go`, ~20 hand-authored entries) matching header/body/favicon/port signals, enriching `ReconResult.TechStack` on top of httpx's own `-tech-detect` output rather than replacing it.
- [`pkg/registry`](../pkg/registry) — `Capabilities` (`registry.go`) hand-transcribes doc01's capability table into a `tools.search`-ready shape; `Resolve` (`decisionengine.go`) turns a `ReconResult`'s tech facts into `PlanTree` leaves deterministically (capability match → template-tag match against `templates/index.json` → a visibly `unresolved` leaf, never silently dropped) — zero LLM involvement, per Design Principle 1 above.
- [`pkg/agenttask`](../pkg/agenttask) — [`plantree.go`](../pkg/agenttask/plantree.go): `PlanTree`/`PlanNode`, mutable only at leaves via `ApplyLeafUpdate` (a shape-changing patch is rejected, not silently applied).
- [`pkg/oob`](../pkg/oob) — the RSA-OAEP+AES-256-CTR Interactsh-protocol client, extracted from `pkg/detectors/ssrf` so `pkg/recon`'s own OOB-verification path can share it without duplicating the crypto.

### 8. Web UI (`pkg/webui/`)
[`server.go`](../pkg/webui/server.go) is the map of this package: `GET /` (the single unified Launch page — see below), `POST /scans`, `GET /scans`, `GET /scans/{id}[...]`, `GET /templates[...]`, `POST /templates/sync`, `POST /recon/setup`, `GET /plan-preview` — wrapped in CSRF + non-loopback-token middleware. It's a pure frontend — every handler ultimately calls the same `scanner.Engine`/`pkg/recon`/`pkg/registry`/`templatesync` that the CLI calls, no scan logic is duplicated. `jobs.go` (`JobStore`/`Job`) tracks async scan jobs, now also carrying wave-by-wave recon progress and the job's `ReconResult`; `handlers_launch.go`, `handlers_scan.go`, `handlers_plan.go`, `handlers_templates.go`, `handlers_toolsetup.go` are the per-page handlers.

**The Launch page (`handlers_launch.go`, Phase 5 Step 6-7) superseded three earlier separate pages** (New Scan / Recon / Guided Scan, and the old dashboard) with one landing page: a target field and five CSS-only radio-driven detector tabs (misconfig/idor/authbypass/ssrf/businesslogic — all wired by Step 7, not just the original three). Recon runs unconditionally on every submission (no opt-out checkbox as of Step 6's later revision) as one phase of the same `Job`, before the checked detectors run. `fillReconFields` (Step 7) then resolves any recon-fillable field a checked detector left blank — `idor`'s `EndpointTemplate` via `recon.SuggestIDOREndpointCandidates` (auto-fills on exactly one candidate, lists every candidate and skips on more than one, never guesses), `authbypass`'s protected/login/logout paths via a 401/403-status and path-shape heuristic, `ssrf`'s `SSRFParams` via a curated query-param-keyword match (no ambiguity to resolve, since it's a list) — always deferring to a value the operator actually typed, and always rendering a genuine gap (`idor: skipped — no candidate; fill in manually`) rather than silently dropping it or guessing. `misconfig`/`idor`/`authbypass`/`ssrf` all now run with zero operator input beyond a target (`businesslogic` can't — both its checks are inherently "as a logged-in account" with no unauthenticated mode). `GET /plan-preview` is a separate, still-read-only page rendering the same `PlanTree` `registry.Resolve` builds — informational only today (Phase 6 Step 4 is where it becomes an approval surface).

**Suggested reading order** to trace one scan end-to-end: [`scan.go`](../cmd/hackerfive/scan.go) → [`config.go`](../pkg/scanner/config.go) → [`engine.go`](../pkg/scanner/engine.go) → one detector (e.g. [`pkg/detectors/idor`](../pkg/detectors/idor)) → [`exporter.go`](../pkg/reporter/exporter.go). Then [`server.go`](../pkg/webui/server.go) → [`handlers_launch.go`](../pkg/webui/handlers_launch.go) to see how the web UI wraps recon + the decision engine + the same engine, asynchronously, into one job.

## Future Considerations (Not Yet Scoped)

Deferred because the trigger condition for needing them hasn't happened yet — revisit if the trigger occurs, not on a fixed date.

- **In-memory template cache:** only pays off when the same process re-parses the same templates across multiple scan jobs — true for a long-running service, not a single-shot CLI invocation. No action unless HackerFive grows a persistent service mode, which isn't currently planned.
- **Template signing:** relevant once a community template repository actually accepts third-party submissions — no such milestone exists yet in [03-development-roadmap.md](03-development-roadmap.md). Premature while templates are either project-authored or pulled from the pinned upstream `nuclei-templates` commit.
- **Auto-generated `SYNTAX-REFERENCE.md` (docgen):** the hand-written template-writing guide (Phase 1b packaging step) covers this need for now. Auto-generation from code solves a scale-of-external-contributors problem this project doesn't have yet.

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — the detectors this architecture must support
- [03-development-roadmap.md](03-development-roadmap.md) — build order for these modules
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — full Web UI and template-sync design behind the components summarized here
- [90-research-hackerbot.md](90-research-hackerbot.md), [91-research-recon-phase.md](91-research-recon-phase.md) — the research behind the agent-integration design below
- [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) — recon/fingerprint/decision-engine/`PlanTree` foundations **and** the Web UI's recon-derived field suggestions — done, not just planned; see "Recon, Fingerprinting & the Decision Engine" and the Launch page above
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md), [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — the MCP server / approval-gate / hardening work (Phase 6-7, not yet built) that will extend this architecture once that work starts
