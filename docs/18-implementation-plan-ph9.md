# Phase 9 Implementation Plan — Depth & Active Detection (Weeks 65-70)

> Part of the [HackerFive documentation set](../README.md).

## Objective

[17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) widens detection
*breadth* — new protocol support (TCP/TLS), served-JS mining, affected-version
gating, richer crawl — against the agent pipeline Phases 5-7 built. Every Phase 8
step is close to self-contained and needs no fresh design pass.

This phase is the **depth** half of the same expansion, split out on 2026-09-07
(see [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md)'s "Execution
order" section for the reasoning). Four capability areas were carried here rather
than left in Phase 8 because each one:

- needs its **own design pass** before implementation (the MCP client subset, the
  SQLi/upload success oracles, the XPath dependency footprint, the injection-marker
  ruleset);
- **wants Phase 8's surface-widening first** — the native `sqli`/`xss`/`lfi`
  detectors realise their value against the param surface Phase 8 Step 3 (JS
  endpoints) and Step 6 (content discovery / numeric query params, LT-83) produce;
- is the most likely to **grow after more live testing** — WAF-bypass and
  agent-surface work in particular are still short on real-world reference cases.

It also absorbs two trust items originally planned as their own steps in
[Phase 7](16-implementation-plan-ph7.md): the OWASP Agentic Top 10 mapping (that
doc's former Step 5, D4) and the agent-output-hygiene trio (that doc's former Step
6b — `templates/proposed/`, triage-assist annotations, structured feedback
capture). **2026-09-10 renumbering:** Phase 7 originally planned an "interim"
OWASP pass against shipped Phase 5-7 code before this phase's full re-walk, so
`v0.7.0` wouldn't ship with zero agent-security self-assessment. Since this phase
was always going to re-walk the same ASI01-ASI10 table in full shortly after —
doing it lightly first just means doing it twice — the interim pass was dropped
and Phase 7's Step 5 removed entirely; this step is now the *only* OWASP pass.
Phase 7's Step 6b was already deferred here and is unaffected by that change.
Doing the OWASP mapping before Phase 9 Steps 3-4 add agent-reachable and active
surface would only mean re-doing it.

**Read/enumerate-only throughout** — the same boundary every prior phase held
([05-hackerone-and-legal.md](05-hackerone-and-legal.md)). An active injection or
WAF-bypass payload's *only* effect is to reach the app: never a shell, a file
write, or data exfil, exactly as blind-SSRF verification already works.

## Scope

1. ⬜ **OOB blind-RCE verification** (Week 65) — *originally Phase 8 Step 4*
2. ⬜ **Remaining template-format gaps** (Weeks 66-67) — `xpath`, `flow:` cross-block `_N`, `flow:` script constructs, `substr`/`date_time`/`generate_jwt` DSL — *originally Phase 8 Step 7*
3. ⬜ **AI-agent surface modeling — `llms.txt` / `SKILL.md` / MCP** (Week 68) — closes LT-78; *originally Phase 8 Step 8*
4. ⬜ **WAF-aware probing + active injection / upload-bypass detectors** (Weeks 69-70) — closes LT-87; *originally Phase 8 Step 9*. The one phase that adds active vulnerability-class detectors.
5. ⬜ **Trust & agent-output hardening** (Week 70) — the OWASP Agentic Top 10 **full** re-walk (Ph7 D4) + `templates/proposed/` isolation (Ph7 E2) + triage-assist annotations (Ph7 F1) + structured feedback capture (Ph7 F2)
6. ⬜ **Eval maturity + release** (Week 70) — `v0.9.0`

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step lands, same convention as doc09-17.)

**Week numbers are nominal.** Work is sequenced by the "Execution order" backlog in
[17-implementation-plan-ph8.md](17-implementation-plan-ph8.md), and the `v0.9.0` tag
is cut when this phase's work is a coherent, green batch — not on a step count.

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **Literal command execution on a target.** OOB verification (Step 1) gets the
  detection value without it; it conflicts with the read/enumerate-only rule and
  most program authorization.
- **`sqlmap` / `ffuf` / other traffic-generating tool dependencies.** Step 4's SQLi
  and content work is a bounded first-party subset over recon's existing candidate
  set, riding the shared rate limiter — not a new fuzzing engine.
- **Headless/DOM XSS via Chromedp as a *community-template* capability.** Step 4's
  reflected-XSS context probe is first-party and sandboxed; the `headless:` template
  rejection for arbitrary community templates is unchanged (same carve-out Phase 8
  Step 6's JS-rendered crawl already respects).
- **A generic XPath/XML query engine.** Step 2's `xpath` support is scoped to the
  matcher/extractor shapes real corpus templates use, evaluated against a concrete
  dependency footprint per CLAUDE.md's dependency rule.

## Dependencies used in this plan

- **Step 1 (OOB blind-RCE)** — reuses `pkg/oob`'s Interactsh client unchanged
  (Phase 6 wired it into the template engine). No new dependency.
- **Step 2 (`xpath`)** — needs an XPath-over-HTML library (e.g. `antchfx/htmlquery`
  + `antchfx/xpath`). **Verify the real transitive footprint** via a scratch-branch
  `go get` and a `go.mod` diff before committing, exactly as doc02 §8's
  `interactsh-client` lesson requires. If disproportionate, implement only the query
  subset real templates use.
- **Step 2 (`generate_jwt` DSL function)** — HMAC signing is stdlib; RSA/EC may want
  the JWT library Phase 2 already pinned. Confirm the same version, no new module.
- **Step 3 (AI-agent surface)** — an MCP client subset for an unauthenticated
  `tools/list` call. Prefer the go-sdk client already vendored for `pkg/mcpserver`
  if it exposes a client mode at a proportionate cost; otherwise a minimal
  hand-rolled JSON-RPC-over-HTTP client for the two methods needed. Decide at design
  time, footprint-checked.
- **Step 4 (WAF / injection / upload-bypass)** — all stdlib + `pkg/uniformwall`
  (Phase 7 D6) for the block-page fingerprint primitive. No new dependency.

---

## Step 1: OOB Blind-RCE Verification (Week 65) — ⬜ not yet implemented

*Originally [Phase 8](17-implementation-plan-ph8.md) Step 4.*

### Design

[follow-up.md](follow-up.md) Detection Coverage: "Add — extend the SSRF Interactsh/OOB
pattern to RCE: prove execution via callback, never run attacker-meaningful commands."
Phase 6 already wired `pkg/oob` into the template engine (`interactsh_*` support), so
the infrastructure exists.

The RCE-verification pattern is: for a candidate injection point, send a payload whose
*only* effect is a DNS/HTTP callback to a correlated Interactsh host (e.g.
`nslookup <nonce>.<oob-host>` / `curl <nonce>.<oob-host>` shaped for the suspected
context), then correlate a callback. A callback proves code execution; its absence
proves nothing (non-vulnerable target). No payload ever does anything beyond the
callback — no file read, no reverse shell, no data exfil — which keeps this inside the
read/enumerate-only boundary the same way blind-SSRF verification already is.

Scoped narrowly: this is a *verification* layer for injection points a template or
detector already flagged as suspicious, not a new fuzzing engine. It reuses
`awaitOOB`/`oob.Poller` exactly as the `interactsh_*` template path does.

### Files (anticipated, confirm at implementation time)
- `pkg/detectors/rce/` (new) or an extension of the ssrf detector's OOB machinery — the callback-only payload shaping + correlation.
- `pkg/oob/` — reused unchanged; if the deferred idle-pause/deferred-correlation improvement (doc15 Step 2's logged OOB tradeoff) lands first, this benefits automatically.
- `pkg/registry/decisionengine.go` — an `rce` capability dispatched only from a concrete upstream signal (a template hit, a suspicious parameter), never speculatively.
- `tests/unit/detector_rce_test.go` — against the same `newFakeOOBServer` local fake every other OOB test uses; no real public OOB server in code or tests (the standing project rule).

### Verification
Unit tests against the local fake OOB server: a "vulnerable" fixture endpoint that
performs the callback → finding; a non-vulnerable one → no finding, no error. Live:
against a lab target with a known blind-RCE (WebGoat/bWAPP have candidates) with a
self-hosted or explicitly-authorized OOB server.

---

## Step 2: Remaining Template-Format Gaps (Weeks 66-67) — ⬜ not yet implemented

*Originally [Phase 8](17-implementation-plan-ph8.md) Step 7.*

### Design

The two [follow-up.md](follow-up.md) LT-22 / P1-4 template-rejection buckets that need
more than a self-contained parser addition (the self-contained ones — `+`, header
parts, `content_type_N`, `duration`, multi-key/file-based `payloads:`, `interactsh_*` —
are already done across Phase 6 addenda and the 2026-09-05 Tier-1 batch):

- **`xpath` extractor/matcher type** (~17 templates). Needs an XPath-over-HTML library.
  Verify the transitive footprint on a scratch branch first (doc02 §8 rule). If the
  footprint is proportionate, wire `type: xpath` into `pkg/template/extractor` +
  `pkg/template/matcher`; if not, implement only the query subset real corpus templates
  use.
- **`flow:` cross-block `_N` indexing** (~5-8 templates, plus the matching
  `interactsh_protocol_N` / `http_N_location` cases). Real Nuclei numbers `_N`
  *globally across separate `http:` request blocks* in a `flow:` template, not per-block
  — a materially different indexing model than the per-block correlation Phase 6 already
  shipped. Needs `runFlow` to thread a running global counter (or full per-request
  history) across its `http(N)` calls. Small in template count, genuinely distinct in
  design — hence deferred here rather than folded into the per-block work.
- **`substr()` / `date_time()` / `generate_jwt` DSL functions**
  ([follow-up.md](follow-up.md)). Not stdlib one-liners: `substr` needs Nuclei's
  end-vs-length argument semantics pinned against real templates, `date_time` is
  strftime-style formatting, `generate_jwt` is JWT signing (HMAC = stdlib; RSA/EC = the
  JWT library Phase 2 already pinned — confirm same version, no new module, per this
  doc's Dependencies note). Modest corpus-coverage gain; do the three together since they
  share the DSL-function registration surface.
- **`flow:` `if` / `set` / `for` / `let` / `var` script constructs**
  ([follow-up.md](follow-up.md), ~42 corpus templates). The larger `flow:` item: a
  `runFlow` redesign to carry mutable script state across blocks. Sequenced after the
  cross-block `_N` counter above (which establishes the per-`flow:` global-state
  plumbing this builds on), and descopable with a stated reason if the weeks run short —
  biggest single template-format gap left, also the deepest.

The other LT-22 buckets (`binary` matcher, 10 of the missing DSL functions, the
string/int coercion gap) are self-contained and were handled in the 2026-09-05
simple-fix batch — not this step; the last DSL three
(`substr`/`date_time`/`generate_jwt`) are the bullet above.

### Files (anticipated, confirm at implementation time)
- `pkg/template/extractor/extractor.go`, `pkg/template/matcher/matcher.go` — `xpath` type.
- `pkg/template/nuclei/{loader,executor}.go` — `flow:` global `_N` counter threaded through `runFlow`; `runFlow` carries mutable `if`/`set`/`for`/`let`/`var` script state across blocks.
- `pkg/template/dsl/dsl.go` — `substr`/`date_time`/`generate_jwt` registered on the DSL-function surface.
- `go.mod` — only if the xpath footprint check passes.
- `tests/unit/` — real sampled `xpath` + `flow:` cross-block + `flow:` script-construct templates, and `substr`/`date_time`/`generate_jwt` cases, as fixtures.

### Verification
Corpus rejection re-measurement before/after each sub-item (the same
load-and-count-rejections method every prior template-engine addendum used). Unit tests
against the real sampled templates each gap was measured from.

---

## Step 3: AI-Agent Surface Modeling — `llms.txt` / `SKILL.md` / MCP (Week 68) — ⬜ not yet implemented — closes LT-78

*Originally [Phase 8](17-implementation-plan-ph8.md) Step 8.*

### Design

[follow-up.md](follow-up.md) LT-78, live-observed on `shop.app` (2026-09-07): the host
publishes an agent skill manifest (`/llms.txt` → `/SKILL.md`: "search the catalog, build
a checkout on the merchant's domain, handle orders") and a live `shop-mcp` endpoint at
`/mcp/`. This is an emerging, largely-unscanned surface — prompt injection into agent
instructions, an unauthenticated MCP `tools/list`, agent-reachable state-changing tools,
checkout manipulation via the agent path — and HackerFive has neither a recon signal nor
a detector for it. Recon fetched none of it usefully on the live run (UA-blocked, then
429-drowned — this step depends on LT-75's browser-UA recon, which landed 2026-09-07).

Two read-only pieces:
- **A passive recon signal.** Wave 3 fetches and records `/llms.txt`, `/SKILL.md` (and
  any file `llms.txt` points at), `/.well-known/mcp`, `/.well-known/ai-plugin.json`, and
  a `GET /mcp` / `/mcp/` probe, into a new `ReconResult.AgentSurface` fact (manifest
  URLs, declared capabilities/tools, MCP endpoint + transport). Scope- and rate-limited
  like every other Wave 3 fetch; manifest text is stored as data, never followed as
  instructions.
- **A follow-up leaf class.** When `AgentSurface` is present: (1) an injection-marker
  scan of the manifest text — does it carry text shaped like instructions to a
  downstream agent ("ignore previous", tool-call syntax, role markers) that a merchant
  could have planted; (2) an unauthenticated `POST /mcp
  {"jsonrpc":"2.0","method":"tools/list"}` and a flag on any returned tool whose
  name/description implies a mutation (`create`/`update`/`delete`/`checkout`/`order`/`refund`);
  (3) a note when a declared capability implies agent-reachable state change on the
  merchant's own domain. All read-only enumeration — `tools/list` never becomes
  `tools/call`. Injection-marker patterns held to the <5% false-positive target
  ([03-development-roadmap.md](03-development-roadmap.md)) — a doubtful marker is left
  out, not guessed.

Needs its own design pass before implementation — the MCP client subset, the manifest
schemas (`llms.txt` is a de-facto convention, not a spec), and the injection-marker
ruleset each need pinning against real published examples. A Detection Coverage table
row lands in [follow-up.md](follow-up.md) when this ships.

### Files (anticipated, confirm at implementation time)
- `pkg/recon/agentsurface.go` (new) — the Wave 3 manifest / `/mcp` fetch + `ReconResult.AgentSurface` fact; `docs/schema/recon-result.schema.json` version bump.
- `pkg/detectors/agentsurface/` (new) — the injection-marker scan, the unauthenticated `tools/list` enumeration, the mutation-implying-tool flag.
- `pkg/registry/decisionengine.go` — an `agentsurface` capability dispatched only when the recon fact is present, never speculatively.
- `pkg/scanner/{config,engine}.go` — `agentsurface` wired into `runDetector`.
- `tests/unit/agentsurface_recon_test.go`, `tests/unit/detector_agentsurface_test.go` — fixture `llms.txt` / `SKILL.md` / MCP `tools/list` responses, including a planted injection-marker decoy set.

### Verification
Unit: a fixture manifest with planted injection markers and a decoy set (measure the
false-positive rate against the decoys explicitly); a fixture MCP `tools/list` carrying
both read-only and mutating tools (only the mutating ones flagged); `tools/call` is
never issued. Live: re-run against `shop.app` with the browser-UA recon and confirm
`/llms.txt`, `/SKILL.md`, `/mcp/` are recorded as an `AgentSurface` fact and the
enumeration runs read-only.

---

## Step 4: WAF-Aware Probing + Active Injection / Upload-Bypass Detectors (Weeks 69-70) — ⬜ not yet implemented — closes LT-87

*Originally [Phase 8](17-implementation-plan-ph8.md) Step 9.*

### Design

[follow-up.md](follow-up.md) LT-87, live-observed on `sandbox-royal.securegateway.com`
(2026-09-07): the whole ALSCO bounty premise is *bypassing* a WAF ("Secure Gateway", the
product under test) plus its upload filters. Read-only manual probes — `?article=8'`,
`?article=8 AND 1=1`, `?article=8/**/OR/**/1=1`, `?lang=../../../../etc/passwd` — all drew
`403`/`503`/`302` from the WAF. HackerFive today has: no WAF-detect step; no notion that
a `403` on a payload (vs `2xx` on a benign control) is *signal*, not a negative result;
no payload mutation/encoding retry; no upload-filter-bypass detector; and — the base gap
— **no native `sqli` / `xss` / `lfi` / command-injection detector at all** (`--detector`
is only `idor|misconfig|authbypass|ssrf|businesslogic`; those classes are covered solely
by generic corpus templates, which a WAF like this catches and which get short-circuited
by the D6 verdict besides). This step is the one place Phases 8-9 add active
vulnerability-class detectors rather than protocol/recon breadth.

**Sequencing:** deliberately last. The native `sqli`/`xss`/`lfi` detectors are
parameter-aware over recon's ID-/URL-/value-shaped params — they realise their value
against the param surface Phase 8 Step 3 (JS-static endpoints) and Step 6 (numeric
query-param ID candidates, LT-83) produce. Running this before that surface exists
under-tests the detectors.

Read/enumerate-only throughout — a bypass payload's *only* effect is to reach the app;
never a shell, file write, or data exfil, the same boundary blind-SSRF/RCE verification
already holds ([05-hackerone-and-legal.md](05-hackerone-and-legal.md)).

Four pieces, sequenced:
- **WAF-detect recon signal.** A `ReconResult.WAF` fact from: a known block-page
  fingerprint set (`pkg/uniformwall` already has the primitive), the `Server` /
  `cf-mitigated` / vendor headers, and a benign-vs-canary-payload status delta on one
  probed endpoint. Feeds a plan/report note and gates the retry logic below.
- **403-is-signal retry in the executor.** When a template or detector payload draws a
  `403`/`406`/`429`/`501` but a benign control on the *same* endpoint returns `2xx`,
  retry that one payload through a small, bounded mutation/encoding set (case, inline
  comment, URL/double-URL/unicode encoding, whitespace alternatives) — a bypass that
  then matches the original matcher is recorded as a finding ("WAF bypass: `<mutation>`").
  Bounded per endpoint; off unless the WAF fact is set, so a WAF-free target is
  unaffected.
- **Native `sqli` / `xss` / `lfi` detectors.** First-party, parameter-aware active
  checks over recon's ID-/URL-/value-shaped params (incl. LT-83's numeric query params):
  error-based + boolean/time-diff SQLi, reflected-XSS context probe, `../`-traversal /
  wrapper LFI. Conservative signatures, decoy-set FP rate measured against the <5%
  target. Dispatched by `resolveEndpointFacts` on a param candidate, like `idor` today.
- **`uploadbypass` detector.** For a discovered upload endpoint: permute extension ×
  `Content-Type` × magic bytes × trailing-null / double-extension against the target's
  allow-list, and confirm the stored file is retrievable and served executable — exactly
  the ALSCO 867316 challenge. Requires an upload endpoint from recon; never speculative.

Needs its own design pass — the mutation set, the SQLi confirmation logic (no `sqlmap`
dependency; a bounded first-party subset), and the `uploadbypass` success oracle each
need pinning. Descopable sub-item by sub-item with a stated reason if the weeks run short;
the WAF-detect signal + `403`-is-signal retry are the minimum that changes outcomes.

### Files (anticipated, confirm at implementation time)
- `pkg/recon/waf.go` (new) — the `ReconResult.WAF` fact (block-page fingerprint reuse from `pkg/uniformwall`, header set, benign-vs-payload delta); `docs/schema/recon-result.schema.json` bump.
- `pkg/template/nuclei/executor.go` — the bounded `403`-is-signal mutation/encoding retry, gated on the WAF fact; a `waf-bypass` finding shape.
- `pkg/detectors/sqli/`, `pkg/detectors/xss/`, `pkg/detectors/lfi/` (new) — first-party parameter-aware active checks; conservative signatures, decoy fixtures.
- `pkg/detectors/uploadbypass/` (new) — extension × content-type × magic-byte permutation against a discovered upload endpoint + a served-executable oracle.
- `pkg/registry/decisionengine.go` — `sqli`/`xss`/`lfi` dispatched from `resolveEndpointFacts` param candidates; `uploadbypass` only from a discovered upload endpoint; all note the WAF fact in their rationale.
- `pkg/scanner/{config,engine}.go`, `cmd/hackerfive/scan.go` — the four new `--detector` values wired into `runDetector`; `--detector` help updated.
- `tests/unit/{detector_sqli,detector_xss,detector_lfi,detector_uploadbypass,waf_detect,executor_wafbypass_retry}_test.go` — planted-vuln + planted-decoy fixtures, FP rate asserted; a fake WAF fixture (benign `2xx`, payload `403`, one encoding that slips through).

### Verification
Unit: each new detector fires on its planted-vuln fixture and stays silent on the decoy
set (FP rate recorded); the executor retry turns a fake-WAF `403` into a finding only
when a mutation actually matches, and does nothing when the WAF fact is absent;
`uploadbypass` confirms a served-executable file, not just a `200` on upload. Live: re-run
against the ALSCO sandboxes (once the IP block clears) — the WAF fact is set, blocked
payloads are recorded as attempts not negatives, and any real bypass is a finding with a
reproducible request.

---

## Step 5: Trust & Agent-Output Hardening (Week 70) — ⬜ not yet implemented

Absorbs [Phase 7](16-implementation-plan-ph7.md)'s former Step 5 (**D4**, OWASP
mapping — this is now the *only* pass, the interim pass having been dropped on
2026-09-10, see this doc's Objective) and former Step 6b (**E2 / F1 / F2**).
Deferred here because each one gates on surface this phase's Steps 3-4 add.

### Design

**D4 — OWASP Agentic Top 10 mapping.** Doc90 §3 Group D sketches HackerFive-specific
mitigations for each ASI01-ASI10 risk against the *design*; this step re-walks that
same table against the *actual shipped Phase 5-9 code* and records the result —
mitigated (cite the file/mechanism), or explicitly accepted as residual risk with a
stated reason — matching this project's own "revise down with reasoning, don't pad"
discipline. Run **after Steps 3 and 4** — Step 3 adds an agent-reachable
MCP-enumeration surface and Step 4 adds active injection detectors, both of which
change the ASI02 (Tool Misuse) / ASI04 (Supply Chain) / ASI05 (Unexpected Code
Execution) / ASI10 (Rogue Agents) rows materially versus doing this against Phase
5-7 code alone. The table below is carried over from Phase 7's design (drafted
2026-09-07, before that phase's own OWASP step was dropped) as a starting point —
every row still needs re-confirming against whatever actually shipped by the time
this step runs, not treated as already-settled:

| ASI risk | Doc90's proposed mitigation | Confirm against real code |
|---|---|---|
| ASI01 Agent Goal Hijack | Untrusted target data, never instructions; D3 hard-fail on missing scope | `pkg/mcpserver/tools_scan.go`'s D3 check (Phase 6 Step 3) |
| ASI02 Tool Misuse & Exploitation | Decision 2 (no shell/exec tool) + schema-validated tools | `pkg/mcpserver` tool registrations (Phase 6 Step 1) **plus this phase's Step 3 MCP-enumeration surface** |
| ASI03 Identity & Privilege Abuse | Short-lived, per-call credentials, never baked into agent context | Confirm `--auth-token`-equivalent handling in `tools_scan.go` doesn't persist beyond one call |
| ASI04 Agentic Supply Chain Vulnerabilities | Pinned-commit template sync + E2's staging directory; an LLM-drafted template (Decision 5's frontier-tier fallback) is itself an untrusted-supply-chain input, not just a hazard from an external source | `pkg/templatesync` (existing) + this step's `templates/proposed/` (E2, below) + confirm `pkg/llmfallback`'s drafted output is never loaded outside that same staging path (Phase 6 Step 2) |
| ASI05 Unexpected Code Execution | No code-execution tool exists; an LLM-drafted template must go through the same load-time block-rejection (`code:`/`javascript:`/`headless:`/`file:`) as any other untrusted template, no carve-out for being "agent-authored" | Confirm against the final Phase 6 tool list, and confirm `pkg/llmfallback`'s output path re-uses the existing template loader's rejection logic rather than a separate, possibly-laxer path |
| ASI06 Memory & Context Poisoning | `PlanTree` is durable, refreshed state, not open-ended memory | `pkg/agenttask` (Phase 5 Step 2) |
| ASI07 Insecure Inter-Agent Communication | Moot — single coordinator, no peer-agent channel | Confirm no peer-agent code was introduced anywhere in Phases 5-9 |
| ASI08 Cascading Agent Failures | Host-error-cache circuit breaker + spend/attempt ceiling | Existing `pkg/scanner/hosterrors` + Phase 6 Step 2's `H5`/Phase 7 Step 4's `H4` |
| ASI09 Human-Agent Trust Exploitation | Approvals only via audited Web UI controls or MCP `elicitation`, never the agent's own conversational assertion | Phase 6 Step 2's `plan` tool + Phase 7 Step 2's `B2` |
| ASI10 Rogue Agents | Kill switch/pause (Agent tab) + policy pre-flight hard blocker | Phase 7 Step 3's Agent tab (does it have an explicit pause/cancel action? confirm and add if missing) + Phase 6 Step 3's `D2` |

**E2 — agent-proposed templates land in `templates/proposed/`**, never a trusted path
(`./templates/` or the synced directory). No agent yet drafts a detection template,
so this is the staging convention only: any such template is written only to
`templates/proposed/`, and requires explicit human promotion (a file move, or a
`hackerfive templates promote <name>` command if that turns out worth building)
before it is ever loaded into a real scan. Deferred to here so it lands alongside
D4's re-walk, which is where an agent-authored-template supply-chain row (ASI04/ASI05)
actually gets confirmed against real code.

**F1 — triage-assist mode on the existing `Exporter` output.** Annotates exported
findings with the agent's own triage notes (severity-context, likely-false-positive
flags) as a clearly-labeled *additional* field, never altering the deterministic
`Finding.Severity`/`Confidence`. Additive/advisory, consistent with Phase 7's whole
"agent output is never authoritative over detector-set fields" theme.

**F2 — structured feedback capture.** When a human overrides or dismisses an
agent-surfaced finding/triage note during review, capture that decision in a
structured, queryable form (not just "the user closed the tab") — raw material for
Step 6's eval work and any future tuning of the coordinator's prioritization.

### Files (anticipated, confirm at implementation time)
- `docs/90-research-hackerbot.md` — D4's table re-walked: each row "confirmed against `<file>`" or "residual risk: `<reason>`".
- `templates/proposed/` — new, empty (gitkept) directory; `pkg/template` loader confirmed to never auto-load from it.
- `pkg/reporter/triageassist.go` — F1's annotation layer.
- `pkg/webui/handlers_scan.go` (or a new `feedback.go`) — F2's capture endpoint.
- `tests/unit/proposed_dir_isolation_test.go`, `tests/unit/triage_assist_test.go`.

### Verification
Every ASI row checked against real code (a file path and line, not a restated
intention). Unit test confirming `templates/proposed/` is never picked up by the
default `--templates` load path (mirrors `templates/nuclei-samples/`'s isolation,
inverted). Triage-assist output verified to never mutate the underlying `Finding`
struct it annotates.

---

## Step 6: Eval Maturity + Release (Week 70) — ⬜ not yet implemented — `v0.9.0`

### Design

Re-run the fixed eval challenge set (Phase 5's harness, Phase 7's agent-driven
extension) against the lab targets with every new detector from Steps 1, 3, 4 (and
Phase 8's Steps 1-3) enabled, and record the delta: new true positives found, and —
held to the same "revise down with reasoning, don't pad" discipline — any new
false-positive mode the new detectors introduced, tracked against the <5% target.
Full cost accounting per run as in Phase 7 Step 7 / Phase 8 Step 10. Then full
integration testing across the Phase 5-9 stack, and release.

### Files (anticipated, confirm at implementation time)
- `tests/eval/` — the new detectors added to the challenge matrix.
- `docs/03-development-roadmap.md` / `docs/follow-up.md` — Detection Coverage table rows moved from "Add" to "✅ shipped" with the measured yield.

### Verification
The eval runs against all lab targets with the new detectors on; the fp/fn numbers and
their delta from the Phase 8 baseline are recorded honestly — met, or not met with a
stated reason.

## Definition of Done (Phase 9, Weeks 65-70)

- [ ] OOB blind-RCE verification proves execution via a callback-only payload, never runs an attacker-meaningful command, and reuses `pkg/oob` unchanged; no real public OOB server in code or tests
- [ ] `xpath` matcher/extractor support ships (dependency footprint verified first) or is explicitly descoped with a stated reason; `flow:` cross-block `_N` indexing ships or is explicitly descoped; `substr`/`date_time`/`generate_jwt` DSL functions ship; `flow:` `if`/`set`/`for` script constructs ship or are explicitly descoped
- [ ] A passive recon signal records an `/llms.txt` / `SKILL.md` / MCP "agent surface" fact; a read-only detector scans the manifest for injection markers and enumerates an unauthenticated MCP `tools/list`, flagging mutation-implying tools, never issuing `tools/call` — decoy false-positive rate measured (LT-78 closed)
- [ ] A `ReconResult.WAF` fact is set from block-page / header / payload-delta signals; a payload `403`/`406`/`429` against a `2xx` benign control is retried through a bounded mutation/encoding set and a slip-through is a `waf-bypass` finding — off when no WAF fact (LT-87)
- [ ] First-party `sqli` / `xss` / `lfi` / `uploadbypass` detectors ship (parameter-aware, read-only, dispatched from recon candidates), each with its decoy-set false-positive rate measured against the <5% target — or a sub-item is explicitly descoped with a stated reason (LT-87)
- [ ] All ten OWASP Agentic Top 10 risks (Ph7 D4) are re-walked against real shipped Phase 5-9 code (file/line cited) and recorded as mitigated or accepted residual risk with a stated reason — the ASI02/ASI04/ASI05/ASI10 rows re-checked against Steps 3-4's new surface
- [ ] `templates/proposed/` exists, is confirmed never auto-loaded by the default `--templates` path, and requires explicit human promotion (Ph7 E2)
- [ ] Triage-assist annotations never mutate `Finding.Severity`/`Confidence` (Ph7 F1); structured feedback on an overridden agent finding is captured queryably (Ph7 F2)
- [ ] New-detector yield and any new false-positive mode measured against all lab targets, tracked against the <5% target, with full cost accounting
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.9.0` tagged and released, or explicitly held with a stated reason

## See also
- [17-implementation-plan-ph8.md](17-implementation-plan-ph8.md) — the breadth/precision half of the detection-coverage expansion, and the "Execution order" backlog this phase's steps sit at the tail of
- [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — the agent pipeline this phase's detectors feed into; its former Steps 5 / 6b are absorbed into this phase's Step 5
- [follow-up.md](follow-up.md) — LT-78 / LT-87 and the Detection Coverage table this phase closes out
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — the `code:`/`javascript:`/`headless:`/`file:` template-rejection boundary Steps 2 and 4 work within
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — the read/enumerate-only rule every step here holds to
- [03-development-roadmap.md](03-development-roadmap.md) — full phase roadmap this plan extends
