# Phase 8 Implementation Plan — Detection Coverage Expansion (Weeks 57-64)

> Part of the [HackerFive documentation set](../README.md).

## Objective

Phases 5-7 build and harden the recon → decision-engine → approval → scan → triage
agent pipeline. Nothing in them widens *what HackerFive can actually detect* — both
[15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) and
[16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) explicitly scope
detector/vulnerability-class expansion **out**. This phase is where that expansion
happens, against a pipeline that by this point actually exists to feed it.

Every item here is already assessed and approved in
[follow-up.md](follow-up.md)'s "Detection Coverage — Protocol/Capability Expansion"
table and its "Decision Engine & Recon→Plan Signal Use" / Live-Testing sections —
this doc schedules that backlog, it does not re-litigate the verdicts. The through-line
is the same read/enumerate-only boundary every prior phase held
([05-hackerone-and-legal.md](05-hackerone-and-legal.md)): banner-grab and passive
inspection, never literal command execution on a target.

## Scope

1. ⬜ **TCP protocol support + network-service exposure detector** (Weeks 57-58)
2. ⬜ **TLS/SSL passive checks** (Week 59)
3. ⬜ **JS static analysis — secrets & endpoints in served JavaScript** (Weeks 60-61)
4. ⬜ **OOB blind-RCE verification** (Week 62)
5. ⬜ **Affected-version (semver) gating for template selection** (Week 63) — closes P0-1b / LT-7
6. ⬜ **Recon-depth & JS-rendered crawl** (Week 63) — closes LT-8
7. ⬜ **Remaining template-format gaps needing a dependency or larger design** (Week 64) — `xpath`, `flow:` cross-block `_N`
8. ⬜ **Eval maturity + release** (Week 64) — `v0.8.0`

(⬜ = not yet implemented. Filled in with ✅/🟡 and a dated note as each step lands, same convention as doc09-16.)

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **Literal command execution on a target.** [follow-up.md](follow-up.md)'s Detection
  Coverage table already records this as "Reject" — OOB verification (Step 4) gets the
  same detection value without it, and it conflicts with the read/enumerate-only rule
  and most program authorization.
- **Headless/DOM XSS via Chromedp as a *community-template* capability.** Step 6 adds a
  JS-rendered crawl for recon signal; it does not relax the `headless:` template
  rejection for arbitrary community templates. First-party DOM-XSS validation stays
  the separately-planned, sandboxed item it already is.
- **A generic XPath/XML query engine.** Step 7's `xpath` support is scoped to the
  matcher/extractor shapes real corpus templates actually use, evaluated against a
  concrete dependency footprint per CLAUDE.md's dependency rule — not an open-ended
  XML feature.

## Dependencies used in this plan

**Most steps add no new dependency** — TCP/TLS work is stdlib (`net`, `crypto/tls`),
JS static analysis is regex/AST over already-crawled response bodies, OOB blind-RCE
reuses the existing `pkg/oob` Interactsh client Phase 6 already wired into the template
engine. **Two steps carry a real "verify before adding" gate:**
- **Step 7 (`xpath`)** — needs an XPath-over-HTML library (e.g. `antchfx/htmlquery` +
  `antchfx/xpath`). Verify the real transitive footprint via a scratch-branch `go get`
  and a `go.mod` diff before committing, exactly as doc02 §8's `interactsh-client`
  lesson requires. If disproportionate, implement only the query subset real templates
  use directly.
- **Step 5 (`generate_jwt` DSL function, if still open)** — HMAC signing is stdlib;
  RSA/EC signing may want the JWT library Phase 2 already pinned. Confirm it's the same
  version, no new module, before use.

---

## Step 1: TCP Protocol Support + Network-Service Exposure Detector (Weeks 57-58) — ⬜ not yet implemented

### Design

**Motivation, live-confirmed.** [follow-up.md](follow-up.md) LT-23: `staging.andertone.com`
exposes FTP (21) and MySQL (3306) straight to the internet behind an otherwise
bot-protection-walled HTTP surface. P1-2 already emits a visible `StatusUnresolved`
leaf naming an open port, but nothing can *check* it: `pkg/template/nuclei/loader.go`'s
`disallowedBlocks` hard-rejects any `tcp:`/`network:` template at load, so the whole
class of checks is structurally unloadable, and no `KindDetector` capability exists for
TCP.

Two pieces, both read-only:
- **A `tcp:` protocol type in the loader**, lifted from `disallowedBlocks` into a real
  (bounded) executor path: connect, optionally send a fixed probe string, read a banner,
  run word/regex/dsl matchers against it. No `code:`/script execution — a `tcp:` block
  that carries one stays rejected. This is the "deferred, not rejected" capability
  doc02's own template-rejection boundary already anticipated.
- **A first-party `netservice` detector** for the common unauthenticated-exposure cases
  a banner alone can't confirm: anonymous-FTP login (`USER anonymous` / `PASS`),
  unauthenticated MySQL/Redis/MongoDB/Elasticsearch connect-and-list. Each is a single
  read-only handshake that stops at "did it let me in", never enumerates or mutates
  data. Gated to the same `--scope` allow-list as every other detector; dispatched by
  `resolvePortFacts` promoting its `StatusUnresolved` port leaf to a real
  `StatusPending` `netservice` leaf once this detector exists.

### Files (anticipated, confirm at implementation time)
- `pkg/template/nuclei/loader.go` / `executor.go` — `tcp:` moved out of `disallowedBlocks` into a real bounded executor path; `code:`-carrying `tcp:` blocks still rejected.
- `pkg/template/tcpproto/` (new) — the connect/probe/read-banner primitive, `net.Dialer` with the scan's context + timeout.
- `pkg/detectors/netservice/` (new) — anonymous-FTP / unauth-DB / open-Elasticsearch checks.
- `pkg/registry/decisionengine.go` — `resolvePortFacts` emits a dispatchable `netservice` leaf (not just `StatusUnresolved`) once the detector is registered; `interestingPorts` reused as-is.
- `pkg/scanner/config.go` / `engine.go` — `netservice` wired into `runDetector`.
- `tests/unit/tcpproto_test.go`, `tests/unit/detector_netservice_test.go` — against local `net.Listen` fakes, no real external service.

### Verification
Unit tests against local TCP fakes (a fake FTP greeting, a fake MySQL handshake).
Integration: the crAPI/DVWA compose stack already exposes a real MySQL — confirm the
unauth-connect check fires against it and reports honestly. Live: re-run against the
LT-23 evidence target (`staging.andertone.com`, owned) and confirm the port-21/3306
leaves now resolve to real `netservice` findings instead of `StatusUnresolved`.

---

## Step 2: TLS/SSL Passive Checks (Week 59) — ⬜ not yet implemented

### Design

[follow-up.md](follow-up.md) Detection Coverage: "Add — passive checks (expired/weak
certs, deprecated protocols, weak ciphers) via stdlib `crypto/tls`, no new dependency."
Recon's Wave 2 already runs `tlsx`; this is the first-party detector that turns that
signal into findings and covers hosts `tlsx` didn't reach.

A `tls` detector that, per in-scope host:port, completes a handshake with
`InsecureSkipVerify` (so an expired/self-signed cert is inspected, not fatal) and
reports: expired / not-yet-valid / near-expiry certificate; a certificate chain that
fails real verification; a negotiated protocol below TLS 1.2; an offered cipher suite
on Go's known-weak list; missing SNI/hostname match. All read-only — one handshake,
no data sent. `Confidence: high` for cert-date/protocol facts (unambiguous),
`Confidence: low` for cipher-preference heuristics.

### Files (anticipated, confirm at implementation time)
- `pkg/detectors/tls/` (new) — the handshake + inspection logic, stdlib `crypto/tls` only.
- `pkg/registry/decisionengine.go` — a `tls` capability; recon's `tlsx`-derived facts (and any host with a live `https://` endpoint) drive a `tls` leaf.
- `pkg/scanner/{config,engine}.go` — `tls` wired into `runDetector`.
- `tests/unit/detector_tls_test.go` — against `httptest.NewTLSServer` and hand-built expired/self-signed cert fixtures.

### Verification
Unit tests with a fixture cert set (expired, self-signed, wrong-host, TLS 1.0-only
server). Live: run against a known-good target (no findings) and a deliberately
weak lab endpoint (findings match the fixture expectations).

---

## Step 3: JS Static Analysis — Secrets & Endpoints in Served JavaScript (Weeks 60-61) — ⬜ not yet implemented

### Design

[follow-up.md](follow-up.md) Detection Coverage: "Add — crawl served JS for hardcoded
secrets/endpoints (LinkFinder/SecretFinder-style), read-only, feeds IDOR/misconfig."
Recon's Wave 3 katana crawl already fetches JS bundles (`-jc`); this step *inspects*
what it fetched.

- **Endpoint extraction** — LinkFinder-style relative/absolute URL regex over each
  served `.js` body, deduped and normalized, folded into `ReconResult.Endpoints` with a
  distinct `Source: "js-static"` so downstream `resolveEndpointFacts` (P1-1) treats them
  like any other observed endpoint — directly widening the idor/ssrf/authbypass
  candidate surface LT-8 flagged as thin.
- **Secret detection** — a curated high-signal pattern set (AWS keys, Google API keys,
  Slack/GitHub tokens, private-key headers, `Authorization: Bearer` literals) with an
  entropy floor to cut noise, reported as `misconfig` findings with the matched file +
  line + redacted match. Deliberately conservative pattern set — this feeds the
  <5% false-positive target ([03-development-roadmap.md](03-development-roadmap.md)),
  so a doubtful pattern is left out, not guessed.

Both are pure functions over response bodies recon already has in hand — no new fetch,
no new dependency.

### Files (anticipated, confirm at implementation time)
- `pkg/recon/jsstatic.go` (new) — endpoint + secret extraction over Wave 3's fetched JS bodies; endpoints folded into `aggregate.go`'s endpoint set.
- `pkg/detectors/misconfig/` — a `checkJSSecrets` rule consuming the extraction output (or a thin `jssecret` detector if that keeps the rule set cleaner).
- `pkg/registry/decisionengine.go` — no new capability needed if secrets route through `misconfig`; endpoints flow through the existing P1-1 path automatically.
- `tests/unit/jsstatic_test.go` — fixture JS bundles with known planted endpoints/secrets and known decoys that must NOT match.

### Verification
Unit tests with planted-secret / planted-decoy fixtures (measure the false-positive
rate against the decoys explicitly). Live: run Wave 3 against a JS-heavy owned target
and confirm the new endpoints reach the plan tree's idor/ssrf candidate lists.

---

## Step 4: OOB Blind-RCE Verification (Week 62) — ⬜ not yet implemented

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

## Step 5: Affected-Version (Semver) Gating for Template Selection (Week 63) — ⬜ not yet implemented — closes P0-1b / LT-7

### Design

[follow-up.md](follow-up.md) P0-1b / P1-4 / LT-7, live-confirmed: `matchTemplateTags`
only ever uses a fingerprinted `:version` as a *stale-CVE penalty* (`scoreTemplateForTech`),
never an affected-range gate — so every Nginx host gets the identical top-8 CVE list
regardless of its actual version. The blocker is data, not logic: `templates/index.json`
carries no affected-version constraints.

- **Index schema** — `templatesync`'s index generator extracts a template's
  `metadata`/`classification` affected-version data (nuclei templates commonly carry
  `metadata: { max-version, min-version }` or a `compare_versions(...)` matcher whose
  constraint is machine-readable) into a new optional `AffectedRange` field on
  `templatesync.Entry`. Absent for templates that don't declare one — those keep
  today's tag+severity+recency scoring unchanged.
- **Gating in `matchTemplateTags`** — when the `TechFact` carries a parseable
  `:version` *and* the candidate template carries an `AffectedRange`, a version outside
  the range drops the template (not just penalizes it). Inside the range, or no range
  declared, or no fingerprinted version → unchanged behavior. Reuses `pkg/template/dsl`'s
  already-hand-rolled `compareVersionSegments` — no new dependency.
- **Per-tech version extraction** — recon captures a version for WordPress plugins
  (P1-3) and httpx tech-detect already yields some (`WooCommerce:11.1.0`), but not for
  Nginx/Apache/etc. Add a Wave 2/3 `Server:`-header + known-path version parse for the
  handful of high-value server products, feeding the same `:version` suffix shape
  `matchTemplateTags` already consumes.

### Files (anticipated, confirm at implementation time)
- `pkg/templatesync/index.go` — `Entry.AffectedRange`; the generator's extraction pass.
- `pkg/registry/decisionengine.go` — `matchTemplateTags`/`scoreTemplateForTech` gain the range gate; `techVersionSuffix` reused.
- `pkg/recon/` — server-product version parse (`Server:` header + a small known-path table), folded into `TechStack` as a `:version` suffix.
- `tests/unit/` — index-extraction fixtures; `decisionengine_test.go` cases proving an out-of-range CVE is dropped and an in-range one kept.

### Verification
Unit: a fixture index with declared ranges + a `TechFact` version on either side of the
boundary. Live: re-run the LT-7 evidence scenario (multiple real Nginx hosts at
different versions) and confirm they now get *different* template lists.

---

## Step 6: Recon-Depth & JS-Rendered Crawl (Week 63) — ⬜ not yet implemented — closes LT-8

### Design

[follow-up.md](follow-up.md) LT-8: katana is hardcoded to `-depth 2`, no
JS-rendering/headless mode, no flag for either — plausibly why the endpoint-driven
idor/ssrf heuristics find nothing on real targets with a live login boundary.

- **Configurable crawl depth** — a `--recon-depth`-adjacent knob (or a dedicated
  `--crawl-depth`) threaded into `runKatana`'s `-depth`, defaulting to today's `2` so
  scripted runs are unchanged.
- **Optional JS-rendered crawl** — katana's own headless mode (`-headless`/`-system-chrome`),
  behind an explicit opt-in flag, with a per-host timeout ceiling (the real cost LT-8
  names — headless across many hosts is slow). Off by default; when on, its output
  merges into the same Wave 3 endpoint set, deduped like any other source. Pairs
  naturally with Step 3's JS static analysis — a rendered DOM surfaces
  dynamically-built endpoints a static bundle scan can't.

No new dependency — katana already ships headless support; this is flag plumbing plus a
timeout guard.

### Files (anticipated, confirm at implementation time)
- `pkg/recon/crawl.go` — `runKatana` takes depth + a headless bool + per-host timeout.
- `pkg/recon/recon.go` — `ClientConfig`/`Option`s for the new knobs.
- `cmd/hackerfive/{recon,plan}.go`, `pkg/webui/handlers_launch.go`, `pkg/mcpserver/tools_recon.go` — surface the flags/fields.
- `tests/unit/crawl_test.go` — depth threaded through to the katana arg list; headless flag gated correctly.

### Verification
Unit: the katana arg list reflects the configured depth/headless. Live: a
depth-3 + headless run against a JS-heavy owned SPA yields materially more endpoints
than the depth-2 static run, and the extra endpoints reach the plan tree.

---

## Step 7: Remaining Template-Format Gaps (Week 64) — ⬜ not yet implemented

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
  design — hence deferred to here rather than folded into the per-block work.

The remaining LT-22 buckets (`binary` matcher, the ~12 missing DSL functions, the
string/int coercion gap) are self-contained and handled in the 2026-09-05 simple-fix
batch — not this step.

### Files (anticipated, confirm at implementation time)
- `pkg/template/extractor/extractor.go`, `pkg/template/matcher/matcher.go` — `xpath` type.
- `pkg/template/nuclei/{loader,executor}.go` — `flow:` global `_N` counter threaded through `runFlow`.
- `go.mod` — only if the xpath footprint check passes.
- `tests/unit/` — real sampled `xpath` + `flow:` cross-block templates as fixtures.

### Verification
Corpus rejection re-measurement before/after each sub-item (the same
load-and-count-rejections method every prior template-engine addendum used). Unit tests
against the real sampled templates each gap was measured from.

---

## Step 8: Eval Maturity + Release (Week 64) — ⬜ not yet implemented — `v0.8.0`

### Design

Re-run the fixed eval challenge set (Phase 5's harness, Phase 7's agent-driven
extension) against the lab targets with every new detector from Steps 1-4 enabled, and
record the delta: new true positives found, and — held to the same
"revise down with reasoning, don't pad" discipline — any new false-positive mode the
new detectors introduced, tracked against the <5% target. Full cost accounting per run
as in Phase 7 Step 7. Then full integration testing across the Phase 5-8 stack, and
release.

### Files (anticipated, confirm at implementation time)
- `tests/eval/` — the new detectors added to the challenge matrix.
- `docs/03-development-roadmap.md` / `docs/follow-up.md` — Detection Coverage table rows moved from "Add" to "✅ shipped" with the measured yield.

### Verification
The eval runs against all lab targets with the new detectors on; the fp/fn numbers and
their delta from the Phase 7 baseline are recorded honestly — met, or not met with a
stated reason.

## Definition of Done (Phase 8, Weeks 57-64)

- [ ] `tcp:` templates load and run (bounded connect/probe/banner-match); a `code:`-carrying `tcp:` block still rejected
- [ ] A `netservice` detector reports anonymous-FTP / unauthenticated-DB / open-Elasticsearch exposure, read-only, `--scope`-gated; `resolvePortFacts` dispatches it instead of only emitting `StatusUnresolved`
- [ ] A `tls` detector reports expired/weak/mismatched certs, sub-1.2 protocols, and weak ciphers, via stdlib `crypto/tls`, no new dependency
- [ ] Served-JS static analysis folds extracted endpoints into `ReconResult.Endpoints` (`Source: "js-static"`) and reports high-signal hardcoded secrets as `misconfig` findings, with its decoy-set false-positive rate measured
- [ ] OOB blind-RCE verification proves execution via a callback-only payload, never runs an attacker-meaningful command, and reuses `pkg/oob` unchanged; no real public OOB server in code or tests
- [ ] `templates/index.json` carries optional `AffectedRange` data; `matchTemplateTags` drops an out-of-affected-range CVE template when the `TechFact` version is known, and real multi-version Nginx hosts get different template lists (LT-7 closed)
- [ ] Crawl depth is configurable (default unchanged) and an opt-in JS-rendered crawl merges into the Wave 3 endpoint set with a per-host timeout ceiling (LT-8 closed)
- [ ] `xpath` matcher/extractor support ships (dependency footprint verified first) or is explicitly descoped with a stated reason; `flow:` cross-block `_N` indexing ships or is explicitly descoped
- [ ] New-detector yield and any new false-positive mode measured against all lab targets, tracked against the <5% target, with full cost accounting
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.8.0` tagged and released, or explicitly held with a stated reason

## See also
- [follow-up.md](follow-up.md) — the Detection Coverage table and Live-Testing (LT-7, LT-8, LT-23) findings this phase schedules
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) / [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — the agent pipeline this phase's new detectors feed into, and whose stated scope boundaries kept detector expansion out until now
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — the `code:`/`javascript:`/`headless:`/`file:` template-rejection boundary Step 1/Step 7 work within
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — the read/enumerate-only rule every step here holds to
- [03-development-roadmap.md](03-development-roadmap.md) — full phase roadmap this plan extends
