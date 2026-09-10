# Phase 8 Implementation Plan — Detection Coverage: Breadth & Precision (Weeks 57-64)

> Part of the [HackerFive documentation set](../README.md).

**Reprioritised 2026-09-07.** Originally a single 10-step "Detection Coverage
Expansion" phase. It was split: this doc keeps the **breadth + precision** work
(new protocol support, served-JS mining, affected-version gating, richer crawl —
Steps 1, 2, 3, 5, 6, 10), each of which is close to self-contained and needs no
fresh design pass. The **depth + active** work — OOB blind-RCE (was Step 4),
template-format gaps (was Step 7), AI-agent surface (was Step 8), WAF-aware +
native injection detectors (was Step 9) — moved to
[18-implementation-plan-ph9.md](18-implementation-plan-ph9.md), because each one
needs its own design pass, several *want* this phase's surface-widening first, and
they are the areas most likely to grow after the next live-testing rounds. The
moved steps keep their bodies below for provenance, each with a banner pointing at
the Phase 9 plan. See **Execution order** below.

## Objective

Phases 5-7 build and harden the recon → decision-engine → approval → scan → triage
agent pipeline. Nothing in them widens *what HackerFive can actually detect* — both
[15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) and
[16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) explicitly scope
detector/vulnerability-class expansion **out**. This phase (with Phase 9) is where
that expansion happens, against a pipeline that by this point actually exists to
feed it.

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
3. ✅ **JS static analysis — secrets & endpoints in served JavaScript; cloud-provider fingerprinting** (Weeks 60-61) — done 2026-09-09
4. → **Moved to [Phase 9](18-implementation-plan-ph9.md) Step 1** — OOB blind-RCE verification (body retained below for provenance)
5. ⬜ **Affected-version (semver) gating for template selection** (Week 63) — closes P0-1b / LT-7
6. 🟡 **Recon-depth, bounded content discovery & JS-rendered crawl** (Week 63) — closes LT-8; also robots/sitemap endpoint probing (LT-76) + an open-redirect/OAuth-flow rule (LT-77) + redirect-chain fidelity & per-host fact attribution (LT-64/LT-65/LT-84) + numeric-query-param ID candidates (LT-83) + per-path-timeout vs host-breaker tuning (LT-86). First tranche landed 2026-09-07 (crawl-depth flag, LT-76, LT-77 partial, LT-64/65/84b, LT-83, LT-50, LT-86b); second tranche landed 2026-09-07 (LT-40 OpenAPI-JSON spec walker, LT-61 known-CDN-ASN naabu skip). LT-40's YAML-body + spec-probe-path-widening tail (b)/(c) landed 2026-09-07 with the Phase 7 Step 6a batch. LT-89 (`recon --openapi-spec` ingest) + LT-90 (spec-driven authbypass) + LT-91 (per-candidate idor leaf fan-out) + LT-93 (leaf `Target` carries scheme+port) + LT-94 (endpoint-driven `authbypass`/`ssrf` leaf carries its recon fields, so `plan→execute` is self-sufficient) ✅ all done 2026-09-08 (pulled forward for the crAPI demo; LT-91/93/94 surfaced by the Step B/E live rounds — the pipeline now autonomously produces 13 verified actionable findings against crAPI, 0 FP). LT-99 (opt-in `--headless-crawl` JS-rendered katana) + LT-100 (opt-in `--param-mining` hidden-parameter oracle) ✅ both done 2026-09-09. **Still open:** content-discovery wordlist, LT-63 (CT-log sibling-API), LT-40 (a) — GraphQL SDL/introspection. (LT-92/95/96 — detector-precision fixes surfaced by the same crAPI round — ✅ done 2026-09-09 too, but filed as an ad-hoc batch rather than folded in here; see [follow-up.md](follow-up.md).)
7. → **Moved to [Phase 9](18-implementation-plan-ph9.md) Step 2** — remaining template-format gaps (`xpath`, `flow:`, DSL functions) (body retained below)
8. → **Moved to [Phase 9](18-implementation-plan-ph9.md) Step 3** — AI-agent surface modeling (`llms.txt` / `SKILL.md` / MCP), closes LT-78 (body retained below)
9. → **Moved to [Phase 9](18-implementation-plan-ph9.md) Step 4** — WAF-aware probing + active injection / upload-bypass detectors, closes LT-87 (body retained below)
10. ⬜ **Eval maturity + release** (Week 64) — `v0.8.0`

(⬜ = not yet implemented; 🟡 = partially landed. Filled in with ✅/🟡 and a dated note as each step lands, same convention as doc09-16.)

## Execution order (2026-09-07 reprioritisation)

**Phase ≠ release train.** The phase docs are a *plan*, not a release contract.
In practice this project already ships in dated tranches that cut across phase
boundaries (`post-demo-batch`, the near-term batch, `ph7-step4a/b/c`, this phase's
Step 6 first/second tranche). The `v0.x.0` tags are cut when a coherent batch of
work is done and green — **not** when a numbered step count is reached. Week
numbers in the Scope lists are nominal.

The remaining [Phase 7](16-implementation-plan-ph7.md) + Phase 8 + [Phase 9](18-implementation-plan-ph9.md)
open work is **one backlog**, ordered by (value × independence), with the eval /
release steps as terminal gates of their phase. Current order:

**Tier 1 — near-term "do now" (small, independent, precision / quality / perf):**
- [Phase 7](16-implementation-plan-ph7.md) **Step 5** ✅ **done 2026-09-07** — F3 (LT-67, content-gate response-grep secret templates) + F4 (LT-71, narrow-load fast path for a small leaf set). (Renumbered 2026-09-10 from "Step 6a" — Phase 7's OWASP-mapping step and its "6b" sub-item both moved wholly to Phase 9 Step 5, freeing this number.)
- **Step 6 tail** — LT-40's spec-probe-path widening + YAML spec bodies ✅ done 2026-09-07 (with the Phase 7 Step 5 batch, same file, same LT-30 gate); opportunistically the LT-6 weak-HSTS skip-list entry and LT-66's per-endpoint bucket-catch-all cleanup still open.
- [Phase 7](16-implementation-plan-ph7.md) **Step 7 — LT-107** ✅ **done 2026-09-10** — coverage-gap ledger (deterministic, no LLM). Pure read over post-scan data; standalone-useful for a human operator and the trigger input for LT-108. Fully independent.
- [Phase 7](16-implementation-plan-ph7.md) **Step 7 — LT-108** ✅ **done 2026-09-10** — `hackerfive suggest` (one stateless frontier call, print-only, H5-capped) — **Tier 1/2 boundary**: it consumes LT-107's ledger, so it follows it. No auto-apply / re-scan (that's LT-109/LT-110, unscheduled).

**Tier 2 — Phase 8 (breadth & precision; each near self-contained, dependencies already satisfied):**
1. **Step 1** — TCP + `netservice` detector. Biggest single new class, live-confirmed on a real target (LT-23). Fully independent.
2. **Step 3** ✅ **done 2026-09-09** — JS static analysis + cloud-provider fingerprinting. Directly widens the thin idor/ssrf endpoint surface every live run has complained about; closes P1-5. Minor `resolveTechFact` merge overlap with Step 6 / LT-84 still open (unaffected by Step 3's own changes).
3. **Step 5** — affected-version (semver) gating. Removes a concrete false-positive class (LT-7); `staleCVEPenalty` is only a stopgap today. Minor `matchTemplateTags` merge overlap with Phase 7 F3.
4. **Step 2** — TLS/SSL passive checks. Small, clean, fully independent.
5. **Step 6 third tranche (6c)** — the two recon-surface items promoted from
   [follow-up.md](follow-up.md) on 2026-09-08 because each has a measured
   endpoint-yield gap, not just a hypothetical one:
   - **LT-99** opt-in headless / JS-rendered katana (`--headless-crawl`).
     ✅ **done 2026-09-09** — CLI only (webui/mcp deferred); re-measured crAPI
     `:8888` 4 → 7 endpoints incl. a real `fetch()` call. See § Step 6.
   - **LT-100** first-party hidden-parameter mining (`--param-mining`).
     ✅ **done 2026-09-09** — CLI only (webui/mcp deferred); curated `go:embed`
     list + ≥2-signal diff oracle over the rate-limited `r.client`, 160-req/run
     cap. Live: 0% decoy FP on crAPI, 4 real params on Juice Shop. See § Step 6.
     Its *active* consumption (feeding native injection probes) pairs with
     [Phase 9](18-implementation-plan-ph9.md) Step 4.
6. **Step 6 remainder** — bounded content discovery + embedded wordlist (needs a wordlist provenance/licence decision), LT-63.
7. **Step 10** — eval + `v0.8.0`.

**Tier 3 — [Phase 9](18-implementation-plan-ph9.md) (depth & active; each needs a design pass, several want Tier-2 surface first):**
7. Phase 9 **Step 1** — OOB blind-RCE verification.
8. Phase 9 **Step 2** — template-format gaps (`xpath`, `flow:`).
9. Phase 9 **Step 3** — AI-agent surface (`llms.txt` / MCP) — LT-78.
10. Phase 9 **Step 4** — WAF-aware probing + native `sqli`/`xss`/`lfi`/`uploadbypass` — LT-87. **Last:** the injection detectors are parameter-aware and realise their value against the param surface Phase 8 Steps 3 + 6 produce.
11. Phase 9 **Step 5** — full OWASP Agentic Top 10 re-walk + Phase 7's E2/F1/F2 (deferred here because they gate on Steps 3-4's new agent + active surface).
12. Phase 9 **Step 6** — eval + `v0.9.0`.

**Independence caveats (merge-coordination, not ordering):** as-built, Step 3's
cloud-provider fact extraction landed in `pkg/fingerprint`'s signature table and
`pkg/recon/jsstatic.go`, touching `canonicalTechTags`/`primaryTechWord` derivation
in `matchTemplateTags` rather than `resolveTechFact` directly — so the caveat below
now applies to Step 3 alongside Step 5 / Phase 7 F3, not to Step 6 / LT-84's
(unrelated) `resolveTechFact` CDN-attribution guard. Step 5's semver gate and Phase 7
F3's content-gate both touch `matchTemplateTags` / `scoreTemplateForTech`. Neither pair is a sequencing
constraint — whichever lands first, the second rebases onto it.

**Explicitly out of scope for this plan, named rather than silently dropped:**
- **Literal command execution on a target.** [follow-up.md](follow-up.md)'s Detection
  Coverage table already records this as "Reject" — OOB verification ([Phase 9](18-implementation-plan-ph9.md)
  Step 1) gets the same detection value without it, and it conflicts with the
  read/enumerate-only rule and most program authorization.
- **Headless/DOM XSS via Chromedp as a *community-template* capability.** Step 6 adds a
  JS-rendered crawl for recon signal; it does not relax the `headless:` template
  rejection for arbitrary community templates. First-party DOM-XSS validation stays
  the separately-planned, sandboxed item it already is ([Phase 9](18-implementation-plan-ph9.md) Step 4).
- **A generic XPath/XML query engine.** [Phase 9](18-implementation-plan-ph9.md) Step 2's
  `xpath` support is scoped to the matcher/extractor shapes real corpus templates
  actually use, evaluated against a concrete dependency footprint per CLAUDE.md's
  dependency rule — not an open-ended XML feature.
- **Large-wordlist directory/parameter brute-forcing as a default.** Step 6's content
  discovery is a small curated list, opt-in, `--recon-depth full` only, and rides
  httpx's existing rate limit. A `directory-list-2.3-medium`-scale sweep stays a
  separate opt-in-only item — it collides with the DoS/brute-force exclusion nearly
  every program carries and with the tool's rate-limited, read-only premise.
  **Not** excluded (scheduled as 6c / LT-100): first-party hidden-parameter mining
  with a *curated* candidate list (hundreds, not tens of thousands), many-per-request
  chunking, a corroboration-gated diff oracle, and a hard per-host request cap — it
  is a targeted enumeration bounded like the content-discovery pass, not a
  traffic-generating fuzzing tool. What stays out is **ffuf-as-a-tool**: a second
  binary doing generic multi-position `FUZZ` at multi-thousand-request volume, which
  [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) already found does
  not reconcile with the shared `--rate-limit` bucket.

## Dependencies used in this plan

**No step retained in Phase 8 adds a new dependency** — TCP/TLS work is stdlib
(`net`, `crypto/tls`), JS static analysis is regex/AST over already-crawled response
bodies, semver gating reuses `pkg/template/dsl`'s hand-rolled version comparison, and
the crawl work is flag plumbing + an embedded wordlist. The two "verify before
adding" gates (`xpath`'s XPath-over-HTML library, `generate_jwt`'s RSA/EC signing)
moved with the template-format step to [Phase 9](18-implementation-plan-ph9.md)
Step 2 — see that doc's Dependencies section.

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

## Step 3: JS Static Analysis — Secrets, Endpoints & Cloud-Provider Signals (Weeks 60-61) — ✅ done 2026-09-09

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
- **Cloud-provider fingerprinting → `aws`/`s3`/`gcp` template tags**
  ([follow-up.md](follow-up.md) P1-5). The corpus carries `aws`/`s3`/`gcp`-tagged
  exposure templates the decision engine currently can't dispatch: `pkg/fingerprint`
  produces nothing more specific than the denylisted "Google Cloud" brand fact. A small
  signal pass — response headers (`x-amz-*`, `x-goog-*`, `Server: AmazonS3`), known
  bucket-URL shapes in crawled endpoints and in the JS bodies this step already scans —
  folds an actionable `aws`/`s3`/`gcp` fact into `TechStack`, so `matchTemplateTags`
  dispatches the cloud-exposure templates. Shares the AWS-key pattern work above: same
  bodies, same pass.

All three are pure functions over data recon already has in hand — no new fetch,
no new dependency.

### Files (anticipated, confirm at implementation time)
- `pkg/recon/jsstatic.go` (new) — endpoint + secret extraction over Wave 3's fetched JS bodies; endpoints folded into `aggregate.go`'s endpoint set.
- `pkg/detectors/misconfig/` — a `checkJSSecrets` rule consuming the extraction output (or a thin `jssecret` detector if that keeps the rule set cleaner).
- `pkg/registry/decisionengine.go` — no new capability needed if secrets route through `misconfig`; endpoints flow through the existing P1-1 path automatically.
- `pkg/fingerprint/` (or `pkg/recon/jsstatic.go`) — cloud-provider fact extraction from headers / bucket-URL shapes → `aws`/`s3`/`gcp` `TechStack` facts (P1-5).
- `tests/unit/jsstatic_test.go` — fixture JS bundles with known planted endpoints/secrets and known decoys that must NOT match.

### Verification
Unit tests with planted-secret / planted-decoy fixtures (measure the false-positive
rate against the decoys explicitly). Live: run Wave 3 against a JS-heavy owned target
and confirm the new endpoints reach the plan tree's idor/ssrf candidate lists.

### As-built (2026-09-09)

All three sub-items shipped roughly as designed, plus one implementation-time
correction and one real scoring bug the tests caught before it shipped broken:

- **No new katana flag was needed.** katana's own `-jsonl` output already
  carries `response.headers`/`response.body` by default (confirmed against
  upstream source, not assumed — no `-omit-body`/`-omit-raw` flag was ever
  passed). `runKatana` (`pkg/recon/crawl.go`) now decodes both and keeps a
  bounded set of `.js`-content bodies (`maxJSStaticAssets` = 25, each capped
  at `maxJSStaticBodyBytes` = 512 KiB) for `runJSStaticAnalysis` to read — a
  genuine "no re-fetch" pass, exactly as scoped.
- **Endpoint extraction** (`extractJSEndpoints`) is quoted-string-first
  (LinkFinder-style: pull every quoted literal, then filter in Go) rather
  than trying to encode "looks like a URL" into the regex itself — reuses
  the existing `IsPlausibleURLPath` (LT-85) / `IsNonRouteAssetPath` (LT-117)
  helpers the recon-derived candidate suggesters already hold themselves to,
  rather than inventing a second FP bar.
- **Secret detection** shipped the five patterns named in the design (AWS
  access/session keys, Google API keys, Slack tokens, GitHub tokens,
  private-key headers) plus the one shape-only pattern (`Authorization:
  Bearer` literal), gated by a Shannon-entropy floor + placeholder-word
  screen. **Correction from the design's anticipated files**: secrets don't
  route through a new `pkg/detectors/misconfig` rule or a `jssecret`
  detector — neither's `Run()` shape naturally accepts "here are pre-found
  facts, no request needed." Instead `ReconResult` gains a frozen `secrets`
  field (schema v1.9) carrying only a redacted match (never the real
  value), and `cmd/hackerfive/scan.go`'s existing `--recon-file` path
  (`jsSecretFindings`) converts them straight into `misconfig`-typed
  Findings before `Dedup` — a direct conversion, not a detector re-deriving
  something it can't independently confirm. Same "CLI (`recon`/`plan`/
  `scan --recon-file`) first, webui/mcp wiring deferred" scoping LT-99/100
  already established for this phase.
- **Cloud-provider fingerprinting** also split from the design's anticipated
  shape once the actual dispatch mechanics were traced through:
  header-based signals (`x-amzn-requestid`, `x-amz-cf-id`, `x-amz-bucket-
  region`, `x-goog-generation`, ...) landed as new `pkg/fingerprint`
  signatures — zero new code path, just table entries, firing through the
  same `runHTTPX` loop every existing signature already does. Bucket-URL-
  shape signals (`extractCloudBucketRefs`, S3 host-/path-style and GCS
  host-/path-style) attach their `aws`/`s3`/`gcp` `TechFact` to **the
  bucket's own host**, not the referencing page's host as first drafted —
  the corpus's real bucket-exposure templates (`aws-object-listing`,
  `s3-username-disclosure`) need to run *against the bucket* to mean
  anything, and a page can reference any third party's bucket with nothing
  to do with the target, so a mention alone earns neither a scan nor a fact
  about the referencing host. Gated on the bucket's own `--scope` check;
  out-of-scope goes to `OutOfScope` only, mirroring `runKatana`'s existing
  LT-52 cross-host handling.
- **Real bug caught by the tests, fixed before shipping**: `canonicalTechTags`
  pinning `"aws"`/`"s3"`/`"gcp"` to their real corpus tags wasn't sufficient
  on its own — `"aws"` is itself listed in `genericTechWords` (a bare
  hosting-brand word carries no product identity alone, the same reasoning
  `nonActionableTech`'s "Google Cloud" entry documents), so `primaryTechWord`
  returned `""` for it and it could never earn the 100-point exact-tag
  bonus in `scoreTemplateForTech` — capped at 50 (word-tag-only), which sits
  below `minTemplateLeafScore` (60, LT-48) for the mostly low/info-severity
  real AWS bucket-exposure templates. Fixed in `matchTemplateTags`: a
  canonical entry now derives its `primary` word directly from its own
  `q.include[0]` rather than re-running it through the generic-word filter —
  behavior-neutral for every pre-existing canonical entry
  (nginx/jquery/mysql/wordpress/woocommerce/litespeed), since each of those
  keys already equals what the filter would have derived anyway.
- Tests: `pkg/recon/jsstatic_test.go` (unit-level extraction/decoy coverage
  for all three sub-passes, plus two end-to-end `recon.Run` tests — one
  proving the whole pipeline populates `Secrets`/`Endpoints`/`TechStack`
  and round-trips the frozen schema, one proving an out-of-scope bucket
  mention produces neither a scan nor a fact); `pkg/fingerprint/
  detector_test.go` (each new header signature + a no-false-positive
  case); `pkg/registry/decisionengine_test.go` (the aws/s3/gcp dispatch,
  which is what caught the scoring bug above); `cmd/hackerfive/scan_test.go`
  (the secrets→Finding conversion never leaks the real value).

---

## Step 4: OOB Blind-RCE Verification — → RESCHEDULED to [Phase 9](18-implementation-plan-ph9.md) Step 1 (2026-09-07)

> **Moved to [Phase 9](18-implementation-plan-ph9.md).** The forward plan and DoD now
> live there; this body is retained for provenance and is unchanged from the original
> Phase 8 draft.

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
  `matchTemplateTags` already consumes. Also close the **P1-3 leftover**: for a
  WordPress plugin/theme slug whose crawled URLs carried no `?ver=`, one `readme.txt` /
  `style.css` GET per unversioned slug (the only new active fetch in this step) parsing
  `Stable tag:` / `Version:`, so plugin-CVE gating has a real version to work against.

### Files (anticipated, confirm at implementation time)
- `pkg/templatesync/index.go` — `Entry.AffectedRange`; the generator's extraction pass.
- `pkg/registry/decisionengine.go` — `matchTemplateTags`/`scoreTemplateForTech` gain the range gate; `techVersionSuffix` reused.
- `pkg/recon/` — server-product version parse (`Server:` header + a small known-path table), and `wpplugins.go`'s `readme.txt`/`style.css` probe for unversioned plugin/theme slugs (P1-3 leftover), folded into `TechStack` as a `:version` suffix.
- `tests/unit/` — index-extraction fixtures; `decisionengine_test.go` cases proving an out-of-range CVE is dropped and an in-range one kept.

### Verification
Unit: a fixture index with declared ranges + a `TechFact` version on either side of the
boundary. Live: re-run the LT-7 evidence scenario (multiple real Nginx hosts at
different versions) and confirm they now get *different* template lists.

---

## Step 6: Recon-Depth, Content Discovery & JS-Rendered Crawl (Week 63) — 🟡 first + second tranche landed 2026-09-07; 6c: LT-99 + LT-100 done 2026-09-09; only bounded content-discovery + LT-63 left — closes LT-8, LT-40, LT-50, LT-61, LT-64, LT-65, LT-76, LT-83, LT-84, LT-86, LT-99, LT-100

**🟡 First tranche landed 2026-09-07** (build / `go vet` / `go test -race` / `golangci-lint` all clean):

- **Configurable crawl depth** — `--crawl-depth` (`recon.WithCrawlDepth`, default 2, on `recon` + `plan`) → `runKatana -depth`.
- **LT-76** — `pkg/recon/endpointprobe.go`: a bounded (≤20), name-ranked Wave-3 pass GETs the status-less `robots.txt`/`sitemap.xml` endpoints with a no-redirect client, folding the first-hop status (+ `final_url` on a 3xx) back onto the `EndpointFact`.
- **LT-77** (partial) — `recon.IsRedirectFlowPath` + a `resolveEndpointFacts` rule dispatch the corpus's `open-redirect-generic` against a host with a `*/bounce` / `/oauth/authorize` / `/sso` / `*/logout` endpoint. A first-party per-param off-origin-`Location` probe is deferred to [Phase 9](18-implementation-plan-ph9.md) Step 4's active-detector work.
- **LT-64 / LT-65 / LT-84b** — httpx `-include-chain -location`; `analyzeRedirect` marks a cross-host redirect, the `EndpointFact` keeps the first-hop 3xx + records `redirect_chain`/`final_url` (schema v1.6) and withholds the destination's title/body/tech/fingerprint input; out-of-scope `final_url` warns loudly. `dropCDNTechWithoutHeader` drops an httpx CDN brand with no corroborating edge header.
- **LT-83** — `recon.numericQueryIDCandidates`: a numeric query param taking ≥2 distinct small-int values across crawled URLs for one path → `/path?key={{id}}`, with a pagination/cosmetic-key denylist.
- **LT-50** — `productEndpointSignatures` + `techEndpointSignatureHit`: a product-distinctive endpoint on the tech fact's own host promotes that host's pending product leaves to ConfidenceHigh.
- **LT-86b** — `recon.isRequestTimeout`: a client/context timeout is a per-path skip, not a host-down signal; only a connection-level failure feeds the LT-4 breaker.

**🟡 Second tranche landed 2026-09-07** (same gate clean):

- **LT-40** — `pkg/recon/specwalk.go` `walkOpenAPISpec`: a fetched OpenAPI 2.0 / 3.x JSON document's `paths`/`parameters` walked into `EndpointFact{Source: "api-spec"}` (basePath / `servers[0].url` path prefix, `{param}` templating kept verbatim, documented query keys appended keyless, cap 200). `probeCommonPaths` keeps the spec-path body (≤3 MiB) and walks it at the existing LT-30-gated `APISpecFact` record site. `recon.isSpecPathParam` makes `SuggestIDOREndpointCandidates` treat a `{param}` segment as an ID position → `/users/{id}` → `/users/{{id}}` with no fabricated id. **Live-validated 2026-09-07** against crAPI's real 101 KB `crapi-openapi-spec.json` (served locally): all 40 routes walked; `plan --recon-file` derived 6 `idor` `endpoint_template` candidates from the `{param}` paths, incl. crAPI's real BOLA path family, plus a `businesslogic` leaf off the spec-walked coupon path. YAML bodies + framework-convention spec paths landed 2026-09-07 (Phase 7 Step 6a batch); GraphQL introspection still open.
- **LT-61** — `pkg/recon/cdnasn.go` `cdnEdgeASNs`: a dedicated-CDN-only ASN table; Wave 1's ASN lookup runs it through `cdnForASNField`, adds a `cdn-edge:` HostFact note and `agg.markCDNEdge` on a hit; `runNaabu` drops marked hosts from the port scan (fresh slice, per-host LT-61 warning) and skips naabu entirely when nothing remains. Generic clouds (AWS/GCP/Azure) deliberately excluded. Annotation is host-grain (HostFact note), not per-EndpointFact. Not lab-validatable (loopback targets have no ASN); `cdnasn_test.go` is the coverage.

**Still open in this step:**
- **LT-89 (Step A) ✅ done 2026-09-08** (pulled forward for the crAPI demo). `recon --openapi-spec <file|url>` (repeatable, also on `plan`, ± `--recon-file`) → `recon.IngestOpenAPISpecs` reads/GETs the doc, walks it with `walkOpenAPISpec`, rebases routes onto the ref/target host, scope-checks each `EndpointFact`, folds it into the `ReconResult`. `--auth-token` not added — `--header 'Authorization: Bearer …'` already reaches recon's probes + httpx/katana. Read-only. Extends LT-40. Detail in [follow-up.md](follow-up.md) § "Live Testing — crAPI actionable-findings prep".
- **LT-90 (Step D) ✅ done 2026-09-08** (pulled forward for the crAPI demo). `walkOpenAPISpec` reads OpenAPI `security` (doc default, per-operation override, `security: []` opt-out) → `EndpointFact.AuthRequired` (schema v1.8, additive). `SuggestAuthBypassPathsFromRecon` adds a parameterless auth-required `api-spec` route to `protected` (capped 30); `resolveEndpointFacts` emits the endpoint-driven `authbypass` leaf and `checkMissingAuth` fires it tokenless. Spec-only, same lineage as LT-40/LT-50/P1-1.
- **LT-91 (Step C) ✅ done 2026-09-08** (surfaced by the Step B crAPI live round). `registry.resolveEndpointFacts` fans out **one `idor` leaf per `SuggestIDOREndpointCandidates` candidate** (`PlanNode.EndpointTemplate`, new additive field; capped `maxEndpointDrivenIdorLeaves` 12; bare tech-capability idor leaf dropped when any fanned leaf exists), so a multi-`{{id}}` spec no longer collapses to one "ambiguous" field miss that drops idor without an LLM key. `planexec.runLeaf` copies the per-leaf template into a blank config pre-dispatch (no LLM, no SeedFn); MCP/CLI field-suggestion passes suppress the now-moot idor escalation. Detail in [follow-up.md](follow-up.md) § "Step B — crAPI live round 1".
- **LT-93 (Step E) ✅ done 2026-09-08** (demo-blocking; surfaced by the Step E full-pipeline run). Decision-engine leaves carried a **bare hostname** as `Target`; the executor hands that to `scanner.Engine` as the request base, so `idor`/`authbypass`/`ssrf` built `"127.0.0.1/path"` (no scheme/port) and every request failed — the plan→execute path had never actually worked against a real host. `Resolve` now rewrites each dispatchable leaf's `Target` to the observed `scheme://host[:port]` (`reconHostBaseURL`: probed endpoint URL → `result.Target`/`APISpec.URL` → port heuristic → `https://` fallback); structural node IDs stay bare. Detail in [follow-up.md](follow-up.md) § "Step E — crAPI live round 2".
- **LT-94 (Step E) ✅ done 2026-09-08.** `planexec.RunPlan` relied on the caller to pre-fill `baseCfg.ProtectedPaths`/`SSRFParams` from recon — the MCP `plan` tool does, the webui `executePlan` (Plan Preview → Approve) path does **not**, so its endpoint-driven `authbypass`/`ssrf` leaves were skipped. Symmetric with LT-91: `resolveEndpointFacts` stashes the derived paths/params on the leaf (`PlanNode.ProtectedPaths`/`SSRFParams`, additive), `planexec.applyLeafReconFields` fills a blank config pre-dispatch, and `dropBareCapabilityLeavesSupersededByEndpointDriven` removes the bare tech-capability leaf. Detail in [follow-up.md](follow-up.md) § "Step E".
- Bounded content-discovery + embedded wordlist (`--content-discovery` — needs a vetted ~4-5k list with documented provenance/licence).
- **LT-63** CT-log sibling-API discovery.
- **LT-99 — opt-in headless / JS-rendered katana. ✅ done 2026-09-09** (branch
  `feat-lt99-headless-crawl`). `--headless-crawl` on `recon`/`plan` (effective at
  `--recon-depth full` only) → `runKatana` runs `-headless -no-sandbox
  -xhr-extraction` under `DefaultHeadlessCrawlTimeout` (180s / env / larger
  `--wave-timeout`), passing `-system-chrome-path` when a local or Playwright
  Chrome resolves (else katana self-provisions, logged). Replaces the link-crawl
  pass (not a second crawler); hits tagged `katana-headless`. Does **not** relax
  the `headless:` template-rejection rule. Re-measured against crAPI's `:8888`
  React shell: 4 → 7 endpoints, incl. the real `/chatbot/genai/state` `fetch()`
  call (the 4-vs-40 was OpenAPI-spec-wide, not one shell's JS). webui/mcp
  toggle deferred — detail in [follow-up.md](follow-up.md) § LT-99. Supersedes
  LT-8's open tail.
- **LT-100 — first-party hidden-parameter mining. ✅ done 2026-09-09** (branch
  `feat-lt100-param-mining`). `--param-mining` on `recon`/`plan` (DepthFull
  only), `--param-mining-wordlist` / `--param-mining-request-cap` overrides.
  `pkg/recon/parammine.go`: mines the top 6 ranked GET endpoints through the
  rate-limited `r.client`, hard-capped at 160 requests/run. Per endpoint: 2
  control requests set a baseline (+ `statusNoisy`/`lenNoisy` flags that
  disable those signals on a too-dynamic endpoint), then batches of 24 names
  ride one request each with a unique marker value. **Gate (≥2 signals, same
  param):** `reflect` + `nameEcho` pinpoint; `status-class change` /
  significant `length shift` (>64 B & >5%) count only when exactly one param in
  the batch was pinpointed. **FP guards:** reflect-all sinks (>8 markers/batch,
  baseline reflecting an unsent marker, or >6 corroborated) dropped whole;
  binary-search narrowing dropped (a status/length-only isolate is 1 signal,
  which the gate rejects anyway). `pkg/recon/wordlists/params.txt` (`go:embed`,
  ~239 names, provenance header cites the public Arjun / SecLists lists). Hits →
  `EndpointFact{Source: "wave3-param-mining", URL: "path?key=<v>"}` — `<v>=1`
  for id-shaped keys → `idShapedQueryCandidate` → IDOR; else value-less →
  `SuggestSSRFParamsFromRecon` on a keyword match. webui/mcp toggle deferred
  (same reasoning as LT-99). **Live:** crAPI 478 decoy probes → 0 emitted (FP
  0%); Juice Shop → 4 real undocumented params (`sort`/`scope` on the auto-REST
  `/api/Challenges/` + `/api/Quantitys/`), 72 requests within cap. Detail in
  [follow-up.md](follow-up.md) § LT-100. Its *active* consumption — feeding the
  native `sqli`/`xss`/`lfi` probes — is [Phase 9](18-implementation-plan-ph9.md)
  Step 4, sequenced after.
- **LT-40 tail (b)/(c) ✅ done 2026-09-07** (with the Phase 7 Step 6a batch): the spec-probe path set now also covers `/openapi.json`, `/v3/api-docs`, `/v2/api-docs`, `/api-docs`, `/swagger/v1/swagger.json` (`commonPaths`/`specPaths` in crawl.go), and `walkOpenAPISpec` normalises a YAML body to JSON up front (`specBodyToJSON`: `yaml.Unmarshal`→`json.Marshal`) and walks it on the same path as JSON. Both stay under the existing LT-30 canary/content-type gate. GraphQL SDL/introspection (a) — needs a POST introspection query — stays deferred.

### Design

[follow-up.md](follow-up.md) LT-8: katana is hardcoded to `-depth 2`, no
JS-rendering/headless mode, no flag for either — plausibly why the endpoint-driven
idor/ssrf heuristics find nothing on real targets with a live login boundary. All
three sub-items below widen the same Wave 3 endpoint set that `resolveEndpointFacts`
(P1-1) turns into idor/authbypass/ssrf/businesslogic candidates.

- **Configurable crawl depth** — a `--recon-depth`-adjacent knob (or a dedicated
  `--crawl-depth`) threaded into `runKatana`'s `-depth`, defaulting to today's `2` so
  scripted runs are unchanged.
- **Bounded content discovery** — active probing of a small curated wordlist of common
  *unlinked* paths (admin panels, backup files, `/.git/`-style dir indexes, config
  endpoints) against each Wave 3 live host, for the surface a link-following crawl by
  definition can't reach. Distinct from `probeCommonPaths`' fixed 6-entry app-shape
  list and from misconfig's exposed-path checks (bad *exposure*, not *discovery*).
  Constrained so it stays inside the read/enumerate-only boundary and the
  DoS/brute-force exclusion nearly every program carries
  ([05-hackerone-and-legal.md](05-hackerone-and-legal.md) §2,
  [21-scanning-real-targets.md](21-scanning-real-targets.md)):
  - **Opt-in only**, behind an explicit flag (`--content-discovery`), and only at
    `--recon-depth full`. Never in a default or scripted run.
  - Runs through **`httpx`'s own `-path <file>` input** — httpx is already the Wave 2/3
    shelled binary and already honors `-rl`/`-threads`, so request volume rides the
    same per-tool rate limit every other recon binary uses. This is the specific
    reconciliation-with-the-rate-limiter that [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md)
    named as ffuf's blocker — sidestepped by not adding a second traffic-generating tool.
  - **Curated default wordlist** (~4-5k entries, seclists `common.txt`-scale),
    `go:embed`-ed with its provenance/licence documented. A larger list is available
    only via an explicit `--content-discovery-wordlist <path>` override — the operator's
    stated choice and risk, not a default.
  - Still `--scope`-gated (only Wave 1's scope-filtered hosts). Hits fold into the Wave 3
    endpoint set as `EndpointFact{Source: "wave3-content-discovery"}`, deduped like any
    other source.
- **Optional JS-rendered crawl (LT-99, 6c tranche)** — katana's own headless mode
  (`-headless`/`-system-chrome`), behind an explicit `--headless-crawl` flag, with a
  per-host timeout ceiling (the real cost LT-8 names — headless across many hosts is
  slow). Off by default; when on, its output merges into the same Wave 3 endpoint set,
  deduped like any other source. Pairs naturally with Step 3's JS static analysis — a
  rendered DOM surfaces dynamically-built endpoints a static bundle scan can't. The
  full scheduled write-up, with the crAPI Step E yield measurement (4 vs. 40
  endpoints), is in the "Still open in this step / LT-99" bullet above.
- **First-party hidden-parameter mining (LT-100, 6c tranche)** — a curated
  candidate-name list + a corroboration-gated response-diff oracle over the existing
  rate-limited `httpclient`, behind `--param-mining`, `--recon-depth full` only, with
  a hard per-run request cap shared across every target. Finds parameters the app honours but never advertises
  (reflected-XSS / LFI / SSRF / IDOR surface). Distinct from ffuf-as-a-tool (still
  out of scope) — targeted enumeration bounded like content discovery, not generic
  multi-position fuzzing. Full scheduled write-up in the "Still open in this step /
  LT-100" bullet above.
- **Parse a reachable OpenAPI/GraphQL spec into endpoints + parameters**
  ([follow-up.md](follow-up.md) LT-40). `recon.APISpecFact` is "presence only, never
  parsed" (`pkg/recon/types.go`) — on a target where `/swagger.json` is *real* the
  engine dispatches `swagger-api` detection but never enumerates the spec's own
  paths/params, so idor/authbypass/ssrf leaves still have nothing to work with. When
  `APISpecFact.Kind == openapi` and the body is genuine JSON/YAML (gated by LT-30's
  canary/content-type check — a SPA catch-all must not reach here), walk `paths` and
  `parameters` into `EndpointFact{Source: "api-spec"}`: an ID-shaped path/query param
  becomes an idor candidate, a URL-shaped one an ssrf candidate, feeding
  `resolveEndpointFacts` like any other observed endpoint. This is the richest
  endpoint+parameter source recon can have and today it is discarded — highest single
  "find more vulns" item in this step. **Pull forward into an earlier batch if a live
  engagement target exposes a real spec.**
- **Cross-correlate Wave 2 tech facts with Wave 3 endpoints for dispatch**
  ([follow-up.md](follow-up.md) LT-50, report item "S-d"). `decisionengine.go`'s
  `correlatedEndpoints` folds endpoints into an *unresolved* leaf's rationale prose
  only — never to raise a match's Confidence or add a targeted leaf. When a product's
  known endpoint signature (e.g. `Jira` + `/secure/Dashboard.jspa`, `GitLab` +
  `/-/health`) is observed on the same host as its tech fact, `resolveTechFact` should
  upgrade the leaf or emit a targeted one. Needs a small per-product
  endpoint-signature table; shares the "turn recon signal into leaves" lineage of
  Phase 6's P1 items.

- **Consume the CDN-ASN fact recon already collects** ([follow-up.md](follow-up.md)
  LT-61). Recon's WHOIS/ASN pass records the host's ASN (e.g. `asn: 20940` = Akamai on
  `www.valmo.in`) in a host note, but nothing downstream reads it: naabu still spent its
  full 60 s wave cap SYN-scanning a CDN edge IP that can carry no origin service. A small
  known-CDN-ASN table (Akamai 20940/16625/…, Cloudflare 13335, Fastly 54113, …): when
  *every* resolved address for a host is in one, skip or sharply shorten the port scan
  and annotate its `EndpointFact`s "CDN edge, not origin" so the plan/report doesn't
  imply origin coverage. Same "turn recon signal into a decision" lineage as LT-50.
- **Companion mobile-app API discovery** ([follow-up.md](follow-up.md) LT-63). A scope
  entry with a documented mobile app (`.engagements/meesho/policy.md`: "Valmo Mobile
  App", test MSISDNs) gets no API-host discovery — recon only pivots via DNS/crawl/ports
  off the given *web* host, so when that host is WAF-walled (LT-57/LT-62) there is
  nowhere left to look even though the app's API is the real surface. A passive,
  `--scope`-checked pass: reuse **subfinder's existing `crtsh` CT-log source** (no new
  dependency) to enumerate `api.`/`gw.`/`mobile.`/`edge.` siblings of the scope host,
  and probe whether an already-in-scope API host (`prod.meeshoapi.com`) answers the
  app's conventional paths. Only surfaces hosts that pass the scope check — never widens
  scope, matching LT-35/LT-52's discipline.
- **Probe high-interest low-confidence robots/sitemap endpoints**
  ([follow-up.md](follow-up.md) LT-76). `resolveEndpointFacts` (P1-1) only reasons over
  endpoints carrying an *observed* status, so the ~100 paths recon lifts from
  `robots.txt` / `sitemap.xml` without probing (`shop.app`, 2026-09-07:
  `/oauth/authorize`, `/oauth/continue`, `/accounts/bounce`, `/pay/*`, `/u/*`,
  `/delete-account/confirm`, `/checkouts/internal`, …) drive no leaves at all — the plan
  had one `businesslogic` leaf off `/cart` against a 110-endpoint recon. Before
  resolution, probe a bounded sample (~20) of the highest-interest names — ranked by
  shape (`/oauth/*`, `*/bounce`, `*/callback`, `/pay/*`, `/u/*`, `*/logout`) — for a live
  status, so a name-suggestive endpoint can seed `authbypass` / `ssrf` / redirect leaves.
  Rides the same per-tool rate limit and `--scope` gate as the curated content-discovery
  pass above; distinct in that the paths come from the target's own robots/sitemap, not
  an embedded wordlist, so it needs no wordlist-provenance handling and is not gated
  behind `--content-discovery` (it's bounded by the endpoint set recon already holds).
- **Redirect / OAuth-flow probe rule for bounce-shaped endpoints**
  ([follow-up.md](follow-up.md) LT-77). `/accounts/bounce` 302s to `/account`;
  `/oauth/authorize` + `/oauth/continue` are textbook `redirect_uri` / `return_to`
  open-redirect and OAuth-flow candidates, but `decisionengine.go` has no rule mapping a
  `*/bounce` / `/oauth/authorize` / `/sso` / `*/logout`-shaped path to a
  redirect-parameter probe. Add an endpoint-name → probe rule that fuzzes
  `url,return_to,redirect_uri,redirect,next,continue,RelayState,checkout_url` against
  such paths and flags an off-origin `Location`; reuse the existing `redirect` template
  tag for the corpus side. Consumes LT-76's newly-probed endpoints — sequence it after
  that bullet. Read-only: a single benign off-origin marker value per param, no payload
  beyond the redirect target.
- **Redirect-chain fidelity + per-host fact attribution**
  ([follow-up.md](follow-up.md) LT-64 / LT-65, with LT-84). `pkg/recon` follows a
  cross-host redirect and records the *destination's* response (status, title, body_len,
  tech) as the in-scope target's — `linkpop.com` got `www.shopify.com`'s 200 + a
  `Shopify` fact that then seeded an 8-leaf template class and widened the scan corpus.
  Three coupled changes: (1) record `redirect_chain` / `final_url` on the `EndpointFact`,
  keep `status_code` as the first hop, and warn + add a plan note when `final_url`'s host
  is outside `--scope`; (2) tag every `TechFact` with the host/URL it was *observed* on,
  and in `resolveTechFact` drop (or ConfidenceLow + "seen on redirect target") a fact
  whose observed host ≠ the target host; (3) the same host-attribution guard covers
  LT-84 — a `Cloudflare` / CDN fact not present in the host's *own* response headers is
  not attributed to it. (LT-84's `cdnjs`/`jsdelivr`/`unpkg`/`google hosted libraries` →
  `nonActionableTech` half is a do-now item, not this step.)
- **Numeric-query-parameter ID candidates** ([follow-up.md](follow-up.md) LT-83).
  `SuggestIDOREndpointCandidates` inspects only *path* segments, so a query-routed CMS
  (`?article=3..13`, `?topic=1..2` — `sandbox-royal.securegateway.com`, 2026-09-07) yields
  only a blind `/{{id}}` path guess even though the real IDOR/SQLi surface is right there
  in the crawled endpoint set. A query param whose observed value is a small integer and
  varies across ≥2 crawled URLs becomes an ID-shaped candidate → `/?article={{id}}`,
  feeding `resolveEndpointFacts` like any path candidate. Same "turn a discovered
  endpoint/param into a real candidate" lineage as LT-40/LT-50/LT-76; realises value once
  auth is available for `idor` or the [Phase 9](18-implementation-plan-ph9.md) Step 4 native injection detector exists.
- **Per-path-timeout vs host-down circuit-breaker** ([follow-up.md](follow-up.md) LT-86).
  Recon's repeated-error breaker (LT-4) abandons a host when a few Wave-3 paths time out —
  `sandbox.securegateway.com` served `GET /` and `/robots.txt` fine but tarpits
  `.well-known/*`, and the final result was `0 endpoints, 0 tech`. A timed-out path
  counts toward a per-path skip, not the host-down tally; the host-down verdict needs
  connection-level failures (refused / DNS / TLS), not response tarpits. (The companion
  fix — *retain* a Wave-2 `200` root even when the breaker does trip — is a do-now item.)

No new dependency — katana already ships headless support and httpx already accepts a
path list, an OpenAPI/GraphQL document is JSON/YAML the stdlib already parses, and
subfinder already carries a CT-log source; this is flag plumbing, an embedded wordlist,
a spec walker, a known-CDN-ASN table, a timeout guard, and (LT-76/LT-77) a bounded
endpoint probe reusing the existing recon HTTP client plus a redirect-parameter rule
over the `redirect` corpus tag. LT-99's headless crawl is a `runKatana` arg + a
per-host deadline; LT-100's param mining is a `go:embed`-ed candidate list + a
diff-oracle loop over the same rate-limited `httpclient` every other recon probe uses —
neither adds a dependency.

### Files (anticipated, confirm at implementation time)
- `pkg/recon/crawl.go` — `runKatana` takes depth + a headless bool + per-host timeout; a new `discoverContentPaths` shelling `httpx -path <wordlist>`, gated on the opt-in flag, folding hits into `agg` as `wave3-content-discovery` endpoints.
- `pkg/recon/endpointprobe.go` (new) — LT-76's bounded, name-ranked probe of unprobed `robots.txt`/`sitemap.xml` endpoints (reusing `recon`'s own HTTP client + rate limiter), folding a live status onto the existing `EndpointFact` so `resolveEndpointFacts` treats it like any observed endpoint.
- `pkg/recon/apispec.go` (new) — LT-40's OpenAPI/GraphQL document walker: `paths`/`parameters` → `EndpointFact{Source: "api-spec"}` with an ID-shaped/URL-shaped param classification; only invoked when LT-30's canary+content-type gate says the spec body is real.
- `pkg/registry/decisionengine.go` — LT-50's tech×endpoint correlation in `resolveTechFact` (per-product endpoint-signature table, Confidence upgrade / targeted-leaf emission); LT-77's endpoint-name → redirect-parameter-probe rule (`*/bounce`, `/oauth/authorize`, `/sso`, `*/logout` shapes → a `redirect`-tagged leaf); LT-65/LT-84 per-host fact-attribution guard in `resolveTechFact` (drop / ConfidenceLow a fact whose observed host ≠ the target host).
- `pkg/detectors/` — LT-77's off-origin `Location` check: extend the `ssrf` detector's redirect handling, or a thin `openredirect` rule, dispatched only from the LT-77 decision-engine rule.
- `pkg/recon/{crawl,types}.go`, `docs/schema/recon-result.schema.json` — LT-64's `redirect_chain` / `final_url` on `EndpointFact` + the off-scope-redirect warning/plan-note; LT-65's per-`TechFact` observed-host tag; LT-83's numeric-query-param candidate in `SuggestIDOREndpointCandidates`; LT-86's per-path-timeout accounting in the Wave-3 error-breaker.
- `pkg/recon/asn.go` (or the existing WHOIS/ASN file) — LT-61's known-CDN-ASN table + the "all resolved addrs in a CDN ASN ⇒ skip/shorten naabu, tag endpoints" gate in the Wave 2 port-scan path.
- `pkg/recon/passive.go` / `crawl.go` — LT-63's CT-log sibling-API pass (subfinder `crtsh` source, `api.`/`gw.`/`mobile.` labels), scope-checked, `--recon-depth full` only.
- `pkg/recon/wordlists/common.txt` (new, `go:embed`) — the curated default content-discovery list; header comment records its source and licence.
- `pkg/recon/crawl.go` — **LT-99**: `runKatana` gains a headless bool + a per-host `context.WithTimeout`; headless katana args (`-headless -no-incognito` / `-system-chrome`) added only when the flag is set; hits fold in as `wave3-headless-crawl` (or merge into the existing katana source), deduped.
- `pkg/recon/parammine.go` (new) — **LT-100**: the candidate-name diff-oracle pass — many-per-request batching, binary-search narrowing, the ≥2-signal corroboration gate, the per-run request cap shared across every target; emits `EndpointFact{Source: "wave3-param-mining"}` with the discovered key keyless on the URL.
- `pkg/recon/wordlists/params.txt` (new, `go:embed`) — the curated default hidden-parameter candidate list (hundreds of high-signal names); header comment records provenance/licence; `--param-mining-wordlist` overrides.
- `pkg/recon/recon.go` — `ClientConfig`/`Option`s for the new knobs (crawl depth, headless, content-discovery on/off + wordlist override, param-mining on/off + wordlist override + request cap).
- `cmd/hackerfive/{recon,plan}.go`, `pkg/webui/handlers_launch.go`, `pkg/mcpserver/tools_recon.go` — surface the flags/fields (`--headless-crawl`, `--param-mining`, `--param-mining-wordlist`).
- `tests/unit/crawl_test.go` — depth threaded through to the katana arg list; headless flag gated correctly (LT-99); `httpx -path` present only when `--content-discovery` is set; a hit becomes a `wave3-content-discovery` `EndpointFact` and reaches `resolveEndpointFacts`.
- `tests/unit/parammine_test.go` (new) — **LT-100**: a fixture endpoint that reflects an undocumented `?debug=` yields exactly one discovered-param `EndpointFact`; one that reflects nothing yields none; a single weak signal (length shift only) is not enough; the per-run request cap shared across every target is honoured; the discovered param reaches `SuggestSSRFParamsFromRecon` / `SuggestIDOREndpointCandidates`.

### Verification
Unit: the katana arg list reflects the configured depth/headless; the httpx arg list
carries `-path` only with the flag on. LT-76: a recon fixture with unprobed
`robots.txt` endpoints probes only the bounded name-ranked sample, and a probed
`/oauth/authorize` reaching a live status produces an `authbypass`/redirect leaf that a
bare listing did not. LT-77: a fixture `/accounts/bounce?url=<off-origin>` that honours
the param yields an open-redirect finding; one that ignores it yields none. LT-64/LT-65:
a recon fixture whose in-scope root 301s cross-host records `final_url` + a
"redirects out of scope" warning, and the destination's tech fact does not seed the
original target's plan. LT-83: a fixture with `?article=8` / `?article=12` crawled
yields an `/?article={{id}}` idor candidate, not `/{{id}}`. LT-86: a fixture host that
serves `/` but times out on `/.well-known/*` keeps its root endpoint in the result.
**LT-99:** the katana arg list carries the headless flags only with `--headless-crawl`
set, and a per-host deadline is applied; a fixture SPA served via a headless-capable
stub yields a `fetch()`-built endpoint the non-headless pass misses. **LT-100:** a
fixture endpoint that reflects an undocumented `?debug=` value yields exactly one
discovered-param `EndpointFact` reaching `SuggestSSRFParamsFromRecon` /
`SuggestIDOREndpointCandidates`; one that reflects nothing, or shifts only length,
yields none; the per-host request cap halts the pass.
Live: a depth-3 + `--headless-crawl` run against a JS-heavy owned SPA yields
materially more endpoints than the depth-2 static run (target the crAPI-class gap —
re-measure the 4-vs-40 number on an owned SPA); a `--content-discovery` run against an
owned target with a known unlinked path (e.g. `/admin`, a dir index) discovers it only
with the flag on; a `--param-mining` run against an owned endpoint with a known
undocumented parameter surfaces it within the request cap; and the extra endpoints —
from all sources — reach the plan tree's idor/authbypass candidate lists.

---

## Step 7: Remaining Template-Format Gaps — → RESCHEDULED to [Phase 9](18-implementation-plan-ph9.md) Step 2 (2026-09-07)

> **Moved to [Phase 9](18-implementation-plan-ph9.md).** The forward plan and DoD now
> live there (including the two dependency-footprint gates); this body is retained for
> provenance and is unchanged from the original Phase 8 draft.

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
  plumbing this builds on), and descopable with a stated reason if the week runs short —
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

## Step 8: AI-Agent Surface Modeling — → RESCHEDULED to [Phase 9](18-implementation-plan-ph9.md) Step 3 (2026-09-07) — closes LT-78

> **Moved to [Phase 9](18-implementation-plan-ph9.md).** The forward plan and DoD now
> live there; this body is retained for provenance and is unchanged from the original
> Phase 8 draft.

### Design

[follow-up.md](follow-up.md) LT-78, live-observed on `shop.app` (2026-09-07): the host
publishes an agent skill manifest (`/llms.txt` → `/SKILL.md`: "search the catalog, build
a checkout on the merchant's domain, handle orders") and a live `shop-mcp` endpoint at
`/mcp/`. This is an emerging, largely-unscanned surface — prompt injection into agent
instructions, an unauthenticated MCP `tools/list`, agent-reachable state-changing tools,
checkout manipulation via the agent path — and HackerFive has neither a recon signal nor
a detector for it. Recon fetched none of it usefully on the live run (UA-blocked, then
429-drowned — this step depends on LT-75's browser-UA recon landing first).

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
never issued. Live: re-run against `shop.app` once LT-75's browser-UA recon lands and
confirm `/llms.txt`, `/SKILL.md`, `/mcp/` are recorded as an `AgentSurface` fact and the
enumeration runs read-only.

---

## Step 9: WAF-Aware Probing + Active Injection / Upload-Bypass Detectors — → RESCHEDULED to [Phase 9](18-implementation-plan-ph9.md) Step 4 (2026-09-07) — closes LT-87

> **Moved to [Phase 9](18-implementation-plan-ph9.md).** The forward plan and DoD now
> live there; this body is retained for provenance and is unchanged from the original
> Phase 8 draft. Sequenced last in Phase 9 — the native injection detectors want the
> param surface Phase 8 Steps 3 + 6 produce.

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
by the D6 verdict besides). This step is the one place Phase 8 adds active
vulnerability-class detectors rather than protocol/recon breadth.

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
need pinning. Descopable sub-item by sub-item with a stated reason if Week 64 runs short;
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

## Step 10: Eval Maturity + Release (Week 64) — ⬜ not yet implemented — `v0.8.0`

### Design

Re-run the fixed eval challenge set (Phase 5's harness, Phase 7's agent-driven
extension) against the lab targets with every new detector from **Steps 1, 2, 3**
(and Step 5's gating, Step 6's crawl) enabled, and record the delta: new true
positives found, and — held to the same "revise down with reasoning, don't pad"
discipline — any new false-positive mode the new detectors introduced, tracked
against the <5% target. Full cost accounting per run as in Phase 7 Step 7. Then full
integration testing across the Phase 5-8 stack, and release.

`v0.8.0` is cut when the Phase 8 (Tier-2) batch is coherent and green — it does
**not** wait on Phase 9's depth/active work, which ships under `v0.9.0`.

### Files (anticipated, confirm at implementation time)
- `tests/eval/` — the new detectors added to the challenge matrix.
- `docs/03-development-roadmap.md` / `docs/follow-up.md` — Detection Coverage table rows moved from "Add" to "✅ shipped" with the measured yield.

### Verification
The eval runs against all lab targets with the new detectors on; the fp/fn numbers and
their delta from the Phase 7 baseline are recorded honestly — met, or not met with a
stated reason.

## Definition of Done (Phase 8, Weeks 57-64)

Covers the **retained** Phase 8 steps (1, 2, 3, 5, 6, 10). The OOB blind-RCE,
template-format, AI-agent-surface, and WAF/injection DoD lines moved to
[18-implementation-plan-ph9.md](18-implementation-plan-ph9.md)'s Definition of Done.

- [ ] `tcp:` templates load and run (bounded connect/probe/banner-match); a `code:`-carrying `tcp:` block still rejected
- [ ] A `netservice` detector reports anonymous-FTP / unauthenticated-DB / open-Elasticsearch exposure, read-only, `--scope`-gated; `resolvePortFacts` dispatches it instead of only emitting `StatusUnresolved`
- [ ] A `tls` detector reports expired/weak/mismatched certs, sub-1.2 protocols, and weak ciphers, via stdlib `crypto/tls`, no new dependency
- [ ] Served-JS static analysis folds extracted endpoints into `ReconResult.Endpoints` (`Source: "js-static"`) and reports high-signal hardcoded secrets as `misconfig` findings, with its decoy-set false-positive rate measured
- [ ] Cloud-provider exposure facts (`aws`/`s3`/`gcp`) are extracted from headers / URL shapes and dispatch the corpus's cloud-exposure templates (P1-5 closed)
- [ ] `templates/index.json` carries optional `AffectedRange` data; `matchTemplateTags` drops an out-of-affected-range CVE template when the `TechFact` version is known, and real multi-version Nginx hosts get different template lists (LT-7 closed)
- [ ] An unversioned WordPress plugin/theme slug gets a `readme.txt`/`style.css` version probe (P1-3 leftover closed)
- [x] Crawl depth is configurable (default unchanged) — 2026-09-07, first tranche
- [x] **LT-99 (6c):** an opt-in JS-rendered crawl (`--headless-crawl`, `--recon-depth full` only) runs Wave 3's katana in real-browser headless mode under a larger timeout ceiling (`DefaultHeadlessCrawlTimeout` 180s / `HACKERFIVE_RECON_HEADLESS_TIMEOUT`), recovering `fetch()`/XHR endpoints the link crawl misses; hits tagged `katana-headless`. Supersedes LT-8's open tail — **done 2026-09-09** (branch `feat-lt99-headless-crawl`). CLI (`recon`/`plan`) + `recon.WithHeadlessCrawl`; `-headless -no-sandbox -xhr-extraction`, `-system-chrome-path` when a local/Playwright Chrome resolves (else katana self-provisions with a logged one-time-download warning). Re-measured against crAPI's `:8888` React shell: 4 endpoints link-crawled → 7 headless, incl. the real `/chatbot/genai/state` fetch call (the doc's 4-vs-40 was OpenAPI-spec-wide; a headless crawl of one shell recovers what that shell's JS calls). `looksLikeEscapedJSArtifact` widened to drop mis-parsed inline-`<script>` fragments the headless pass surfaces. webui/mcp surface deferred (neither wires `--crawl-depth` today either — see follow-up.md LT-99)
- [ ] An opt-in (`--recon-depth full` only) bounded content-discovery pass probes a curated embedded wordlist via `httpx -path`, `--scope`-gated, and its hits reach `resolveEndpointFacts` as `wave3-content-discovery` endpoints
- [x] **LT-100 (6c):** an opt-in (`--param-mining`, `--recon-depth full` only) hidden-parameter pass over the rate-limited `r.client` — `go:embed` candidate list (`wordlists/params.txt`), 24-name batches, ≥2-signal corroboration gate, reflect-all sink suppression, hard 160-request/run cap — emits a discovered undocumented parameter as a `wave3-param-mining` `EndpointFact` that reaches `SuggestSSRFParamsFromRecon` / `SuggestIDOREndpointCandidates` — **done 2026-09-09** (branch `feat-lt100-param-mining`). Decoy FP rate measured live: crAPI 478 probes → 0 emitted (0%); Juice Shop → 4 real params. webui/mcp toggle deferred
- [x] A bounded, name-ranked sample of unprobed `robots.txt`/`sitemap.xml` endpoints is probed for status and reaches `resolveEndpointFacts`, so `/oauth/*`, `*/bounce`, `/pay/*` can seed `authbypass`/`ssrf`/redirect leaves (LT-76 closed) — 2026-09-07, first tranche
- [x] An endpoint-name → redirect-parameter-probe rule flags a `*/bounce` / OAuth / SSO / logout-shaped path into the `redirect`-tagged corpus check (LT-77 partial, first tranche); a first-party per-param off-origin-`Location` probe is [Phase 9](18-implementation-plan-ph9.md) Step 4
- [x] Recon records `redirect_chain` / `final_url` and warns when an in-scope root redirects out of scope; a `TechFact`'s observed host is tracked and a cross-host (post-redirect / CDN-not-in-own-headers) fact does not seed the target's plan (LT-64 / LT-65 / LT-84b closed) — 2026-09-07, first tranche
- [x] A numeric-valued query parameter that varies across crawled URLs becomes an `/?param={{id}}` ID candidate, not a blind `/{{id}}` (LT-83 closed) — 2026-09-07, first tranche
- [x] A Wave-3 path timeout counts toward a per-path skip, not the host-down breaker; a host serving `/` but tarpitting some paths keeps its endpoints/tech in the result (LT-86 closed) — 2026-09-07, first tranche
- [x] A reachable OpenAPI/Swagger doc (JSON or YAML, at any of the framework-convention paths) is walked into `api-spec` `EndpointFact`s that feed `resolveEndpointFacts` (LT-40) — JSON 2026-09-07 (second tranche, live-validated against crAPI); YAML bodies + widened spec-probe path set 2026-09-07 (Phase 7 Step 6a batch). Tail open: GraphQL SDL/introspection (a)
- [x] A host resolving into a known dedicated-CDN ASN is dropped from the naabu port scan with a `cdn-edge:` note (LT-61) — 2026-09-07, second tranche
- [ ] New-detector yield and any new false-positive mode measured against all lab targets, tracked against the <5% target, with full cost accounting
- [ ] `go build`/`go vet`/`go test -race`/`golangci-lint` all clean
- [ ] `v0.8.0` tagged and released, or explicitly held with a stated reason

## See also
- [18-implementation-plan-ph9.md](18-implementation-plan-ph9.md) — the depth/active half (OOB blind-RCE, template-format gaps, AI-agent surface, WAF + native injection detectors); the "Execution order" section above spans both
- [follow-up.md](follow-up.md) — the Detection Coverage table and Live-Testing (LT-7, LT-8, LT-23) findings this phase schedules
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) / [16-implementation-plan-ph7.md](16-implementation-plan-ph7.md) — the agent pipeline this phase's new detectors feed into, and whose stated scope boundaries kept detector expansion out until now
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — the `code:`/`javascript:`/`headless:`/`file:` template-rejection boundary Step 1 (and Phase 9 Step 2) work within
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — the read/enumerate-only rule every step here holds to
- [03-development-roadmap.md](03-development-roadmap.md) — full phase roadmap this plan extends
