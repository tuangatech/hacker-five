# Follow-Up: Enhancement Backlog

> Part of the [HackerFive documentation set](../README.md).

Open enhancement items and unresolved review findings, organized by category rather than by when they were raised. Direction: HackerFive is expanding beyond HackerOne-program scanning, so categories here stay useful for detection/reporting work generally. Narrative-style research and decision write-ups live in [discussions.md](discussions.md); this doc is the open-items backlog.

**Trimmed 2026-09-10** to cut re-read cost: every `✅ done` item below is compressed to 1-3 lines (symptom → fix, test pointer, phase-step pointer); every still-open item keeps full detail. **The original, unabridged write-up of every item — full reproduction steps, exact measurements, superseded designs — lives in [follow-up-archive.md](follow-up-archive.md).** When resolving an open item here, add its full write-up to the archive, then compress it here.

**`LT-N` items** form one continuous number sequence wherever they sit in this doc, currently through **LT-143** (LT-142/143 from Phase 8 Step 1's implementation, 2026-09-11: `netservice`'s remaining-port gap and `tcp:` extractors: being unwired). Full per-batch provenance (which live round produced which range) is in the archive's header. Next number: `grep -oE 'LT-[0-9]+' docs/follow-up.md docs/follow-up-archive.md | sort -t- -k2 -n | tail -1`. A fresh live round gets its own `## Live Testing — <targets> (<date>)` section that continues the count.

## Near-term batch — "do now" (raised across the 2026-09-07 linkpop / shop.app / ALSCO runs)

**✅ Landed 2026-09-07.** Twelve small correctness/anti-FP fixes, all clean on build/vet/test/lint:
- **Recon fidelity:** LT-80 (scope parser strips inline `#` comments), LT-81=LT-75 (recon's own client sends a desktop-browser UA by default), LT-82 (uniform-wall verdict suppressed when the host has ≥5 distinct endpoints spanning a real 404 among 2xx), LT-72/86a (wave-3 canary-probe failure falls back to the wave-2 httpx root), LT-68 (new `ReconResult.AppSurface` none/thin/full verdict), LT-84a (cdnjs/jsdelivr/unpkg/Google-hosted-libs → `nonActionableTech`), LT-85 (`IsPlausibleURLPath` rejects JS-syntax-punctuation candidates).
- **`misconfig` anti-FP:** LT-69+LT-73 (exposed-path/dir-listing skip 404/429/5xx; disallowed-method skip a 2xx/3xx matching a plain-GET baseline).
- **Engine robustness:** LT-74+LT-88 (adaptive rate-halving → target-abort on sustained 429/503 or a mid-run connect-failure spike, `pkg/scanner/adaptive.go`), LT-79 (`--max-target-duration`, default 15m), LT-70 (an unresolved/dead-end leaf sorts below every dispatchable leaf).

**Routed to a phase step instead:** LT-64/65/83/84b/86b/76/77 → Phase 8 Step 5 (✅ done 2026-09-07) · LT-40/61 → Phase 8 Step 5 (✅ done 2026-09-07) · LT-78 → [Phase 9](18-implementation-plan-ph9.md) Step 3 · LT-87 → [Phase 9](18-implementation-plan-ph9.md) Step 4 · LT-67/71 → [Phase 7](16-implementation-plan-ph7.md) Step 5 (✅ done; renumbered 2026-09-10 from "Step 6a") · LT-107/108 → [Phase 7](16-implementation-plan-ph7.md) Step 7 (✅ both done 2026-09-10; renumbered from "Step 8"; LT-109/110 are its still-unscheduled rungs 3-5) · LT-89/90/91/93/94 → Phase 8 Step 5 (✅ all done 2026-09-08, pulled forward for the crAPI demo). LT-92/95/96 ✅ done 2026-09-09 too — detector-precision fixes, filed as an ad-hoc batch rather than folded into Step 5. (Phase 8's own Steps renumbered 2026-09-11 — old Step 5→4, Step 6→5, Step 10→6, per Step 1's netservice work; Steps 4/7/8/9 were fully removed from doc17, their bodies already duplicated in [Phase 9](18-implementation-plan-ph9.md).)

## Security & Scope Hardening

Resolved, kept for traceability:
- ✅ Scope allow-list, evidence redaction, IDOR normalization, JWT weak-secret check, rate-limit-signal probe, Business Logic Flaw detector (`--allow-writes`-gated) — doc10/11/13.
- ✅ OOB default: 2 public interactsh servers, `--no-oob` opt-out (2026-09-02).
- ✅ `--rate-limit` default 50 → 10 req/s (2026-09-05).
- ✅ OOB `Poller` idle-skips its network poll when nobody's waiting (2026-09-05).
- ✅ `Retry-After`-aware HTTP backoff, `max(exponential, Retry-After)`, 30s ceiling (2026-09-05, Phase 6 Step 3).

(Baseline-mode account-provisioning guidance and a self-hosted `interactsh-server` moved to [Parked](#parked--revisit-on-a-trigger-or-after-an-eval) — both engagement-triggered, not code work.)

## Detection Coverage — Protocol/Capability Expansion

Scheduled 2026-09-05 as Phase 8, split 2026-09-07 into breadth/precision ([Phase 8](17-implementation-plan-ph8.md): TCP banner-grab Step 1 ✅ done 2026-09-11, TLS passive checks Step 2, JS static analysis Step 3 ✅, semver gating Step 4, richer crawl Step 5) and depth/active ([Phase 9](18-implementation-plan-ph9.md): OOB blind-RCE Step 1, template-format gaps Step 2, AI-agent surface Step 3, WAF-aware + injection detectors Step 4). Phases 6/7 explicitly scope detector/vuln-class expansion out. A large-wordlist sweep or ffuf-style fuzzing stays a separate opt-in-only item (Phase 8 Step 5's out-of-scope note, reaffirmed 2026-09-08 — see Parked).

## Template Engine & Detection Backlog

| Item | Status |
|---|---|
| `xpath` matcher/extractor; `flow:` cross-block `_N` indexing | [Phase 9](18-implementation-plan-ph9.md) Step 2 |
| `substr()` / `date_time()` / `generate_jwt` DSL functions | [Phase 9](18-implementation-plan-ph9.md) Step 2 |
| `flow:` `if`/`set`/`for`/`let`/`var` constructs (~42 templates) | [Phase 9](18-implementation-plan-ph9.md) Step 2 |
| Template signing | [Parked](#parked--revisit-on-a-trigger-or-after-an-eval) |
| DOM-based XSS via Chromedp | [Parked](#parked--revisit-on-a-trigger-or-after-an-eval) |
| **LT-142 ✅ mostly done 2026-09-11** — `netservice` now covers 5 of `interestingPorts`' 7 entries: 21/ftp, 3306/mysql, 6379/redis (Phase 8 Step 1) plus 5432/postgresql (trust-auth `StartupMessage`) and 27017/mongodb (unauthenticated `listDatabases` over OP_MSG — deliberately not `hello`/`isMaster`, which always succeeds pre-auth by design and would false-positive on every secured server) added this batch. **Still open:** 23/telnet and 9200/elasticsearch stay `StatusUnresolved`-only — telnet names no specific check beyond "the port is open", and Elasticsearch's real exposure check is arguably HTTP (`GET /` unauthenticated on 9200), not `tcp:`/netservice, and would want its own recon Wave-2 pass; a separate, unbuilt item, not scheduled. Also still unre-verified: LT-23's original evidence target (`staging.andertone.com`, owned) hasn't been re-scanned against the new `netservice` detector yet — do that before calling LT-23 fully closed in practice, not just in code. |
| **LT-143 (open)** — a `tcp:` template's `extractors:` block is accepted by the (lenient, non-`KnownFields`) YAML decoder but silently does nothing (`TCPRequest` has no `Extractors` field — see schema.go's doc comment): no consumer exists yet since `tcp:` requests support no `flow:`/chaining. Low priority — no real corpus tcp: template sampled at implementation time needed it. |
| Real synced-corpus `tcp:` templates (upstream's `network/` category) aren't in the committed `templates/index.json` yet | Operational, not code — `pkg/templatesync.List`'s own loader rejected every one before Step 1 lifted `tcp` out of `disallowedBlocks`; takes effect on the next corpus sync/re-index run. |

✅ Done 2026-09-05 (LT-22): `+` concat operator, `location`/`server`/`set_cookie` parts, `binary` matcher, 10 stdlib DSL string functions, string/int comparison coercion.

## Scan Output & Logging

- ✅ Scan-duration log line (2026-09-06) — `scan finished in <d> (<n> target(s), <m> raw finding(s), pre-dedup)`, all 3 frontends.
- ✅ Rejected-template log spam (2026-09-05) — compact per-reason histogram by default, full list behind `--verbose`/`--log-rejected`.
- ✅ **Host-error-threshold skip was silent** (2026-09-10) — `hosterrors.Cache` gained `ShouldSkipWarnOnce`; the breaker now logs one `warn` line per host instead of vanishing it from the Logs panel. Tests: `TestCache_ShouldSkipWarnOnce_*`, `TestEngineRun_LogCallback_FiresOnceForHostErrorSkip`.
- **LT-141 (open) — the "this target is a dead end" signal is four unrelated mechanisms with no shared shape.** D6's uniform-wall skip (findings), the adaptive-throttle abort (findings), recon's `AppSurface: none` (stderr only), the hosterrors breaker (a log line, no finding) each report "give up" independently — a UI/report consumer has to know all four. **Possible fix:** a shared "target abandoned" event with a `reason` enum, without collapsing the existing distinct finding IDs. **Not scheduled** — UX polish, not detection coverage; revisit opportunistically or on a 5th mechanism.

## Decision Engine & Recon→Plan Signal Use

Surfaced 2026-09-04 against `andertone.com`: recon was strong but `registry.Resolve` produced 134 mostly-noise leaves and idor/authbypass/ssrf/businesslogic never activated. Root cause: the decision engine reasoned only over `TechStack`, never `Endpoints`/`Ports`, and tag-matching was too broad.

### P0 — precision & correctness (✅ all landed 2026-09-04)

Version-aware CVE ranking (P0-1a); ranked template-tag selection + canonical tech→tag map (P0-2, 107→74 leaves); `Finding.Target` double-slash fix (P0-3); PlanTree leaf dedup by `(target, detector)` (P0-4, 31→8 leaves); non-actionable-tech denylist (P0-5). Detail: [15](15-implementation-plan-ph6.md) Step 2 addenda. P0-1b (true semver range gating) → Phase 8 Step 4.

### P1 — coverage (turn recon signal into leaves)

- **P1-1 ✅** Endpoint-driven resolution pass (2026-09-04) — idor/ssrf/businesslogic went from unreachable to active.
- **P1-2 ✅ (2026-09-04 interim, 2026-09-11 real detector)** — `resolvePortFacts` emits an honest `StatusUnresolved` leaf naming an open port for a protocol nothing checks; for the ports `netservice` now covers (21/3306/5432/6379/27017) it promotes straight to a dispatchable `tcp://host:port` leaf instead (Phase 8 Step 1, closes LT-23; 5432/27017 added 2026-09-11, LT-142). Remaining `interestingPorts` entries (23/9200) still get the visibility-only leaf — see LT-142.
- **P1-3 ✅ (2026-09-04)** — WordPress plugin/theme slug+version facts from crawled endpoints.
- **P1-4** nuclei DSL/`part:` gaps — ✅ mostly closed 2026-09-04 (`content_type_N`, indexed `part:` names, `path:`-multi-request correlation). Still open: `xpath`/`flow:` cross-block `_N` → [Phase 9](18-implementation-plan-ph9.md) Step 2; affected-version index field → Phase 8 Step 4.
- Multi-key + file-based `payloads:` ✅ (2026-09-04); `interactsh_*`/OOB support for nuclei templates ✅ (2026-09-04, `pkg/oob` wired into `pkg/template/nuclei`, one shared `Poller`).
- **P1-5** `techRules` coverage — woocommerce ✅; cloud-provider (aws/s3/gcp) exposure tags ✅ done 2026-09-09, Phase 8 Step 3.

### P2 — LLM leverage & ergonomics (✅ all six done 2026-09-04)

Structured `LeafContext` for `ResolveLeaf` (P2-2); ranked-template prompts for `use_existing_tag` (P2-3); `PlanFromRecon` 4th caller, CLI `plan --llm-assist` only (P2-1/P2-4); index/corpus drift guard (P2-5); `--scope` hard-fail for CLI `plan`/`recon` (P2-6). Detail: [15](15-implementation-plan-ph6.md) Step 2 P2 addendum.

## Live Testing — nettix.com.pe & aceautowreckers.com (2026-09-04)

First real run against owned targets. All 17 items below ✅ done 2026-09-04 unless noted:
- LT-1 Web UI Launch never dispatched ranked leaves → `pkg/planexec` + Plan Preview approve/execute.
- LT-2 `misconfig.rejected()` didn't exclude 5xx → now excludes 502/503/504.
- LT-3 A real OpenAPI/GraphQL spec never triggered idor/misconfig → `resolveAPISpecFact`.
- LT-4 Recon silently failed on self-signed-cert hosts → `recon.ClientConfig` forces `InsecureSkipVerify`.
- LT-5 ✅ done 2026-09-07 — SSE catchup/dedup via a monotonic `eventSeq`.
- LT-6 ✅ done 2026-09-06 — `reporter.SplitAggregates` expands the nuclei missing-headers aggregate, collapses the native/nuclei pair. *Tail still open:* same 1:1 pair for weak-HSTS (needs a template-ID skip-list entry); webui/mcp never call `Dedup`/`SplitAggregates`.
- LT-7 `matchTemplateTags` is version-blind → Phase 8 Step 4.
- LT-8 katana hardcoded `-depth 2`, no JS-rendering → 🟡 `--crawl-depth` done 2026-09-07; headless mode superseded by LT-99.
- LT-9 hostname product hints unused → `hostnameProductHints` exact-token dispatch.
- LT-10 Google Analytics → 3 false template leaves → added to `nonActionableTech`.
- LT-11 `recon`/`plan` emitted zero stderr → `--verbose` flag.
- LT-12 Web UI "misconfig" selection also runs the full corpus → doc fix (real mitigation is LT-16/17).
- LT-13 A malformed rendered URL crashed the whole template → skip-with-warning per path.
- LT-14 Tech facts duplicated across www./bare host variants → `NormalizeHost`.
- LT-15 Bare response headers weren't DSL identifiers → case-insensitive header fallback.
- LT-16 Full corpus scans regardless of detected tech → `registry.TechStackTags`, opt-in. **Superseded 2026-09-06** by LT-17's default-on narrowing + category floor.
- LT-17 ✅ done 2026-09-05 — CLI/MCP parity for tech-stack narrowing (`--recon-file --narrow-by-tech`).

## Live Testing — andertone.com (2026-09-04)

Recon was strong (5 hosts, 28 tech facts, 204 endpoints, ports 21/3306 on `staging.`) but exposed the decision engine's noise problem and a corpus-execution-cost problem.

- **LT-18 ✅ done 2026-09-05/06** — a scan spent its wall-clock on unrelated templates: (a) `--narrow-by-tech` made default-on + a per-detector category floor; (b) bounded intra-target template fan-out (`--template-concurrency`); (c) corpus loaded once per host not once per leaf; (d) rejected-template log hygiene. All [Phase 6](15-implementation-plan-ph6.md) Step 6, complete.
- LT-19 ✅ `canonicalTechTags["nginx"]` exclude set didn't match real corpus tags → fixed.
- LT-20 ✅ businesslogic endpoint match didn't reuse `IsStaticAssetPath` → fixed.
- LT-21 ✅ a cache-busting hash was recorded as a plugin version → shape-validated.
- LT-22 ✅ (2026-09-05) fresh template-rejection measurement (320/9,363, ~3.4%) → `+` concat, named parts, `binary` matcher, 10 DSL functions, string/int coercion all fixed; `xpath`/`flow:` → Phase 9 Step 2; disallowed blocks are by-design.
- **LT-23 ✅ done 2026-09-11** — live-confirmed FTP (21) + raw MySQL (3306) exposure on `staging.andertone.com` behind an otherwise 403-walled HTTP surface, with no reachable check. Closed by [Phase 8](17-implementation-plan-ph8.md) Step 1: `tcp:` lifted out of `loader.go`'s `disallowedBlocks` into a real bounded executor (`pkg/template/tcpproto`, matcher/dsl `data`-part alias), plus a first-party `netservice` detector (anonymous-FTP, empty-password MySQL, unauthenticated-Redis) dispatched via `resolvePortFacts` promoting a covered open port straight to a `tcp://host:port` leaf. Not yet re-verified against the live `staging.andertone.com` target itself (owned, in scope) — see LT-142's re-verification note.

### Step 5 live-verification runbook (2026-09-05, DVWA/WebGoat/Juice Shop + aalberts.com)

- LT-24 ✅ an I4 field-miss LLM call fired on every `plan`, even a misconfig-only one → gated on `planLeafDetectors(tree)`.
- LT-25 ✅ `plan --llm-assist`'s recon-wide proposal call timed out reading a slow frontier response → request timeout bumped 180s→240s.
- LT-26 ✅ done 2026-09-06, two landings — `--recon-file` tech→tag union was too liberal (pulled in corpus-wide `rce`/`kev`/`cve*` tags from one legit match); fixed via a `genericCorpusWideTags` denylist then `techProductTags` (intersect with the fact's own identifying tags only). 9,432→5,333 templates on a real rich-stack target.
- LT-27 ✅ the Web UI Cancel control full-page-navigated away → `hx-post`/`hx-target` in place.
- LT-28 ✅ `pkg/webui` tests timed out when the real recon toolchain was on `PATH` → test-isolation env scrub.

## Live Testing — www.valmo.in / Meesho (2026-09-06 and 2026-09-07)

First end-to-end pipeline run against a modern SPA/CDN target. `www.valmo.in` was a Google-Cloud-fronted React SPA returning one byte-identical `index.html` for every path (incl. a random canary) — recon's unguarded 2xx-checks fabricated signal, and `plan` produced ~19 false leaves out of 21. By the 2026-09-07 re-run the asset had moved behind an Akamai WAF (403 on everything) — a second, different class of the same "recon needs a block-wall gate" problem. Full write-ups: `.engagements/meesho/logs/{baseline,acceptance,dryrun}-2026-09-06/*.md`.

**All items below ✅ done** (demo-batch 2026-09-06, post-demo-batch 2026-09-06, `ph7-step3a/3b/4a/4b` and the near-term batch 2026-09-07) unless marked open:
- **Canary/soft-404 gating (LT-30, LT-30b):** `EndpointFact` gained `BodyLen`/`ContentType`/`Title`; `probeCommonPaths` fetches one canary/host and drops any 2xx/3xx matching its shape; an `APISpecFact` requires a real structured content-type. Highest-value single fix from this round.
- **Non-actionable-tech additions (LT-31, LT-84a):** Google Cloud Storage/S3/CloudFront, cdnjs/jsdelivr/unpkg/Google-hosted-libs.
- **LT-32** a live HTTP host with only non-actionable tech facts got zero misconfig leaf → `resolveLiveHostBaseline` emits a baseline leaf for any host with a direct-probe live endpoint.
- **LT-33** recon-tool names (`katana`/`subfinder`) leaked into `MergeLLMProposals`/`PlanFromRecon` as non-executable "detectors" → filtered to `KindDetector`.
- **LT-34** `plan` always re-ran full recon → `--recon-file` input.
- **LT-35** Wave 1 subdomain/SAN enum ran even with no wildcard scope entry → `scope.HasWildcard()` gate.
- **LT-36** recon sent no policy-mandated headers → `policy.yaml` `request_headers:`, threaded through all 3 frontends.
- **LT-37** `plan --llm-assist` gave zero progress/spend visibility → per-leaf log lines + `spent $X of $Y`.
- **LT-38** a context-killed recon wave was indistinguishable from "found nothing" → `errWaveTimeout` + explicit warning. *Tail still open:* scaling `waveTimeout` by host count (see LT-111 below, which added an explicit override instead).
- **LT-39** `robots.txt`/`sitemap.xml` fetched but never parsed → `EndpointFact`s from `Disallow`/`Allow`/`Sitemap:`/`<loc>`. *Tail still open:* seeding the Wave-3 crawl itself from the parsed hints; recursive child-sitemap fetch.
- **LT-40** ✅ done 2026-09-07 (Phase 8 Step 5) — OpenAPI JSON/YAML spec walker (`specwalk.go`), live-validated against crAPI's real spec (40 paths → 6 idor candidates incl. the real BOLA route). *Tail (a) still open:* GraphQL SDL/introspection walking.
- **LT-41** `ResolveField`/`TriageFindings` reachable only from mcpserver/webui → `pkg/fieldsuggest` shared package + CLI `triage --llm-assist` + `scan --recon-file` self-fill.
- **LT-42** an engagement's prose `policy.md` was invisible to D2 preflight → warns when no `policy.yaml` sits beside it.
- **LT-43(1)/(2)** misconfig's `panel` floor tag (~1,591 templates) admitted on a bare 401/403 → gated on a real auth-boundary/admin-path signal; paired with the new `pkg/uniformwall` primitive (D6) that short-circuits the per-target corpus entirely on a uniform wall/catch-all verdict.
- **LT-44** PlanTree was flat, no grouping/priority/seeding → `GroupIntoClassNodes`, `PlanNode.Priority`/`Class`, `ExecOptions.SeedFn` (a completed leaf's finding can seed a still-pending one). Full `DependsOn` graph deferred → LT-56.
- **LT-45** CLI `scan --detector authbypass` hard-required `--auth-token` (MCP/webui didn't) → `SkipAuthTokenRequired` on the CLI path too.
- **LT-46** scan-completion log counted pre-dedup findings with no label → labelled "raw finding(s), pre-dedup".
- **LT-47** native weak-HSTS `max-age` check added (`misconfig-weak-hsts-max-age`).
- **LT-48** no deterministic "junk fact" suppressor → relevance-score floor (`minTemplateLeafScore=60`) replaced the blunt per-tech leaf count cap. A genericness-keyed fan-out cap is NOT done (folded toward LT-49's LLM veto, itself also done).
- **LT-49** no plausibility veto over a confidently-wrong `StatusPending` leaf → `VetPendingLeaves`/`VetoImplausibleLeaves` (opt-in `--llm-assist`; demote/drop only, never strengthens a leaf).
- **LT-50** tech facts and endpoints were never cross-correlated → `productEndpointSignatures` promotes a pending leaf to high confidence when a product-distinctive endpoint is observed on the same host.
- **LT-51** a `400` on an `/api/*` path is a stronger IDOR/param signal than a `404`, untreated as such → `apiRouteConfidence` lifts endpoint-driven leaves to high confidence.
- **LT-52** an out-of-scope crawled link still reached `ReconResult.Endpoints` → diverted to `OutOfScope`.
- **LT-53** `scan` didn't auto-apply policy `request_headers` (recon/plan did) → fixed.
- **R-c** `/robots.txt` double-fetched (Wave 0 + Wave 3) → Wave 3's duplicate dropped.
- **LT-61 / LT-63 (routed, not this run)** consume the CDN-ASN fact to skip/shorten naabu (✅ done, see the Akamai re-run below); companion mobile-app API discovery via subfinder's `crtsh` source → Phase 8 Step 5, still open.

## Live Testing — www.valmo.in / Meesho, Akamai re-run (2026-09-07)

Asset had moved behind an Akamai WAF returning a 403 "Access Denied" on every path (verified across UA/protocol/header variants) — zero reachable surface from this vantage. `plan` produced an empty tree; native misconfig correctly reported `misconfig-waf-blocked` in 5.8s; the `--recon-file`-narrowed full-corpus run ran 30+ minutes for nothing. All items ✅ done 2026-09-07 (`ph7-step4a`/`lt57-60-waf-plan-gaps`):
- LT-57 `resolveLiveHostBaseline`'s live-status gate excluded 401/403/429 → widened, so a WAF-walled host still gets a baseline misconfig leaf.
- LT-58 `reconShowsAdminSurface` re-admitted the `panel` floor on a blanket WAF 403 → now requires a real auth-boundary/admin-path signal, not just any 403.
- LT-59 **the D6 primitive itself:** `pkg/uniformwall.Classify` (recon Wave 3) → `ReconResult.UniformResponses` → `scanner.Engine` skips `runTemplates` for a walled host, emitting one honest finding. Override: `--scan-uniform-anyway`. (Originally one fact per whole run — widened to one per host by LT-140 below, 2026-09-11.)
- LT-60 an empty plan gave no diagnostic → `emptyPlanDiagnostic` stderr line.
- LT-61 CDN-edge ASN table (`pkg/recon/cdnasn.go`) skips naabu port-scanning a recognized CDN-edge host. *Tail still open:* per-resolved-IP ASN classification (today only the seed domain's own ASN is checked).
- LT-62 recon gave no "I'm blind here" signal on a high block ratio → `UniformResponseFact.BlockedRatio` + a `plan` stderr diagnostic.
- **LT-63 (open)** — a scope entry with a documented companion mobile app triggers no API-host discovery. **Fix:** a passive, scope-checked companion-API pass reusing subfinder's `crtsh` CT-log source for `api.`/`gw.`/`mobile.` siblings. → Phase 8 Step 5.

## Live Testing — linkpop.com / Shopify (2026-09-07)

A decommissioned asset: root 301s to the out-of-scope `www.shopify.com`; every other path is a GCS bucket serving one static 404 shell. All items ✅ done 2026-09-07 (Phase 7 Step 6a / Phase 8 Step 5 first tranche / near-term batch) unless noted:
- LT-64 recon followed a cross-host redirect and attributed the destination's content to the original target → `redirect_chain`/`final_url` recorded, first-hop status kept, out-of-scope destination warned loudly.
- LT-65 tech facts fingerprinted post-redirect were attributed to the original host → withheld; paired with `dropCDNTechWithoutHeader` (a CDN brand with no corroborating header on the host itself is dropped).
- LT-66 ✅ done 2026-09-10 — the D6 catch-all verdict was host-level; a bucket host whose canary happened to 404 could still record an individual `200` path as a high-confidence endpoint. Fixed: `probeCommonPaths` now keeps a per-call body-hash/bucket-marker record, and `dropCatchallCommonPathEndpoints` drops any batch endpoint whose body duplicates another probed path's or whose headers carry an `x-goog-*`/`x-amz-*`/`x-guploader-uploadid` marker, when the host classified `catchall`. Test: `pkg/recon/catchall_endpoints_test.go`.
- LT-67 8 `shopify-*` secret-grep template leaves planned against a 746-byte static shell → suppressed when the host shows no dynamic-content evidence.
- LT-68 (see the valmo batch above — done in the near-term batch, first hit on this run).
- LT-69/73 (see the anti-FP fixes above — the 200-equals-baseline and 429-as-exposed shapes resurfaced here, same fix).
- LT-70 (see above — done in the near-term batch).
- LT-71 ✅ done (Phase 7 Step 6a, F4) — `LoadDirByIDs` ID-peek fast path for a plan-executor specific-template leaf; skips a full corpus parse. *Still open:* the pure-`--tags` scan path (no plan) still full-loads.

## Live Testing — accounts.shopify.com / shop.app (2026-09-07)

Both behind Cloudflare managed-challenge. `accounts.shopify.com` was the model D6 outcome (correctly classified, corpus skipped, one honest finding in 10s). `shop.app` was not: a 58-minute scan into the wall produced 11 noise findings from self-inflicted rate-limiting, because its wave-3 canary had errored rather than returned a readable block page, so no uniform-wall fact was ever set. All items ✅ done 2026-09-07 (near-term batch / Phase 8 Step 5 first tranche) unless noted:
- LT-72 D6 verdict derived only from the canary probe, with no fallback on a canary error → falls back to the wave-2 httpx root observation.
- LT-73 (see anti-FP fixes above).
- LT-74 no adaptive backoff/abort on sustained 429/503 → the adaptive-throttle middleware (LT-88 extends it to connect-failure spikes).
- LT-75 (= LT-81, see above).
- LT-76 low-confidence recon endpoints (robots/sitemap, unprobed) were discarded wholesale, missing a 110-endpoint payment/OAuth surface → `probeUnprobedEndpoints` probes a name-ranked sample.
- **LT-77 (🟡 partly done)** — no redirect/OAuth-flow detector rule for `*/bounce`, `/oauth/authorize`-shaped endpoints. `IsRedirectFlowPath` now dispatches the corpus's `open-redirect-generic` template against such hosts. **Still open:** a first-party per-param off-origin-`Location` probe beyond that one template → folded toward [Phase 9](18-implementation-plan-ph9.md) Step 4.
- **LT-78 (open)** — the `llms.txt`/`SKILL.md`/`/mcp/` AI-agent surface is unmodeled (prompt injection into agent instructions, unauthenticated MCP `tools/list`, agent-reachable mutating tools). **Fix:** a passive recon signal (fetch+record the manifest) + a follow-up leaf class (injection-marker scan, unauthenticated `tools/list` probe). → [Phase 9](18-implementation-plan-ph9.md) Step 3, needs its own design pass.
- LT-79 no per-target wall-clock budget → `--max-target-duration` (default 15m).

## Live Testing — ALSCO / Secure Gateway sandboxes (2026-09-07)

First genuinely reachable (no-CDN) bug-bounty target in four runs — but the program's premise is bypassing their own WAF/upload filters, and the run ended with the scanning IP blocked at origin. All items ✅ done 2026-09-07 (near-term batch / Phase 8 Step 5 first tranche) unless noted:
- LT-80 `--scope` didn't strip inline `#` comments → fixed (same fix applied to `scan -t <file>`).
- LT-81 (= LT-75, see above).
- LT-82 D6 verdict set without cross-checking recon's own crawl evidence (54 real endpoints incl. a genuine 404 among 2xx) → `crawlEvidenceRefutesWall` suppresses the verdict on ≥5 distinct endpoints spanning ≥2 status codes.
- LT-83 numeric query params (`?article=3`) ignored as ID-shaped IDOR candidates → `numericQueryIDCandidates`.
- LT-84 false `Cloudflare`/CDN facts and asset-host brands (cdnjs/jsdelivr) spawned unresolved leaves → denylist additions + the LT-65 "CDN fact absent from host's own headers" fix.
- LT-85 (see above — JS-syntax-fragment candidates).
- LT-86 the repeated-error breaker discarded a host's good observations when only *some* paths tarpit → a timed-out path now only counts as a per-path skip; the wave-2 root is retained.
- **LT-87 (open, coverage/model gap)** — no WAF-fingerprint step, no payload-mutation-on-403 retry, no upload-bypass detector — the whole premise of a WAF/filter-bypass-premised program. **Fix:** (1) WAF-detect recon signal; (2) retry a blocked payload with a mutation/encoding set and flag any bypass; (3) an `uploadbypass` detector. → [Phase 9](18-implementation-plan-ph9.md) Step 4, sequenced last (wants Phase 8's param surface first). A docs/22 target-selection caveat is already applied.
- LT-88 (see LT-74 above — folded in as an extra trigger condition).

Worked correctly this round: LT-26 tech-tag narrowing, LT-35 exact-host-scope warning, the D6 `--header`-UA workaround.

## Live Testing — crAPI actionable-findings prep (2026-09-08)

Capability-gap review (not a live run): every prior live target was WAF-walled/decommissioned, so the recon→detector→**confirmed finding** loop had never run against a dense-vuln target. crAPI has that surface (BOLA×N, JWT `alg:none`, SSRF, mass assignment); the detectors were already capable, the gaps were on the recon→feed side.

- LT-89 ✅ done 2026-09-08 — `recon --openapi-spec <file|url>` ingests a spec recon can't discover on its own (local/behind-auth/non-standard-path), scope-checked, folded into `ReconResult` like a served spec.
- LT-90 ✅ done 2026-09-08 — `walkOpenAPISpec` reads OpenAPI `security:` declarations onto `EndpointFact.AuthRequired`, feeding an endpoint-driven `authbypass` leaf.
- LT-91 ✅ done 2026-09-08 (Step C) — one idor leaf with N candidates meant a downstream field-miss picked the wrong one (crAPI: a harmless community-posts route, not the real BOLA orders route) → `resolveEndpointFacts` now fans out **one idor leaf per candidate**, each self-sufficient (own `EndpointTemplate`), capped at 12.

### Step B — crAPI live round 1 (diagnostic), 2026-09-08

First end-to-end recon→detector→confirmed-finding loop, two accounts, spec ingested via LT-89. Isolated detector runs (`--templates <empty-dir>`):
- **authbypass** — 6× critical (JWT `alg:none` forged token → real PII, manually reproduced; crAPI genuinely doesn't verify signatures), 1× BFLA (flagged via token-reuse, see LT-92), 5× token-reuse noise (hedged, acceptable), 1× no-rate-limit on login (hedged).
- **idor** — 5× high, verified: baseline-mode BOLA on `/workshop/api/shop/orders/{{id}}` (orders 1-5 return full card data to both test accounts; 6-100 all 500, 0 FP). crAPI's canonical BOLA, pre-LT-91 only reachable by hand-picking the endpoint.
- **LT-92** ✅ done 2026-09-09 — new `authbypass.checkBFLA` fires a structural signal (>1 distinct account identifier in the body of a `/all`/`/admin`/`management`-shaped path) instead of relying on the diff-based token-reuse check, which was tightened to require a non-empty, identifier-bearing body before flagging at all — quiets the 5 benign shared-catalog hits without touching the real BFLA detection.

### Step E — crAPI live round 2 (full pipeline + fp/fn), 2026-09-08

The whole loop, no manual per-leaf scan: `recon --openapi-spec` → `registry.Resolve` → `planexec.RunPlan` (the same executor webui/MCP wrap), two tokens on `baseCfg`. Surfaced and fixed LT-93, LT-94 (below); after those, one serial run produced **26 findings, 0 FP**:

| crAPI vuln | Result |
| --- | --- |
| Broken auth — JWT `alg:none` | ✅ 8× critical, manually reproduced |
| BOLA — shop orders + card data | ✅ 5× high (orders 1-5; 6-100 all 500, none flagged) |
| `/.env` served with real DB/Mongo passwords | ✅ 1× high misconfig |
| Missing security headers on API base | ✅ 4× misconfig |
| Excessive-data / token-reuse hedged hits | 6× medium noise (LT-92) + 1× medium no-rate-limit |
| BOLA — vehicle location (UUID IDs) | ❌ miss → **LT-95** (idor only enumerated small ints) |
| BOLA — mechanic reports (empty `report_id=`) | ❌ miss → **LT-95** (spec walker didn't template an empty ID-shaped query key) |
| BFLA — delete another user's video (DELETE) | ❌ miss → **LT-132** (no detector probes non-GET methods) |
| SSRF — `contact_mechanic` forwards attacker URL in POST **body** | ❌ miss → **LT-96** (SSRF param-suggestion only inspected query-param names) |
| Mass assignment; NoSQL/SQL injection | ❌ miss → **LT-133** (no native detector; injection needs a corpus run, not attempted) |
| JWT weak-secret; OTP rate limiting | ❌ miss → **LT-134** (wordlist/path didn't hit) |

- LT-93 ✅ done 2026-09-08 (Step E) — every `registry.resolve*` helper set a leaf's `Target` to the bare hostname (no scheme/port), so every request against a real host was malformed (0 findings) → `Resolve` rewrites a dispatchable leaf's `Target` to the real `scheme://host[:port]` recon observed.
- LT-94 ✅ done 2026-09-08 (Step E) — `planexec.RunPlan` wasn't self-sufficient: the webui execute path (unlike MCP) never pre-filled `ProtectedPaths`/`SSRFParams` from recon → the derived fields now ride the leaf itself (`PlanNode.ProtectedPaths`/`SSRFParams`), filled by `applyLeafReconFields` just before dispatch.
- LT-95 ✅ done 2026-09-09 — (1) an empty ID-shaped query key (`?report_id=`) now templates as `{{id}}`; (2) new `idor.RandomUUIDStrategy` (fresh UUIDs as denial-baseline filler + one real observed UUID as the sample) covers UUID-keyed BOLA without inventing target IDs.
- LT-96 ✅ done 2026-09-09 — the spec walker now reads a POST operation's JSON body schema onto `EndpointFact.BodyParamKeys`; `SuggestSSRFBodyParamsFromRecon` keyword-matches them; `ssrf.Detector` gained a body-param check (`checkBodyParamTargets`).
- **LT-132 (open)** — no authbypass/idor check ever probes a non-GET method, so crAPI's real `DELETE /workshop/api/merchant/video/delete/{id}` BFLA (delete another user's video) is structurally unreachable. **Value: medium-high** (generalizable mutating-method BFLA/BOLA class). **Effort: medium** — mechanical field-threading, but firing a non-idempotent method against a live target needs a safety-first design (probe with the *other* account's token against the *owner's own* just-observed resource ID, read-verify via a follow-up GET, never invent/mutate a resource that isn't the authenticated account's own). **Route:** [Phase 9](18-implementation-plan-ph9.md) Step 4 (already touches parameter-aware, non-GET-shaped probing).
- **LT-133 (open)** — two homeless vuln classes from the same crAPI observation. **Mass assignment** (an extra/undocumented JSON field silently accepted on write) has **no detector anywhere**, native or corpus, and doesn't fit Phase 9 Step 4's `sqli`/`xss`/`lfi`/`uploadbypass` scope. **NoSQL/SQL injection** *is* Step 4's job once it lands. **Value: medium** (real class, not independently confirmed exploitable this round). **Effort: high** for mass assignment (needs its own design pass — safely diffing "extra field accepted" without a destructive write); SQLi/NoSQLi effort already accounted for in Step 4. **Route:** SQLi/NoSQLi → Phase 9 Step 4; mass assignment → needs its own future design note, not silently folded in.
- **LT-134 (open)** — `checkJWTWeakSecret`'s fixed wordlist didn't contain crAPI's actual secret, and `checkRateLimitSignal` never probes an OTP/2FA-verification endpoint (only `LoginPaths`). **Value: low** (target-specific wordlist/candidate-list gap, not structural). **Effort: low** (append `WeakJWTSecrets` entries / add an `OTPPaths` list, same pattern as `LoginPaths`/`LogoutPaths`). **Route:** low-priority roll-up, pick up opportunistically.
- LT-123 ✅ done 2026-09-10 (design review) — `--auto-provision-account` + `--provision-email <template>`: registers a throwaway second account against a recon-observed signup endpoint (new `ReconResult.SignupEndpoint`, spec-derived or path-guess) so idor/authbypass's second-account checks don't need an operator-supplied token. A second, independently-scoped exception to read/enumerate-only (CLAUDE.md) — fails closed on an email-verification gate, no cleanup attempted. CLI-only for v1 (MCP/webui wiring gap → LT-131).
- LT-135 ✅ done 2026-09-10 — `businesslogic`'s coupon checks were previously crAPI-only in practice: hardcoded field/response-field names on top of the already-overridable paths. `responseGrantedAmount` generalized to a bounded recursive scan for any numeric field within [90%,150%] of the injected amount; new spec-derived `ReconResult.CouponEndpoint`/`CouponFact` (schema v1.12) extracts both the mint+apply paths *and* their real field names from an OpenAPI spec (no path-guess fallback — recon must stay read-only and a coupon-mint endpoint is POST-only/mutating). `--allow-writes` + a spec-carrying `--recon-file` now needs zero manual coupon flags. Tests: `pkg/recon/specwalk_test.go`, `tests/unit/detector_businesslogic_test.go`, `pkg/registry/decisionengine_test.go`.
- **LT-136 (open, design idea)** — a JS-static-extracted secret (Phase 8 Step 3) is reported on pattern match alone, never confirmed live. **Idea:** for a curated, small set of well-known shapes, add one bounded read-only validity probe against the credential's own vendor API (AWS STS `GetCallerIdentity`, GitHub `/user`, Slack `auth.test`) and fold a confirmed-live result into `Confidence`/evidence — never `Severity` (detector-sets-severity invariant preserved). **Value: medium-high** (large trust jump, "confirmed live" vs. "looks like," for one extra benign call). **Effort: low-medium** (each vendor check is one fixed-endpoint call; the real work is the shape→probe dispatch table and never persisting the credential value beyond that one call). Not scheduled; natural fit alongside Phase 8 Step 3 if picked up.

## Live Testing — G1 agent-driven eval (2026-09-10)

Real MCP-client-driven `recon`→`plan`→execute(→`findings.triage`) run against all four lab targets (`tests/eval/agent_run.go`/`agent_eval_test.go`, doc16 Step 6's G1). Full write-up: [90-research-hackerbot.md](90-research-hackerbot.md) §G1.

- LT-137 ✅ done 2026-09-10 — `plan` execution never applied doc15 Step 6a's tech-based template narrowing at all (`DerivedTags`/`Tags` left empty in both `tools_plan.go`'s `buildBaseExecConfig` and webui's plan-exec path), so every leaf ran the *entire* synced corpus — a first G1 run timed out on 3/4 scenarios from one misconfig leaf's 3+-minute corpus pass alone. Fixed: both paths now set `DerivedTags`, `planexec.executor.go`'s `runLeaf` unions each leaf's own detector-tag floor on top (mirroring `cmd/hackerfive/scan.go`'s existing `unionScanTags` composition). **Residual, honest limitation:** misconfig's floor tags are broad category words matching most of the corpus, so floor-only narrowing (no tech fingerprint) only trims ~25% — matches the CLI/webui paths' own long-documented behavior.
- **LT-138 (open)** — two agent-specific gaps surfaced, neither fixed. (1) crAPI's idor/authbypass leaves resolved *pending* but were *skipped at execution* (missing `--endpoint`/`--protected-paths`) under `--recon-depth active` (no Wave-3 crawl); I4's field-miss resolution never ran — `llmfallback.ResolveTreeLeaves`'s field-suggestion path appears scoped to an I3-*unresolved* leaf, not a *pending*-but-execution-blocked one. (2) the native `misconfig-method-*` check (`checkDisallowedMethods`) never fired against DVWA/Juice Shop/vAPI through the agent path despite firing in the CLI baseline against the same targets, identical `Concurrency`/`RateLimit`/`Timeout` defaults ruled out as cause; root cause not yet found. Needs a follow-up live session with dedicated time for (2)'s root-cause and a design decision for (1).

## Live Testing — pre-v0.7.0-tag re-verification against www.aalberts.com (2026-09-10)

Full `recon --recon-depth active` → `scan --detector misconfig` → `triage --llm-assist` → `suggest --llm-assist` pass against the live, published-VDP `www.aalberts.com`, before tagging `v0.7.0`. `triage --llm-assist` worked cleanly (11 findings ranked, $0.0005). Two real bugs surfaced and fixed before tagging:

- LT-139 ✅ done 2026-09-10 — `misconfig-cors` conflated a literal wildcard `Access-Control-Allow-Origin: *` with genuine origin-reflection, both rated high/high — but a literal `*` alongside `Access-Control-Allow-Credentials: true` is spec-non-functional in every standards-compliant browser (Fetch/CORS spec), so the finding overstated severity for aalberts.com's actual (non-reflecting) case. Fixed: `checkCORS` now splits `echoedProbe` (genuine reflection, stays high/high) from `literalWildcard` (down-ranked to low/medium, description corrected). Test: `TestMisconfigCORS_LiteralWildcardWithCredentials_DownRanked`.
- LT-139b ✅ done 2026-09-10 — `SuggestedAction.Detail map[string]string` couldn't decode a real model response (`suggest --llm-assist` correctly proposed a `triage_group` action with an array-valued `finding_ids` field), so `decodeJSONResponse` failed the *entire* response and silently degraded to ledger-only — a good, safe proposal thrown away per the "degrade, never fabricate" contract, but a real capability loss. Fixed: widened `Detail` to `map[string]any`; prompt documents the array shape. Test: `TestSuggest_TriageGroupWithFindingIDsList_Decodes`.

## Live Testing — nettix.com.pe Part A/B verification (2026-09-10)

Re-ran a full recon + targeted scans against the real, owned `nettix.com.pe` estate to check whether LT-92/95/96/123 actually engage on a real target, and to watch live traffic for further gaps.

**Verdict: the Part A fixes are real and already proven correct (crAPI, unit tests) but this target has none of the endpoint shapes that exercise them** — no `{id}`-shaped route, SSRF-able param, or self-service signup flow; `--auto-provision-account` correctly failed closed. Digging into *why* authbypass got zero leaves surfaced LT-124/125, the most valuable findings of the round:

- **LT-124 ✅ done 2026-09-10** — every authbypass check blindly trusted `resp.StatusCode` after the shared client transparently follows a redirect — a live FALSE POSITIVE: `GET /wp-admin/` (302→`wp-login.php`, correctly protected) was reported as `authbypass-missing-auth-wp-admin` high/high because the client followed the redirect and graded the login page's 200. Fix: `redirectedAwayFrom(req, resp)` gates all five authbypass checks (porting `misconfig`'s existing pattern). idor/ssrf's identical blind-status pattern left as-is (self-corrects via baseline/diff).
- **LT-125 ✅ done 2026-09-10** — `SuggestAuthBypassPathsFromRecon` only recognized 401/403 as "protected path" evidence, missing the extremely common "3xx redirect to a login page" shape — which is *why* this round had zero authbypass leaves despite `/wp-admin/` sitting right there as a recon-observed `302`. Fix: `redirectsToLoginBoundary` bucket ahead of the other cases. Landed with LT-124, sequenced after it.
- **LT-126 (open)** — `probeCommonPaths` records a probed path's *pre-redirect* URL alongside the *post-redirect* response's status/body — a same-host redirect gets none of LT-64's cross-host treatment. Live-confirmed: `erp.nettix.com.pe/api` recorded as `200` (actually Dolibarr's "API module must be activated" page at `/api/`, confirmed by hand; `/api` itself is a 301). **Fix:** same shape as LT-64 for the same-host case — rewrite `EndpointFact.URL` to the final URL, or carry the redirect chain regardless of host.
- **LT-127 (open)** — a wiki/CMS whose "page doesn't exist" response is HTTP 200 with a page-name-templated title defeats LT-30's canary suppression (body differs *by design* per path) — DokuWiki fabricated 3 high-confidence fake API endpoints this round. **Fix:** fetch a second, differently-named canary and diff it against the first; if they differ only in the echoed-path substring, classify as templated-catch-all.
- **LT-128 (open)** — `signupPathCandidates` (LT-123) is too narrow for WordPress/WooCommerce-style registration (a query-string action on an existing path, or a form embedded in an existing page) — `--auto-provision-account` never got a chance on this target. **Fix:** widen with `/wp-login.php?action=register`; consider a body-marker check for GET-rendered registration forms.
- **LT-129 (open)** — `pkg/fingerprint` has no signatures for Dolibarr/Nextcloud/Webmin/DokuWiki (all four confirmed live here), each instead reverse-engineered into a bespoke one-off `misconfig` check; `Signature` has no version-capture mechanism at all. **Fix:** add header/body signatures for all four (e.g. Dolibarr's `DOLAPIKEY` CORS header) + `hostnameProductHints` tokens; add an optional `VersionRegex` to `Signature` so future products get CVE-correlation for free.
- **LT-130 (open)** — the D2 program-policy pre-flight runs only against the CLI's initial seed target, never against hosts recon fans out to (24 real hosts this round, zero individually policy-checked). `scan` itself is unaffected (explicit `--targets` only). **Fix:** re-run `preflight.Check` over the full in-scope host list after Wave 1.
- **LT-131 (open)** — `pkg/mcpserver` has zero wiring for Part A/B's new fields (`SSRFBodyParams`/`IDORSeedID`/`AutoProvisionAccount`/`SignupEndpoint`) — an MCP-driven agent can't reach LT-95/96/123 at all, CLI-only. **Fix:** add the fields to `scanInput`/`planInput`, thread into `cfg`/`baseCfg` the same way the CLI does. Minor: `handlePlan` silently discards a template-index load error where `runScan` warns — align them.

### Demo-target selection (2026-09-08/09/10)

Active recon + a focused `misconfig` pass over the four owned demo domains (`.engagements/owned-sites/scope.txt`) to pick the 2026-09-10 Web UI demo target.

**Demo-target verdicts — do not re-evaluate these for a demo:**
- **`nettix.com.pe` — ✅ the demo target.** Only one of the four with a reachable, un-walled surface and a confirmed actionable finding: `www.nettix.com.pe` serves the full WordPress author list unauthenticated at `/wp-json/wp/v2/users/` (incl. `admin`, still active) — CWE-200, feeds credential stuffing. Secondary: `erp`/`ixn.nettix.com.pe` expose Dolibarr ERP 23.0.3 (behind 23.0.4+, CVE-2026-81728 HIGH + CVE-2026-85401; the earlier "critical dol_eval RCE" read was wrong, NVD-corrected 2026-09-08).
- **`aalberts.com` — ❌ non-viable.** Hardened estate (Cloudflare/M365 SSO/HTTP Basic/S3 apex), ~3 scannable hosts, thin actionable set, source-IP-blocked mid-run. FP-regression fixture only. Full record: § "Live Testing — www.aalberts.com" below.
- **`andertone.com` — ❌ non-viable (demo).** HTTP surface CDN-403-walled; the one real exposure (FTP:21+MySQL:3306 on `staging.`, LT-23) has a real `netservice` detector now (Phase 8 Step 1, done 2026-09-11) but that's a single non-HTTP finding, not a demo-worthy walkthrough — this verdict is about demo viability, not detector coverage; do not re-evaluate.
- **`aceautowreckers.com` — ❌ non-viable.** Fully Cloudflare-walled, every host 403. Same dead-end class as valmo/shopify/ALSCO.

For an actionable demo independent of owned sites, crAPI (13 verified findings, 0 FP, full plan→execute) stays the strongest.

- LT-97 ✅ done 2026-09-08 — no first-party WordPress REST user-enum check (the nuclei template existed but a real-target corpus run reliably never dispatches it within budget) → `misconfig.checkWPUserEnum`, always-on, immune to corpus starvation.
- LT-98 split into the dispatch-order fix (✅ done 2026-09-08, below under LT-114) and the corpus-load-perf design item (✅ done 2026-09-09, LT-106).
- LT-99 ✅ done 2026-09-09 — no headless/JS-rendered crawl (non-headless katana on crAPI's SPA found 4 endpoints vs. 40 in its spec) → opt-in `--headless-crawl` (`recon`/`plan`, `--recon-depth full` only), self-provisions Chromium if needed. webui/MCP toggle deferred.
- LT-100 ✅ done 2026-09-09 — no hidden-parameter mining → first-party diff-oracle param miner (`--param-mining`, curated ~239-name wordlist, ≥2-signal corroboration gate, hard request cap). Live: 0% FP on crAPI decoys, 4 real undocumented Juice Shop params found. webui/MCP toggle deferred.
- ffuf-style multi-position fuzzing reaffirmed out of scope 2026-09-08 → [Parked](#parked--revisit-on-a-trigger-or-after-an-eval).

### Apex re-run 2026-09-08 — 24 hosts, 5 findings confirmed by hand

`recon --scope '*.nettix.com.pe' --recon-depth full` → 24 hosts / 66 endpoints / 66 tech facts. Hand-verified actionable surface (all read-only GET):

| # | Finding | Host(s) | Detector status |
| --- | --- | --- | --- |
| A | WordPress REST user enumeration | `www`, `soporte` | ✅ `checkWPUserEnum` |
| B | Dolibarr ERP 23.0.3 exposed, outdated | `erp`, `ixn` | ✅ `checkDolibarrOutdated` |
| C | Nextcloud `status.php` unauth version disclosure | `cloud01`, `cloud02` | ✅ `checkNextcloudStatus` |
| D | Nextcloud 28.0.5 outdated (EOL major + 4 CVEs) | `cloud01`, `cloud02` | ✅ `checkNextcloudStatus` |
| E | phpMyAdmin exposed | `chasqui03` | ✅ `checkPhpMyAdmin` |

Not hand-verified: Webmin :10000, Apache Guacamole (`guacamole01`), a webmail stack, DokuWiki (current, ruled out).

- LT-101 ✅ done 2026-09-08 — a `www.<domain>` seed starved Wave 1 subdomain enum (39-host surface collapsed to 1, since subfinder ran against the `www.` host, not the registrable domain). **Still open:** the registrable-domain reduction itself (this round worked around it by re-seeding at the apex by hand); real fix → Phase 8 Step 5/recon backlog.
- LT-102 ✅ done 2026-09-08 — `app_surface: none` suppressed the plan on a 24-host result where a majority of hosts were walled but several served real, distinct content → `classifyAppSurface` now weighs distinct-real-content hosts, not just the majority verdict.
- LT-103 ✅ done 2026-09-08 — a CMS login page that renders for many paths (Dolibarr/DokuWiki) was flagged `catchall` despite katana crawling real distinct routes on it → suppressed when katana itself extracted ≥2 distinct non-asset routes. **Residual (open):** depends on katana actually reaching the host inside the flat 60s wave cap on a large sweep (fixed for a focused 2-6-host scan, not a 24-host one) — filed toward LT-38/a `uniformwall` follow-up.
- **LT-140 ✅ done 2026-09-11** — `ReconResult.UniformResponse` was one fact, not one per host, so D6's corpus-skip (LT-59) only ever protected a single host per multi-host recon run — `aggregator.setUniformResponse` kept only "the first verdict seen," and all three frontends built `UniformWallHosts` (already a `map[string]string`) from that one fact. **Fix:** `UniformResponseFact` widened to a per-host collection — `ReconResult.UniformResponses []UniformResponseFact` (schema v1.13, a deliberately breaking rename: `uniform_response` → `uniform_responses`, agreed since no real external MCP consumer depended on the old shape yet); `aggregator.uniformResponses` keyed by `NormalizeHost` (per-host first-writer-wins, same convention as `addTech`'s LT-14 dedup); `classifyAppSurface` now judges "blind" against every walled host, not one named host; new `ReconResult.UniformWallHosts()` / `UniformResponseForHost(host)` helpers replace each of the 4 call sites' (`cmd/hackerfive/scan.go`, `pkg/webui/handlers_launch.go`, `pkg/mcpserver/tools_plan.go`/`tools_scan.go`) hand-rolled single-entry map. Also fixed two latent cross-host bugs the single-fact shape had baked in: `reconShowsAdminSurface` (LT-58) and `hostServesDynamicContent` (LT-67) in `pkg/registry/decisionengine.go` now resolve the wall verdict per endpoint/leaf host — before, a WAF wall on host A could blanket-suppress a real 401/403 admin signal or secret-grep leaf on unrelated host B in the same multi-host run. → [Phase 8](17-implementation-plan-ph8.md) Step 5 DoD (filed alongside LT-64/65/84's per-host fact attribution theme, not Step 6 as originally noted here — Step 6 is Eval Maturity + Release, a stale reference from before this doc's 2026-09-10 step renumbering).
- LT-104 ✅ done — scan-side face done 2026-09-08 (a second-canary `detectCatchAll` check suppresses exposed-path/dir-listing FPs on a confirmed soft-404 catch-all host); recon-side face done 2026-09-10 via LT-66's tail (above) — the phantom `wave3-common-path-probe` endpoints themselves are now dropped on a catch-all host.
- LT-105 (open) — a `WordPress:7.1` tech fact is a misparse (plugin/asset version bleeding into the core-product fact, cf. LT-21) — poisons any affected-version CVE gating. Needs shape-validation / a `/wp-includes/version.php`-adjacent signal instead of an httpx guess.
- LT-118 ✅ done 2026-09-09 — `misconfig-exposed-path-admin` structurally false-positives on any app whose `/admin` redirects to a login page (every WordPress site) → `looksLikeAuthLoginPage` suppresses it.
- Native product-fingerprint checks (Dolibarr/Nextcloud/phpMyAdmin/Webmin) ✅ done 2026-09-08 — `checkDolibarrOutdated`, `checkNextcloudStatus`, `checkPhpMyAdmin`, `checkWebmin`, all gated on a hard structural marker + an NVD-verified `KnownVulnerableVersions` CVE table shared across products. Negative control: DokuWiki correctly yields zero product findings.

### Baseline run 2026-09-08 — engine multi-host findings (pre-implementation)

Ran current `main` against `nettix.com.pe` before any new implementation: **the native product checks — the entire value of the work above — did not fire against the live Dolibarr hosts**, silently missing the demo's headline finding. All four causes ✅ done 2026-09-08 (`fix-baseline-lt113-111-114`):
- LT-111 recon's wave-time cap was a hard-coded 60s const, non-deterministically starving subdomain enum on a large sweep → `--wave-timeout` flag + env override, default unchanged. Host-count auto-scaling (LT-38's tail) still open.
- LT-112 subfinder emitted an FTP-banner-prefixed hostname (`220-sinchi01…`) that silently voided the entire httpx batch (zero output, no error) → `normalizeHostname` strips/rejects malformed entries; httpx-wave now warns on an unexpected zero-live-host result.
- LT-113 **#1 demo-blocker** — the misconfig check loop forfeited every remaining check once the host-error breaker tripped, and the 5 product-fingerprint checks were ordered *last* → they're now a `priorityChecks` tier, run first, exempt from the breaker; a check error is now non-fatal instead of aborting the whole detector. Root-response-cache dedup (reduces the request volume that trips the breaker at all) still open.
- LT-114 a multi-target corpus scan dispatched ~0 templates/host inside any sane budget (shared rate bucket ÷ N hosts, plus `cves/**`-first dispatch order wasting what little got through) → real dispatched-count reporting, native-before-corpus + severity-band dispatch ordering, and (via LT-106) a per-target rate-limit share once a large corpus is loaded.
- LT-106 ✅ done 2026-09-09 — corpus-load perf: `pkg/scanner/targetshare.go`'s `effectiveTargetConcurrency` caps cross-target concurrency so each in-flight target keeps ≥5 req/s of the shared bucket once a large corpus is loaded; `pkg/scanner/parsecache.go`'s fingerprinted sidecar cache skips a full ~9.6k-template parse on a tag-scoped re-run. Kill switch: `HACKERFIVE_DISABLE_PARSE_CACHE=1`. **Tail still open (low priority):** one extra dir-read pass on a cache miss; `--all-templates` can't use the cache to narrow, only to warm it.
- LT-107 ✅ done 2026-09-10 — coverage-gap ledger (`pkg/coveragegap.Ledger` + `registry.CoverageStatus`): a structured record per `(host, fingerprinted product/version)` that no loaded tag/detector matched. [Phase 7](16-implementation-plan-ph7.md) Step 7 (renumbered from "Step 8").
- LT-108 ✅ done 2026-09-10 — `hackerfive suggest <scan-output>` CLI command (`llmfallback.Suggest`): one stateless frontier call over LT-107's ledger + findings, printed-only proposed next actions. No auto-apply, no re-scan. Phase 7 Step 7, builds on LT-107.
- LT-109 (open) — `hackerfive templates promote <name>` + a webui review panel for an I4-drafted template sitting in `templates-proposed/` (today: manual `mv`). Still human-gated. → after LT-108, not yet scheduled into a step.
- LT-110 (open) — webui "Apply and Run": execute LT-108's mechanical suggestions (draft templates, queue second-pass leaves), present at the existing Plan Preview gate, launch a fresh scoped Job on approval. Needs a design pass (job-lineage model, iteration cap). → after LT-109, Phase 8/9 window.

**Baseline finding inventory (20 findings post-dedup, before the fixes above):** `www` got WP-user-enum + 2 FPs; `soporte` got one lucky corpus hit; `cloud02` got its Nextcloud findings but `cloud01` (identical) got 0 — all from LT-113. `erp`/`cloud01`/`gateway` got 0 findings each. `wiki` produced a false `misconfig-exposed-path-swagger-ui.html` (the scan-side face of LT-104). Missed vs. the hand-verified table: Dolibarr on `erp`/`ixn` (LT-113), Webmin on `gateway:10000` (port never scanned), phpMyAdmin on `chasqui03` (host never discovered, LT-111).

### Web UI review 2026-09-08 (Playwright, demo-prep)

Drove `hackerfive serve` against a live `erp.nettix.com.pe` to rehearse the demo — the scan itself was clean (5 findings, 0 FP). Three UI gaps, all ✅ done 2026-09-09 unless noted:
- LT-115 ✅ scoped MVP — the Launch form had no multi-target input (a focused N-host scan needed N launches) → an optional "Additional targets" textarea, one Job fans across all targets. **Deferred to a fuller version:** recon still runs once, against the primary host only — its tech-narrowing/field-fill then apply to every target, so a mixed-tech host set should leave tech-stack narrowing unchecked. Per-host recon + a merged multi-host result is the larger follow-up, still open.
- LT-116 ✅ the "Plan Preview" link was invisible during a running scan (only appeared after a manual reload) → moved into an SSE-swapped block, appears the moment recon finishes. Also renamed the page "Suggested Checks" for clarity (label only).
- LT-117 ✅ the recon Endpoints table was swamped by katana-crawled JS-library internals (`includes/jquery/…`, `*.js.php`) → widened static-asset/vendor-path recognizer (`IsNonRouteAssetPath`) used by both the table collapse and the idor/authbypass/ssrf candidate filters.

## Live Testing — www.aalberts.com (2026-09-09)

First full recon+scan of an owned domain only ever recon'd before. A hardened corporate estate — Cloudflare, M365/SharePoint SSO gateways, catch-all SPA shells, HTTP Basic auth, S3-fronted apex — real scannable surface is 3 of 10 hosts. 17 findings post-dedup, actionable set thin (1 `misconfig-cors` worth a look, ~3 valid missing-header rows); the adaptive throttle correctly aborted the scan mid-run on a source-IP block. **Demo verdict: not a candidate, do not re-evaluate** (see the Demo-target selection block above) — kept as an FP-regression fixture only.

All four FP fixes below ✅ done 2026-09-09 (`fix-webui-plan-preview-and-misconfig-fps`):
- LT-119 `/.well-known/security.txt` flagged as an exposed path, despite RFC 9116 *requiring* it be public → dropped from `ExposedPaths` (whole `/.well-known/` namespace).
- LT-120 `checkDisallowedMethods` treated a uniform 401 (HTTP Basic wall) as "method accepted" → `401`/`407` added to `rejected()` alongside `403`.
- LT-121 `misconfig-cors` fired high/high off an auth-wall-only 401 response → down-ranked to medium/medium with a note, when every observed status on the host is an auth-wall status.
- LT-122 ✅ done 2026-09-09 — the Scan form started blank after every `serve` restart (in-memory job store) → client-side-only `localStorage` prefill of non-secret fields (never auth tokens/headers/the authorized checkbox/`allow_writes`).

**Datapoints for existing items (no new LT):** LT-6's info-severity header-noise case reappeared on `tmo.aalberts.com` (5 separate info rows); LT-26's "generic cloud-provider fact contributes no usable tag" gap reconfirmed (S3/AWS facts on the apex produced no `aws`/`s3` tag that round — since closed by Phase 8 Step 3).

## Scan-Engine Request Efficiency

Design-review follow-on to LT-18, closing the remaining redundant-request waste. Both ✅ done 2026-09-07 (`ph7-step4b`, D5):
- LT-54 the template executor had no cross-request response cache (same URL re-fetched once per template) → `pkg/template/nuclei/respcache.go`, a 512-entry FIFO cache keyed on method+URL+headers+body; carved out: interactsh/timing/path-correlated/multi-payload/non-GET/`raw:` requests always hit the network.
- LT-55 the scan re-probed paths recon already knew were 404 → `ReconResult.DeadPaths()` → `scanner.Config.KnownDeadPaths`, skips a lone single-request matcher-only template on a known-dead path (gated to an unauthenticated scan only).
- **LT-56 (open)** — PlanTree seeding is best-effort and single-case: `ExecOptions.SeedFn` lets a completed leaf's finding fill a still-pending one, but there's no explicit `DependsOn` edge and the extractor only pulls URLs from `Finding.Target`/`Evidence`. **Fix (design, unscheduled — trigger-gated):** explicit `PlanNode.DependsOn []string` + a real two-phase in-class dispatch, plus a broader `Finding→Config` seed extractor. **Trigger:** a real multi-leaf agent run observed dropping a seed that mattered.

## Low-priority / trigger-gated open items (roll-up)

Small residual tails, genuinely open but not worth front-loading. Pick up opportunistically; none is on the critical path.

- **LT-6 tail** ✅ done 2026-09-10 — `reporter.DropSupersededNucleiFindings` is the template-ID skip-list (weak-HSTS's native/nuclei pair); wired into all three finding-producing paths (CLI, webui `exportJSON`, MCP scan-tool output — the latter two previously called neither `Dedup` nor `SplitAggregates` at all). Test: `tests/unit/reporter_supersedednuclei_test.go`.
- **LT-29** — `TestEngineRun_HundredTargetsPerformance` lands ~13s over its 2m doc03 budget, deterministically (misconfig's request fan-out grew since doc03 was written, not an engine regression; CI's default `go test ./...` doesn't run this `integration`-tagged test). Re-baseline to ~2m30s with the floor-math comment, or measure a rate-limit-normalized figure.
- **LT-40 tail (a)** — GraphQL SDL/introspection walking. Deferred until a live target with a real GraphQL endpoint justifies the design work.
- **LT-56** (see Scan-Engine Request Efficiency above).
- **LT-61 tail** — per-resolved-IP ASN classification; a `lookupASN` test seam. Both small; the table itself already ships.
- **`report_intents` create — unconfirmed live** (see Reporting & Integrations below).
- **GitHub Action `scan-action`** (see Reporting & Integrations below).

## Parked — revisit on a trigger or after an eval

Genuinely deferred: real value, not yet actionable. Each entry names what would un-park it.

- **Template signing.** Un-parks when a community repo starts accepting outside template submissions.
- **DOM-based XSS via Chromedp.** Un-parks when a Phase 7/8/9 eval shows reflected-XSS live yield justifies the dependency + sandboxing cost.
- **Playwright/Caido-style richer recon signal.** Largely overlaps Phase 8 Steps 3+6; un-parks once those land and a concrete residual delta is worth sizing.
- **ffuf-style multi-position fuzzing as its own tool.** Reaffirmed out of scope 2026-09-08 — content discovery rides `httpx -path`, param discovery is served by LT-100's diff-oracle, and true multi-position volume doesn't reconcile with the shared rate limiter. Un-parks only if a live engagement shows a surface LT-100+`httpx -path` provably can't reach.
- **Baseline-mode account-provisioning guidance for a real bounty/VDP target.** LT-123 automates the common case; this is narrower operator-facing guidance for the residual manual cases. Un-parks when a real engagement needs it.
- **Self-hosted `interactsh-server`.** The public-server default covers owned-site scanning. Un-parks when a real third-party engagement needs a private OOB server.

## Reporting & Integrations

- **`report_intents` create still unconfirmed live.** `ListWeaknesses`/`ListStructuredScopes` are live-verified; the create-report request-body schema is unexercised against the real API — a deliberately incomplete trial call's `422` body is the fastest confirmation.
- **GitHub Action (`scan-action`).** Thin CI wrapper for continuous self-scanning, a different audience than opportunistic hunting. Not started; parallel track, not blocking any phase.

## Testing & Verification Gaps

- **Auth-bypass integration tests** (crAPI/vAPI) ✅ re-verified live 2026-09-10 against a fresh crAPI+vAPI Compose bring-up — `TestAuthBypassAgainstCRAPI`/`…VAPI_API1`/`…VAPI_JWTUser` all pass. [Phase 7](16-implementation-plan-ph7.md) Step 6 (renumbered from "Step 7") — which also now owns the credentialed crAPI recon→plan→scan→export round trip, itself live-verified 2026-09-10 (7 real `idor-*` + 8 real `authbypass-*`/`coverage-gap-*` findings incl. 3 critical alg:none JWT bypasses).
- **`--scope` live verification** against a real authorized target ✅ done 2026-09-10 — `localhost` vs. `127.0.0.1` (same target, different literal hostname) scans/skips correctly per `--scope`. Folded into Phase 7 Step 6.
- **LT-29** (see the roll-up above).
- **✅ done 2026-09-03 — CI coverage gate 79.0%→77.0%→80.0%.** Real coverage had drifted to ~77% unnoticed (an earlier network-flakiness failure was masking it); gate re-closed to 80.0% after new unit tests brought real coverage to 83.5%. Reusable hazard found and fixed: a naive "happy path" test on a dev machine with real recon binaries on `PATH` silently shelled out to them — fixed via `isolateFromInstalledReconBinaries` test helpers (`cmd/hackerfive` + `pkg/mcpserver` + `pkg/webui`).

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — protocol scope and template-security boundaries referenced above
- [03-development-roadmap.md](03-development-roadmap.md) / [09](09-implementation-plan-ph1a.md) / [10](10-implementation-plan-ph1b.md) / [11](11-implementation-plan-ph2.md) / [13](13-implementation-plan-ph4.md) — implementation detail behind the items above
- [15](15-implementation-plan-ph6.md) / [16](16-implementation-plan-ph7.md) / [17](17-implementation-plan-ph8.md) / [18](18-implementation-plan-ph9.md) — phase plans scheduling the deferred items above; doc17 § "Execution order" is the single cross-phase backlog
- [follow-up-archive.md](follow-up-archive.md) — the unabridged original write-up behind every compressed item above
