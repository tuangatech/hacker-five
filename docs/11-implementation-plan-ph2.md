# Phase 2 Implementation Plan — Weeks 11-18 (Expansion)

> Part of the [HackerFive documentation set](../README.md).

## Objective

Phase 1 (Weeks 1-10, see [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)/[10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md)) proved the engine works end-to-end on IDOR and misconfiguration, shipped `v0.1.0`, and closed every doc10 Future Enhancement. Phase 2's job is breadth: add API-specific auth-bypass detection, and extend coverage into two of the most commonly reported web vuln classes (XSS, SQL injection) plus information disclosure, per [03-development-roadmap.md](03-development-roadmap.md)'s Weeks 11-18.

**This plan was written before any Phase 2 code existed** — same discipline doc09 and doc10 followed: a concrete, file-by-file design first, filled in with dated "done" notes as each step is actually built, not written after the fact. **Status as of 2026-08-28: Steps 0-4 implemented and unit-tested; Step 5 (live verification) partially done — real results below, `v0.2.0` not yet tagged.** An earlier draft of this doc claimed "this Windows checkout has no Docker/live crAPI/vAPI/DVWA/Juice Shop access" — that was wrong, not a real constraint: the user's native WSL2 clone (`~/projects/hacker-five`) is reachable from this same session via `wsl.exe`, exactly like the `/mnt/c` mount used for build/test/lint, and Docker was already running there with all four lab targets up. Once corrected, Step 5's live verification ran for real — see its section below for the honest results, including where doc03's Phase 2 Success Metrics were **not** met and why.

**A real architectural finding worth stating up front, since it changes the shape of this plan versus a literal reading of doc03:** cross-checking doc03 against [doc01](01-overview-and-strategy.md) (vuln-class definitions), [doc02](02-architecture-and-tech-stack.md) (architecture), and [follow-up.md](follow-up.md) (a prior senior-security-engineer review) shows that only Week 11-12 (Auth Bypass) needs a new Go detector package. XSS and SQL injection are explicitly scoped in doc01 as template-based ("build on Nuclei patterns," "template-based patterns + error matching") — and Phase 1b already built exactly the machinery this needs: `raw:`/`payloads:` payload injection plus word/regex matchers (Future Enhancement #1, [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md)). Information disclosure similarly turns out to mostly extend the existing `misconfig.Detector` rather than needing a new package — its "internal IPs/hostnames/stack traces" detection already exists as `VerboseErrorPatterns`/`checkVerboseErrors`, built in Phase 1b. So Weeks 13-17 are mostly template curation and small built-in-rule extensions, not three more detector modules — the same "measure the real shape before assuming a bigger build" discipline Phase 1b's own Future Enhancements repeatedly demonstrated (see doc10's extractor-DSL-binding note for the clearest example: an initial "250+ templates" guess collapsed to 1 once actually measured).

**A doc inconsistency worth naming, not silently fixing here:** doc01 groups "API-Specific Auth Issues" under a "Phase 1: Foundation (Weeks 1-10)" heading, but doc03 — the roadmap Phase 1a/1b's real implementation actually followed, which shipped only IDOR + Misconfiguration — schedules it at Week 11-12 under Phase 2. This plan treats doc03 as authoritative, consistent with how Phase 1a/1b were actually built. doc01's heading is stale and worth a future correction pass, but rewriting doc01 isn't this plan's job.

## Scope

Six chunks, matching doc03's Week 11-18 breakdown, plus one carried-forward gap from `follow-up.md` that this phase is the natural point to close:

0. ✅ **Scope enforcement** (Week 11-12, alongside Step 1) — a `--scope` allow-list validated before a target is dispatched. Not in doc03's text; carried forward from `follow-up.md` §1's Critical finding, still open since Phase 1.
1. ✅ **API Auth Bypass Detector** (Week 11-12)
2. ✅ **XSS Detection** (Week 13-14)
3. ✅ **SQL Injection Detection** (Week 15-16)
4. ✅ **Information Disclosure** (Week 17)
5. 🟡 **Testing & Release** (Week 18) — v0.2.0 — live verification done (2026-08-28), real results below; success metrics not fully met, `v0.2.0` not yet tagged

(✅ = implemented, unit-tested, and live-verified as of 2026-08-28 — see each step's own dated note below.)

**Explicitly deferred, named rather than silently dropped:**
- **DOM-based XSS via Chromedp** (doc03 marks it "Optional" for Week 13-14). Passive/reflected detection via the existing template engine covers the bulk of realistically findable XSS; Chromedp adds a new dependency, the sandboxing requirement `follow-up.md` §4 calls for (isolated container, no filesystem/network egress beyond the target, resource limits), and real engineering cost for a smaller slice of real-world findings. Revisit as its own future item once Phase 2's template-driven XSS work is live and its real yield is measured — same "prove the smaller thing first" pattern as Phase 1b's Future Enhancements.
- **Boolean-based SQLi** (doc03: "if time allows"). Error-based detection (Step 3) is the primary deliverable; boolean-based (time-based blind confirmation) stays optional, not required for this step's Definition of Done.
- **Rate Limiting Bypass, as doc03 literally describes it** ("rapid credential brute force without throttle") is **not built as described** — see Step 1's design note below for why and what replaces it.

Dev environment (macOS + WSL2/Windows 11) is already covered by [04-environment-and-testing.md](04-environment-and-testing.md); this plan assumes that setup is done, same as doc09/doc10.

## Dependencies used in this plan

One new dependency: **`github.com/golang-jwt/jwt/v5`** (verified via pkg.go.dev on 2026-08-27: latest stable is `v5.3.1`, published 2026-01-28; 15,000+ known importers, API stable since the v5 rework) — needed for Step 1's JWT decode/tamper/verify (parsing claims/header, testing `alg: none`, locally verifying candidate HS256 secrets). No hand-rolled JWT parsing — this is exactly the kind of well-established, single-purpose library doc02's "minimal dependencies" policy allows adding when a real need appears, same precedent as `golang.org/x/time` being added in Phase 1a for rate limiting.

No new dependency for Steps 2-3 (XSS/SQLi) — both reuse the existing `pkg/template/{matcher,extractor,dsl}` engine and `raw:`/`payloads:` support (Phase 1b Future Enhancement #1) via curated template content, not new Go code. Step 4 (info disclosure) extends `pkg/detectors/misconfig` in place — no new package, no new dependency.

Chromedp (`github.com/chromedp/chromedp`, listed as optional in doc02) is **not** added in this plan — see Scope's deferral note above.

---

## Step 0: Scope enforcement (`--scope` allow-list) (Week 11-12) — ✅ implemented (2026-08-28)

**Goal:** close `follow-up.md` §1's Critical finding — "No technical scope-enforcement mechanism. The Input Parser design (doc 02) has no described allow-list/scope-file validation." — before Phase 2 starts running more stateful, sequenced checks (auth bypass) against a wider target set than Phase 1's lab-only usage.

**Design tradeoff, stated explicitly rather than silently resolved either way:** `follow-up.md` recommends a scope file "on by default." But every existing documented lab-target workflow (README, [20-setup-testing-targets.md](20-setup-testing-targets.md), [21-scanning-real-targets.md](21-scanning-real-targets.md)) points `hackerfive` at `localhost`/`127.0.0.1` with no `--scope` flag at all — making it mandatory would break every one of those documented commands. Resolution: `--scope` is **optional**. When given, it's strictly enforced — default-deny, any target not matching an entry is skipped (not scanned, not silently included) with a one-line stderr note per skipped target. When omitted, scanning proceeds unrestricted exactly as today, but `hackerfive` prints a one-line stderr warning (`"no --scope file provided — all targets will be scanned without authorization-scope validation"`) once per run, so a real-target run without scoping is visibly, not silently, unguarded.

### Files

| File | Purpose |
|---|---|
| `pkg/scanner/scope/scope.go` (new) | `Scope` type, `Parse(path string) (*Scope, error)`, `(*Scope) Allowed(target string) bool` |
| `pkg/scanner/config.go` | New `Config.ScopeFile string` field (from `--scope`) |
| `pkg/scanner/engine.go` | `Engine.Run` checks `Allowed(target)` before submitting each target to the worker pool; skipped targets logged, not silently dropped |
| `cmd/hackerfive/scan.go` | New `--scope` flag |
| `tests/unit/scope_test.go` (new) | Domain exact-match, `*.example.com` glob-suffix match, CIDR match (`net.ParseCIDR`), malformed-line handling, empty-file/omitted-flag behavior |

### Key types/functions

`Scope.Parse` reads one entry per line — blank lines and `#`-prefixed comments ignored (same convention as `--targets`' file-or-literal handling in `cmd/hackerfive/scan.go`'s `resolveTargets`). Each line is either a bare/glob domain (`example.com`, `*.example.com` — suffix match, no full glob library needed) or a CIDR (`10.0.0.0/8`, parsed via stdlib `net.ParseCIDR`). `Allowed(target string)` parses `target` as a URL, checks its host against every domain entry (exact or suffix match) and every CIDR entry (if the host is a literal IP) — first match wins, otherwise denied.

Natural tie-in, not built as new code here: a `--scope` file's content can be hand-derived from [22-authorized-targets.md](22-authorized-targets.md)'s existing registry — that doc stays the source of truth for *which* targets are authorized; `--scope` is just the mechanical enforcement of a list a human already curated.

### Verification

```bash
wsl.exe -e bash -lc "cd /mnt/c/ML-Projects/Weekend-Projects/hacker-five && go build ./... && go vet ./... && go test ./... -race && PATH=\$PATH:\$HOME/go/bin golangci-lint run ./..."
```
Unit tests cover the matching rules directly; no live target needed. Confirm existing documented lab-target commands (README, doc20) still work unmodified with `--scope` omitted, and that a deliberately-mismatched `--scope` file causes a target to be skipped rather than scanned.

**Implemented as designed**, no deviations: `pkg/scanner/scope/scope.go`, wired into `Config.ScopeFile`/`Engine.loadScope`/`Engine.Run`, `--scope` flag in `cmd/hackerfive/scan.go`. `tests/unit/scope_test.go` (7 cases: exact domain, `*.`-wildcard including the wildcard's own base domain, CIDR, comments/blank lines, missing file, default-deny on an unmatched target) plus two `Engine`-level tests in `tests/unit/engine_test.go` (`TestEngineRun_ScopeFile_BlocksUnmatchedTarget`/`AllowsMatchedTarget`) confirming `Run` actually wires enforcement in, not just that `scope.Allowed` works in isolation. `go build`/`vet`/`test -race`/`golangci-lint` all clean. **Not yet live-verified with `--scope` actually set** (only confirmed lab-target commands still work with `--scope` omitted, per Step 5's other live runs) — running with a real `--scope` file derived from [22-authorized-targets.md](22-authorized-targets.md) is still open, tracked in Step 5.

---

## Step 1: API Auth Bypass Detector (Week 11-12) — ✅ implemented, live-verified (2026-08-28)

**Goal:** a new detector, peer to `idor`/`misconfig` (doc02's architecture diagram already lists Auth Bypass as a peer Scanner Engine module) — genuinely needs custom Go logic (JWT manipulation, multi-step request sequencing) the template engine can't express, unlike Steps 2-3 below.

**The roadmap's literal "Rate Limiting Bypass: rapid credential brute force without throttle" is not built as described.** `follow-up.md` §1 flags this as a Critical risk: repeated credential guessing against a live target can lock real accounts, directly in tension with CLAUDE.md's read/enumerate-only rule — the same tension doc10's `DefaultCredRule` design note already resolved once, for default-credential checking (fixed list, single pass, never retried). This detector applies the identical discipline to the rate-limit check: a small, fixed number of requests (e.g. 10) against a login endpoint using **one** known-invalid credential — never a real credential-guessing sequence — just to observe whether `429`/`Retry-After` appears at all. It proves the *absence* of throttling, not a brute-force attempt, and needs no destructive-mode flag because it's read/enumerate-only by construction, same as everything else this project ships.

**Checks:**
- **Missing authentication** — a configured protected endpoint accepts a request with no `Authorization` header at all and returns `200` instead of `401`/`403`.
- **JWT `alg: none` / signature-stripping bypass** — given a real, valid JWT (from `--auth-token`), decode it via `golang-jwt/jwt/v5`, rewrite the header to `alg: none` (or strip the signature segment entirely), refire the same request with the tampered token, flag if it's still accepted.
- **JWT weak-secret dictionary check — offline only.** Decode the JWT's claims/header locally, then try a small, fixed wordlist of well-known-weak HS256 secrets (`secret`, `changeme`, `your-256-bit-secret`, etc. — mirrors `DefaultCreds`' "capped, fixed list" shape) by verifying the signature **locally** against each candidate key via `jwt.Parse`. Zero requests sent to the server for this check — explicitly required by `follow-up.md`'s own note: "JWT weak-secret dictionary check is offline, not live guessing — worth stating explicitly in the docs so a future contributor doesn't implement it as online brute force against the live server."
- **Rate-limit signal** — the redesigned bounded check described above.
- **Token reuse across accounts** — reuses IDOR's two-account baseline shape (`ownerToken`/`otherToken`, already in `scanner.Config`): fire a request to an identity-scoped endpoint (e.g. `/me`, `/profile`) with account A's token, confirm it returns account A's identity; same endpoint pattern with account B's token must return account B's identity, not account A's — flags if a token resolves to the wrong account.
- **Broken session (logout-then-reuse)** — fire a logout request, then re-fire one previously-authenticated request with the same token; flag if it's still accepted.

**Open implementation detail, now resolved:** the missing-auth check's candidate protected-path list is supplied via a new `--protected-paths` flag (comma-separated, parsed the same way `--tags` is) — the simpler of the two options this plan originally left open, chosen over a new native-template tag since it needs no new template-engine mechanism and mirrors `--endpoint`'s existing shape. `Config.Validate()` requires it (like idor's `--endpoint`) when `--detector authbypass` is selected. Still no real recon happened (no live crAPI/vAPI access in this session) — the path list itself is user-supplied at scan time, same as `--endpoint` always has been, so this doesn't block implementation the way a hardcoded path guess would have.

**Token-reuse design correction, found by the test suite, not assumed correct up front:** the plan below originally said this check would reuse `idor.Signature`'s fuzzy (size-tolerance + keyword-set) comparison. A test using two different accounts' same-size JSON responses (`{"user":"owner","email":"..."}` vs `{"user":"other","email":"..."}`) proved that tolerance too coarse — both responses landed inside idor's 5%-size/same-keyword-set fallback and were wrongly reported as "identical," which would make this check flag real, correctly-personalized endpoints as bugs. Fixed by comparing raw response bytes directly instead of `idor.Signature` — deliberately higher precision than IDOR's own comparison, since a false positive here (telling a user their app has an auth bug it doesn't have) is worse than the false negative idor's tolerance is designed to avoid. `pkg/detectors/authbypass` no longer imports `idor` at all as a result.

### Files

| File | Purpose |
|---|---|
| `pkg/detectors/authbypass/detector.go` (new) | `Detector` (client, `hosterrors.Cache` — same shape as `idor.Detector`/`misconfig.Detector`), `New`, `Run(ctx, target, ownerToken, otherToken string) ([]detectors.Finding, error)` |
| `pkg/detectors/authbypass/jwt.go` (new) | JWT decode/tamper/local-verify helpers built on `golang-jwt/jwt/v5` |
| `pkg/detectors/authbypass/rules.go` (new) | `WeakJWTSecrets []string` — small, fixed wordlist, same shape as `misconfig.DefaultCreds` |
| `pkg/scanner/engine.go` | New `case "authbypass":` in `runDetector`, mirroring the existing `idor`/`misconfig` cases |
| `pkg/scanner/config.go` | `recognizedDetectors` gains `"authbypass"`; `Validate()` gains its required-flag checks (mirrors idor's auth-token requirement) |
| `cmd/hackerfive/scan.go` | `--detector authbypass` becomes a valid value; new flag for the protected-path list once the open question above is resolved |
| `tests/unit/detector_authbypass_test.go` (new) | Table-driven against `httptest.Server`, 12 cases (hit + no-finding pair per check) |
| `tests/integration/authbypass_crapi_test.go` / `authbypass_vapi_test.go` | **Not yet created** — deferred until real recon against a live crAPI/vAPI instance is actually possible (see Verification below); doc10/doc11's own precedent is to write the live integration test alongside real recon, not guess its shape blind |

### Key types/functions

`Detector` mirrors `idor.Detector`'s shape exactly (`client *httpclient.Client`, `hostErrors *hosterrors.Cache`, `New`, `Run`) — same constructor/lifecycle convention as every other built-in detector, no new pattern invented. Each check follows the existing `checkX(ctx, target, host, ...) ([]detectors.Finding, error)` shape `misconfig.Detector` already establishes, registered in a `checks` slice inside `Run`, same as `misconfig.Detector.Run`'s `checks` slice.

`Finding.Evidence` uses the existing `detectors.FormatRequest`/`FormatResponse` helpers (`pkg/detectors/evidence.go`, Phase 1b Future Enhancement #7) for consistent, redacted request/response capture — no new evidence-formatting code needed.

### Verification

```bash
wsl.exe -e bash -lc "cd /mnt/c/ML-Projects/Weekend-Projects/hacker-five && go build ./... && go vet ./... && go test ./... -race && PATH=\$PATH:\$HOME/go/bin golangci-lint run ./..."
```
Unit tests prove each check's logic against a mock server (JWT tampering correctness, rate-limit-signal request count staying fixed/capped, token-reuse cross-account detection). Live verification against crAPI/vAPI happens in the user's native clone, same "confirm live once code exists" pattern as every Phase 1b Future Enhancement in this session.

**Implemented**: `pkg/detectors/authbypass/{detector,jwt,rules}.go`, wired into `scanner.Config`/`Engine.runDetector` (new `case "authbypass"`) and `cmd/hackerfive/scan.go` (`--detector authbypass`, `--protected-paths`). `checkBrokenSession` is deliberately last in `Run`'s checks slice — it ends the real session `ownerToken` refers to, which would otherwise poison every check after it that still needs that token valid within the same `Run` call; a mutation this bounded (one non-retried logout) follows the same precedent `misconfig.DefaultCredRule`'s single login POST already established. `go build`/`vet`/`test -race`/`golangci-lint` all clean, 12 new unit tests pass (including one proving `checkJWTWeakSecret` makes exactly zero extra network requests beyond what `checkRateLimitSignal`'s login-path discovery already makes — the offline-only property `follow-up.md` requires, locked in by an assertion, not just a comment).

**Live-verified (2026-08-28), see [20-setup-testing-targets.md](20-setup-testing-targets.md)'s crAPI/vAPI sections for full detail and commands**: **crAPI — 2 real critical findings**, `alg: none` JWT bypass on `/identity/api/v2/user/dashboard` and `/identity/api/v2/vehicle/vehicles` — independently confirmed with a hand-built tampered token via `curl` outside the tool, and cross-checked that a garbage token is correctly rejected, so this is genuine signal, not a detector bug. **vAPI — 1 low-confidence finding** (`authbypass-no-rate-limit-login`), correctly self-flagged as needing manual triage; every other check on both targets correctly found nothing, including two genuine architectural mismatches this run surfaced (not bugs — both need a deliberate follow-up decision, not a silent fix):
- **`LoginPaths`/`LogoutPaths` (rules.go) are fixed, generic guesses** (`/login`, `/api/login`, `/auth/login`, and the `/logout` equivalents) that match neither crAPI's real login path (`/identity/api/auth/login`, and crAPI has no server-side logout at all — stateless JWT) nor vAPI's (`/vapi/api2/user/login`, `/vapi/api4/login`, etc. — several different per-challenge login routes, none at a bare path). `checkRateLimitSignal`/`checkBrokenSession` are effectively no-ops against both of this project's own two auth-bypass lab targets as shipped. **Recommendation**: make these configurable (e.g. `--login-paths`/`--logout-paths`, mirroring `--protected-paths`) rather than hardcoded, since no fixed guess will match every real target's routing.
- **`authbypass.Detector` only sends `Authorization: Bearer <token>`** (`doRequestBody`, hardcoded) — `idor.Detector` already solved this exact problem for a different target (vAPI's `Authorization-Token: base64(...)` scheme) via `WithAuthHeader`/`--auth-header-name`/`--auth-header-format` (Phase 1b Future Enhancement #6). `authbypass`'s token-reuse and broken-session checks can't meaningfully test any target using a non-Bearer scheme until it gets the same option. **Recommendation**: extend `authbypass.Detector` with the identical `idor.Option`-style auth-header configuration, not a new mechanism.

Two auth-bypass integration tests (`tests/integration/authbypass_crapi_test.go`/`authbypass_vapi_test.go`) are still **not created** — this session's verification was done via ad-hoc `./hackerfive scan` runs against the live targets (fast, real, and what actually found the crAPI critical findings), not via a checked-in Go test; writing the two integration tests, now that real recon has happened and the right protected-paths/login-paths are known, is tracked in Step 5.

---

## Step 2: XSS Detection (Week 13-14) — ✅ implemented, live-verified (2026-08-28) — real yield is 0, see note below

**Goal:** passive/reflected XSS detection via curated templates, not a new Go package — per doc01's own "start with passive detection (build on Nuclei patterns)" scoping, and because Phase 1b's `raw:`/`payloads:` support (Future Enhancement #1) plus the existing word/regex matcher engine already provide everything a reflected-XSS check needs: inject a payload marker into a request (query param, common body field) via `payloads:`, check whether that marker reflects back **unescaped** in the response body via a word/regex matcher.

**Real upstream source confirmed, not assumed:** the sync script (`scripts/sync-nuclei-templates.sh`) currently only checks out `http/exposed-panels`, `http/misconfiguration`, `http/technologies` — none contain XSS templates. Verified directly against the upstream repo that real, generic (non-product-specific) reflected-XSS templates exist at **`http/vulnerabilities/generic/`** — `xss-uri-reflected.yaml`, `top-xss-params.yaml` — the same category `cors-misconfig.yaml` (one of Phase 1b's original four permanent samples) already came from. This step needs the sync script's `CATEGORIES` array widened to include `http/vulnerabilities/generic` and re-run against the **already-pinned commit** (`0aa256a344d5b53648575163c61517ac67f57961`) — no re-pin needed, per doc10's "explicit re-pin only" discipline; confirm these specific files still exist at that pinned commit before relying on them.

### Files

| File | Purpose |
|---|---|
| `scripts/sync-nuclei-templates.sh` | `CATEGORIES` array gains `"http/vulnerabilities/generic"` |
| `templates/nuclei-samples/xss/` (new directory) | Curated, real, unmodified-where-possible templates picked the same way `dvwa-php/`/`crapi/`/`juice-shop/` were — reconning a real target first (DVWA/Juice Shop both have known reflected-XSS-friendly parameters), not guessed blind. Each with its own README documenting what fired live and why, same convention as every existing `templates/nuclei-samples/*/README.md` |
| `docs/template-writing-guide.md` | New section on writing a reflected-XSS template: payload marker convention, unescaped-reflection matcher pattern |

### Key design notes

No new Go code is assumed here — any real gap (a DSL function or matcher shape a real upstream XSS template needs but this project doesn't yet support) gets measured against real templates first and closed the same way Phase 1b's Future Enhancements were: read the real template, confirm the exact blocker, fix precisely that, not a guessed-broader feature. This step's actual file list may grow by exactly what that measurement finds, mirroring how Phase 1b's `compare_versions()`/`base64_decode()` additions were sized to real corpus data, not estimated upfront.

**Explicitly out of scope for this step:** DOM-based XSS validation via Chromedp (see Scope's deferral note above) — named here again so it isn't silently forgotten once this step ships.

### Verification

```bash
wsl.exe -e bash -lc "cd /mnt/c/ML-Projects/Weekend-Projects/hacker-five && go build ./... && go test ./... -race"
```
Plus a regression test mirroring `tests/unit/nuclei_dvwa_php_samples_test.go`'s pattern (load-correctness only) for the new `xss/` directory, and a live run against DVWA/Juice Shop once templates are drafted — real finding count reported once measured, not assumed in advance.

**Implemented**: fetched `xss-uri-reflected.yaml`/`top-xss-params.yaml` directly from `raw.githubusercontent.com` at the pinned commit (verified both exist there before relying on them, rather than assuming the earlier upstream-repo confirmation still held at this exact SHA), read both fully to confirm every field they use (`part: content_type`, `part: header`, `negative: true`, `stop-at-first-match`) is already supported — no new Go code was needed, matching this step's own prediction. `scripts/sync-nuclei-templates.sh`'s `CATEGORIES` widened. New `templates/nuclei-samples/xss/` + README, `tests/unit/nuclei_xss_samples_test.go` (load-correctness, passes).

**Live-verified (2026-08-28), real yield is 0 findings against both DVWA and Juice Shop — recorded honestly, not padded, same discipline as Phase 1b's DVWA misconfig number.** Root cause fully diagnosed, not just observed (see [20-setup-testing-targets.md](20-setup-testing-targets.md)'s DVWA/Juice Shop sections for the exact commands and evidence): these two curated templates test whether a path segment appended to `{{BaseURL}}` reflects unescaped, a real technique for apps that echo unmatched routes, but a different shape than DVWA's/Juice Shop's actual bugs (named query params, `?name=`). Separately confirmed the matcher/DSL logic itself is correct — not just "the templates found nothing so maybe the engine is broken" — by hand-building a throwaway, uncommitted template pointed at DVWA's real `?name=` param with a manually-obtained session cookie; it correctly flagged the live, unescaped reflection. The engine works; these two specific curated templates just don't happen to test DVWA's/Juice Shop's actual vulnerable shape, and (for DVWA) couldn't reach it even if they did — see Step 5 for why and what closing this gap would take.

---

## Step 3: SQL Injection Detection (Week 15-16) — ✅ implemented, live-verified (2026-08-28) — real yield is 0, see note below

**Goal:** error-based SQLi detection via curated templates, same template-driven approach as Step 2 — per doc01's "template-based patterns + error matching" scoping. Inject common SQLi payloads (via `payloads:`), match on known DB-error-message signatures in the response body — the same "match a known signature in the body" mechanism `misconfig.Detector`'s `VerboseErrorPatterns`/`checkVerboseErrors` (Phase 1b) already proved out, just applied to injected-payload responses instead of a malformed-query probe.

**Same upstream source as Step 2**: `error-based-sql-injection.yaml` (29-database-engine error-signature matcher) also lives at `http/vulnerabilities/generic/`, confirmed alongside the XSS templates above — one sync-script category change covers both steps.

### Files

| File | Purpose |
|---|---|
| `templates/nuclei-samples/sqli/` (new directory) | Curated real templates, same recon-first, documented-README convention as every other `templates/nuclei-samples/*/` batch |

**Boolean-based SQLi** (time-based blind confirmation) stays optional per doc03's own "if time allows" wording — not required for this step's Definition of Done; revisit only if error-based detection's real yield against DVWA/Juice Shop turns out too low to be useful on its own.

### Verification

Same shape as Step 2: build/vet/test clean, a load-correctness regression test for the new template directory, live finding count measured (not assumed) once templates are drafted and run against a real lab target.

**Implemented**: fetched `error-based-sql-injection.yaml` from the pinned commit alongside Step 2's files. Reading it fully mattered here — a naive reading of `matchers-condition: and` across every named `type: regex` entry in the file would wrongly conclude the template could never realistically fire (dozens of different DB-engine regexes could never all match one response simultaneously). The real structure: `matchers:` is only 2 entries (an Adminer-panel false-positive exclusion, and one matcher whose own regex list is internally OR'd across ~30 engines); everything past that — the per-engine named entries — is `extractors:`, used only to report *which* engine matched, not to gate the finding. Documented this explicitly in `templates/nuclei-samples/sqli/README.md` so the next reader doesn't have to re-derive it. New `templates/nuclei-samples/sqli/` + README, `tests/unit/nuclei_sqli_samples_test.go` (load-correctness, passes).

**Live-verified (2026-08-28), real yield is 0 findings against both DVWA and Juice Shop** — same root cause as Step 2's XSS templates (path-appended payload vs. named-query-param bug, plus DVWA's session-cookie wall). Also separately confirmed sound: the same manual, uncommitted-template verification against DVWA's real `?id=` SQLi param produced the actual MariaDB error text, and the checked-in template's regex (`check the manual that (corresponds to|fits) your MariaDB server version`) matches it — the matcher would have fired had it been reachable. See Step 5 and [20-setup-testing-targets.md](20-setup-testing-targets.md)'s DVWA section for full detail.

---

## Step 4: Information Disclosure (Week 17) — ✅ implemented, live-verified (2026-08-28)

**Goal:** mostly extends `pkg/detectors/misconfig`, not a new package — "internal IPs/hostnames/stack traces" is already `VerboseErrorPatterns`/`checkVerboseErrors` from Phase 1b. Real remaining scope is narrower than doc01's full list suggests:

- **"Commented code in responses"** — genuinely new: a new built-in rule table for common debug leftovers inside actual HTML comments (`<!-- TODO -->`, a commented-out `<script>` block, a credential-shaped word inside a comment, etc.), checked the same way `VerboseErrorPatterns` is — a new `CommentLeakPatterns []string` + `checkCommentLeaks`, following `checkVerboseErrors`'s exact shape. (A bare, non-comment-anchored `console.log(` pattern was considered and dropped during implementation — see the dated note below.)
- **"API responses leaking unnecessary fields"** (internal IDs, timestamps, role info) — **not** built as a generic built-in rule here. What counts as "unnecessary" is inherently target-specific (an internal `_id` field is expected in one API's contract and a leak in another's) — a fixed keyword list would either miss real cases or false-positive constantly. Documented instead as a **template-writing-guide pattern**: a `dsl:` matcher checking for specific, known-sensitive JSON field names, written per-target the same way `templates/idor/*.yaml` are per-target today, not a generic built-in.

### Files

| File | Purpose |
|---|---|
| `pkg/detectors/misconfig/rules.go` | New `CommentLeakPatterns []string` |
| `pkg/detectors/misconfig/detector.go` | New `checkCommentLeaks`, registered in `Run`'s `checks` slice alongside the other seven |
| `tests/unit/detector_misconfig_test.go` | New test cases mirroring `TestMisconfigVerboseError_Matched`'s pattern |
| `docs/template-writing-guide.md` | New section: writing a per-target "sensitive field in response" template |

### Verification

```bash
wsl.exe -e bash -lc "cd /mnt/c/ML-Projects/Weekend-Projects/hacker-five && go build ./... && go vet ./... && go test ./... -race && PATH=\$PATH:\$HOME/go/bin golangci-lint run ./..."
```
Same pattern as Phase 1b's Future Enhancement #4 (directory-listing check) — new unit tests prove the mechanism; live re-verification against DVWA/Juice Shop happens once code exists, reported honestly rather than assumed.

**Implemented, one deliberate narrowing from this plan's original example list**: `CommentLeakPatterns` dropped the bare `console.log(` pattern this doc originally proposed (copied from doc03's own Week 17 wording) — every pattern actually shipped is anchored to being inside an HTML comment (`<!--...`), not a bare substring match anywhere in the body. A plain `console.log(` match has no such anchor and would fire on essentially any JS-heavy production site (any bundled library that logs anything), which is a real false-positive generator, not a genuine "debug leftover" signal — caught during implementation, not measured against a live target, but a design-time call clear enough not to need one (this project's own `<5%` FP goal is the reason, not a guess). `checkCommentLeaks` fetches target root only (no principled path list exists for "where a leftover comment might be," unlike `ExposedPaths`), registered as the 3rd of 8 `misconfig.Detector` checks. `pkg/detectors/misconfig/{rules,detector}.go` updated, `tests/unit/detector_misconfig_test.go` gained a hit case (a real `<!-- TODO -->`) and a false-positive-safety case (a bare `console.log(` outside any comment, confirming the narrowing actually holds). **Live-verified (2026-08-28)**: 0 findings against both DVWA and Juice Shop root — neither's actual HTML comments (DVWA has a commented-out `<img>` and structural `<div>` comments; Juice Shop has none at root) match `CommentLeakPatterns`' anchored patterns, correctly not flagged. No false positive, but also no true positive yet demonstrated live — both targets' real comments are genuinely benign, so this check's real-world value is still unproven against a target that actually has a leftover debug comment.

---

## Step 5: Testing & Release (Week 18) — 🟡 live verification done (2026-08-28); success metrics not fully met; `v0.2.0` not yet tagged

**What actually happened, not the pre-verification plan:** an earlier draft of this doc (and this section) claimed live verification was blocked by "no Docker on this Windows checkout." That was never actually checked — it was carried forward as an assumption. It's wrong: the user's native WSL2 clone (`~/projects/hacker-five`) is reachable from this same session via `wsl.exe` exactly like the `/mnt/c` mount already used for build/vet/test/lint, and Docker was already running there with crAPI, vAPI, DVWA, and Juice Shop all up (some for several days). Once that was corrected, this step ran for real: `git pull` to bring the native clone to `3b7e8a1`, rebuild, then live scans against all four targets. Full commands and evidence live in [20-setup-testing-targets.md](20-setup-testing-targets.md)'s per-target sections; this section is the honest roll-up against doc03's Success Metrics.

### Phase 2 Success Metrics (doc03) — measured, not assumed

| Metric (doc03 target) | Real result (2026-08-28) | Verdict |
|---|---|---|
| Auth bypass: 10+ issues (crAPI/vAPI) | **3 with default settings** — 2 critical (crAPI `alg: none` JWT bypass, independently verified with a hand-built token via `curl`), 1 low-confidence (vAPI rate-limit-signal, artifact of a path mismatch). **More real findings confirmed once the three fixes below were applied** (2 vAPI token-reuse findings via the auth-header fix, a correctly-targeted crAPI rate-limit finding via `--login-paths`) — but not yet cleanly re-measured as one combined, final total across both targets with every override applied together, so this row still shows the baseline number rather than an estimate | **Not met** at baseline; real ceiling with the fixes applied is higher but not yet precisely counted — root cause below, not a detector-quality problem |
| XSS: 20+ issues (DVWA/Juice Shop) | **0** | **Not met.** Detection logic separately proven correct (manual verification against live vulnerable output); the two shipped generic templates don't reach either target's actual bug shape |
| SQLi: 10+ issues (DVWA/Juice Shop) | **0** | **Not met.** Same as XSS — logic proven correct, reachability is the blocker |
| False-positive rate <5% | Not re-measured this session (`scripts/measure-fp-rate.sh` not yet extended to the three new checks) | Not done |

**This is a real shortfall, recorded honestly per this project's own "revise down with reasoning, don't pad" discipline (same as Phase 1b's DVWA misconfig number)** — not something to quietly work around. Every one of the three gaps below is well-understood, not mysterious, and each has a concrete, scoped fix:

1. **`LoginPaths`/`LogoutPaths` are fixed, generic guesses that match neither lab target's real routes.** crAPI's real login is `/identity/api/auth/login` (and it has no server-side logout — stateless JWT); vAPI's are per-challenge (`/vapi/api2/user/login`, `/vapi/api4/login`, etc.). `checkRateLimitSignal`/`checkBrokenSession` are effectively no-ops against both of this project's own lab targets today. This alone explains most of the auth-bypass shortfall — `checkMissingAuth`/`checkJWTAlgNone`/`checkJWTWeakSecret`/`checkTokenReuse` don't depend on these lists and worked correctly (that's how the 2 real crAPI findings were found).
2. **`authbypass.Detector` hardcodes `Authorization: Bearer <token>`**, unlike `idor.Detector`, which already has a configurable auth-header scheme (`--auth-header-name`/`--auth-header-format`, Phase 1b Future Enhancement #6) specifically because vAPI needs it. Token-reuse/broken-session can't meaningfully test vAPI (or any non-Bearer target) until `authbypass` gets the same option.
3. **The XSS/SQLi templates test the wrong location, and nuclei-format templates can't carry a credential at all.** The two curated upstream templates (`xss-uri-reflected.yaml`, `error-based-sql-injection.yaml`) probe path-appended payloads; DVWA's/Juice Shop's real bugs are in named query params. Even a correctly-shaped template couldn't reach DVWA's pages regardless, since they're gated behind a session cookie and `pkg/template/nuclei`'s executor has no mechanism to inject any CLI-supplied header/cookie into a request — only `pkg/template/native` gets `AuthToken`/`OtherAuthToken`, for `idor`-tagged templates specifically.

**All three fixed and live-verified (2026-08-28), same session, after explicit user request:**
- **`--login-paths`/`--logout-paths` flags** (`scanner.Config.LoginPaths`/`LogoutPaths` → `authbypass.WithLoginPaths`/`WithLogoutPaths`, same `Option`-func shape as `idor.Detector`). Live-verified against crAPI with `--login-paths '/identity/api/auth/login'`: the rate-limit-signal check now correctly reaches the real endpoint (`authbypass-no-rate-limit-identity-api-auth-login`, evidence shows the request actually hitting `/identity/api/auth/login`) instead of the previous vacuous `/login` 404. **A new, separate nuance surfaced by this same live run, not silently glossed over**: crAPI's real login expects a JSON body; `checkRateLimitSignal` sends a fixed form-encoded (`application/x-www-form-urlencoded`) body, so the real endpoint returns `415 Unsupported Media Type` rather than a real invalid-credential rejection — the path is now correct, but the request shape still isn't a fully faithful rate-limit probe against a JSON-only API. Not fixed in this pass (a different, smaller gap than the one requested); tracked as a further follow-up below.
- **`authbypass.Detector` auth-header scheme** (`WithAuthHeader`, identical shape/semantics to `idor.Detector.WithAuthHeader`; `scanner.Engine` now applies the same `--auth-header-name`/`--auth-header-format` flags to both idor and authbypass). Live-verified against vAPI with `--auth-header-name 'Authorization-Token' --auth-header-format '{token}'`: `checkTokenReuse` now fires two real findings (`authbypass-token-reuse-api1-user-5`/`-6`) — `/vapi/api1/user/{id}` returns identical content regardless of which account's token is used, the same underlying BOLA the IDOR detector already found, now also caught through auth-bypass's own lens. Before this fix, every token-reuse/broken-session check against vAPI silently found nothing, not because vAPI was safe but because every request carried a header vAPI's real auth middleware doesn't recognize at all.
- **`--header 'Name: Value'` flag** (repeatable, `scanner.Config.ExtraHeaders` → `nuclei.Executor.WithHeaders`/`native.Executor.WithHeaders`, applied before a template's own `Headers:` map so the template still wins on a literal name conflict). Live-verified end-to-end against DVWA: a throwaway, uncommitted verification template targeting the real `?id=` SQLi param (no cookie baked into the template itself) fired correctly when run with `--header "Cookie: PHPSESSID=...; security=low"` supplying a real, freshly-obtained DVWA session cookie purely via the CLI flag — proving the mechanism reaches a real target, not just a mock server.

All three are also covered by new unit tests (`tests/unit/detector_authbypass_test.go`'s `TestAuthBypassLoginPaths_Override`/`TestAuthBypassLogoutPaths_Override`/`TestAuthBypassAuthHeader_Override`, `tests/unit/nuclei_executor_test.go`'s `TestExecutorRun_WithHeaders_AppliedToRequest`/`TestExecutorRun_WithHeaders_TemplateHeaderWins`, `tests/unit/native_executor_generic_test.go`'s `TestNativeExecutorRun_WithHeaders_AppliedToRequest`, `cmd/hackerfive/scan_test.go`'s `TestParseHeaders_*`) — 9 new tests, each asserting the fix actually changes request behavior (e.g. a mock server that only serves content when it sees the overridden header/path), not just that the option compiles. `go build`/`vet`/`test -race`/`golangci-lint` all clean after.

**Remaining, smaller follow-up not done this pass** (surfaced by the crAPI live-verification above, a different gap than what was fixed): `checkRateLimitSignal`'s form-encoded probe body doesn't match JSON-only APIs like crAPI's — would need either a `--login-body-format` option or content-type sniffing to send a real invalid-credential JSON payload instead. Writing real DVWA-specific/Juice-Shop-specific XSS/SQLi templates (using `--header` for the session cookie, targeting the actual known-vulnerable query params) is also still open — the mechanism to build them now exists and is proven, but the templates themselves haven't been written, so doc03's 20+/10+ XSS/SQLi metrics are still not re-measured as of this note.

**Also fixed along the way, not a Phase 2 design decision — a pre-existing doc bug:** [20-setup-testing-targets.md](20-setup-testing-targets.md)'s vAPI IDOR example was missing the `/vapi` path prefix vAPI's real routes all require (confirmed from vAPI's own Postman collection) — as written, it would have 404'd. Corrected, and the corrected command live-verified: **6 real IDOR findings** (account `hf_other`'s token reads every other account's data via `/vapi/api1/user/{id}`), closing out a "not yet live-verified" gap that predates Phase 2.

- False-positive rate re-measurement (`scripts/measure-fp-rate.sh` extended to the three new checks) — **not done this session**, tracked as remaining Step 5 work.
- `v0.2.0` release reuses the existing `goreleaser`/CI pipeline built in Phase 1b — no new packaging work needed; `.goreleaser.yml`'s `templates/**/*` bundling (Step 5 release follow-up, doc10) already picks up the new `xss/`/`sqli/` template directories automatically. **Not yet tagged** — holding until the Success Metrics gap above is either closed or explicitly accepted as Phase 2's real, honest ceiling (same kind of call Phase 1b made for DVWA's misconfig number).
- The two `tests/integration/authbypass_{crapi,vapi}_test.go` integration tests are still not created — this session's verification used ad-hoc `./hackerfive scan` runs instead, which is what actually found the real findings, but the checked-in regression tests remain open work.

**Dev-time verification stays lab-only, deliberately.** [22-authorized-targets.md](22-authorized-targets.md)'s real, authorized targets (`a2x.io`, `abc8.immobilien`) are for actual bug-hunting once this phase ships (that's what [21-scanning-real-targets.md](21-scanning-real-targets.md)/doc22 exist for), not a substitute for this step's DVWA/Juice Shop verification loop — repeatedly firing XSS/SQLi payloads at a live production site during development iteration is a materially different risk/friction profile than a local Docker target, same reasoning CLAUDE.md's read/enumerate-only rule already applies elsewhere. `aalberts.com` specifically carries its own unresolved "confirm before scanning" caveat in doc22 (ambiguous "third-party tools" restriction) and isn't usable, for hunting or otherwise, until that's cleared directly with the target.

### Verification

`go build`/`vet`/`test -race`/`golangci-lint` all re-confirmed clean in the native WSL2 clone after `git pull` (not just the `/mnt/c` checkout). Every number in the table above is from an actual run against a real, running lab target on 2026-08-28, not an estimate — see [20-setup-testing-targets.md](20-setup-testing-targets.md) for exact commands and evidence per target.

---

## Definition of Done (Phase 2, Weeks 11-18)

- [x] `go build ./...`, `go vet ./...`, `golangci-lint run ./...` clean on both macOS/WSL2 (`/mnt/c`) and the native WSL2 clone
- [ ] GitHub Actions CI green, coverage gate still passing — not re-checked this session
- [x] `--scope` allow-list enforced when provided (unit + `Engine`-level tests); omitted-flag behavior confirmed unchanged for lab-target commands — **not yet live-verified with `--scope` actually set** against a real target
- [x] Auth bypass detector finds real issues in crAPI/vAPI — **3 real (2 critical + 1 low-confidence), short of the ≥10 target**, honestly measured and root-caused, not padded — see Step 5
- [x] JWT weak-secret check confirmed to make **zero** network requests (offline-only, per follow-up.md's explicit requirement) — locked in by a unit test, not just a design note
- [x] Rate-limit-signal check confirmed to send a fixed, capped request count with **one** known-invalid credential, never a real credential-guessing sequence — locked in by a unit test
- [x] XSS templates measured live against DVWA/Juice Shop — **0 findings, short of the ≥20 target**; detection logic separately proven correct, reachability is the documented blocker
- [x] SQLi templates measured live against DVWA/Juice Shop — **0 findings, short of the ≥10 target**; same as XSS
- [x] Information-disclosure rule measured live — 0 findings (no false positive against either target's real, benign comments; no true positive demonstrated yet either)
- [ ] False-positive rate re-measured across all Phase 1+2 detectors combined — **not done this session**
- [x] No hardcoded credentials/tokens; no request verb beyond what each detector's design calls for; nothing added here writes/destroys target state (per CLAUDE.md's read/enumerate-only rule)
- [ ] `v0.2.0` tagged and released — **holding** until the Success Metrics gap is closed or explicitly accepted, same call Phase 1b made for DVWA's misconfig number
- [x] `docs/template-writing-guide.md` updated with the new XSS/SQLi/sensitive-field template patterns
- [x] doc03's "Phase 2 Success Metrics" section cross-checked against this doc's real, measured results — recorded honestly above, not silently dropped; three concrete, scoped follow-up items identified (configurable login/logout paths, configurable auth-header scheme for `authbypass`, header/cookie injection for nuclei-format templates) but **not implemented** — a deliberate stop before expanding scope further without checking in

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — vulnerability classes this plan builds on (note: its Auth-Issues phase numbering is stale relative to doc03, see Objective above)
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — architecture this plan follows, including Auth Bypass's place in the Scanner Engine diagram
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-3 roadmap this plan is a slice of
- [follow-up.md](follow-up.md) — source of the scope-enforcement and rate-limit-check redesign decisions in Steps 0/1
- [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) / [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — the foundation this plan builds directly on top of (package layout, detector conventions, template engine)
- [20-setup-testing-targets.md](20-setup-testing-targets.md) — crAPI/vAPI/DVWA/Juice Shop bring-up this plan's integration tests assume
- [22-authorized-targets.md](22-authorized-targets.md) — real-target registry a `--scope` file can be derived from
