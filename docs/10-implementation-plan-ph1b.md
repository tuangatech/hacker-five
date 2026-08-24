# Phase 1b Implementation Plan — Weeks 5-10 (Coverage Expansion)

> Part of the [HackerFive documentation set](../README.md).

## Objective

Phase 1a proved HackerFive can find one real vulnerability class (IDOR) end-to-end. Phase 1b's job is breadth: catch the other bugs a bug-bounty hunter checks for by hand on every target, and stop needing a Go code change for each new check.

**What it detects, and how:**
- **Misconfigurations** (exposed `.env`/`.git`/admin panels, missing security headers, dangerous HTTP methods like PUT/DELETE, permissive CORS, verbose stack-trace errors, default credentials) — a fixed, hand-written table of paths/headers/methods/patterns, each probed directly with one HTTP request per check (Step 1).
- **Everything the community already has templates for** (exposed panels, known misconfigurations, technology fingerprinting) — by running a curated subset of real, upstream Nuclei templates instead of re-encoding that knowledge by hand (Step 2).
- **HackerFive's own checks as data, not code** (starting with IDOR) — a native YAML format so a new check is a template file, not a new Go detector; IDOR templates drive the exact baseline-comparison logic Phase 1a already built (Step 3).

Both template formats share one matcher/extractor engine (status/word/regex/size matching, regex/JSON/header extraction) — the format differs, the evaluation logic doesn't.

**Why this order:** the misconfig detector ships first as plain Go so there's a second working detector even before any template engine exists — Nuclei templates then *add* to it later rather than being a dependency for it. Testing/validation (Step 4) and packaging (Step 5) come last because they need Steps 1-3's detectors and templates to already exist to measure against.

## Scope

[03-development-roadmap.md](03-development-roadmap.md) splits Phase 1 ("Foundation") into Phase 1a (Weeks 1-4, done — see [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)) and **Phase 1b (Weeks 5-10)**. This plan covers Phase 1b's five chunks:
1. Misconfiguration Detector (Week 5)
2. Nuclei-Compatible Template Parser (Week 6-7)
3. Native YAML Template Engine (Week 7-8)
4. Testing & Validation (Week 8-9)
5. Packaging & Documentation (Week 9-10)

**What Phase 1a actually shipped** (verified against the working tree, not just the plan): CLI skeleton (`cmd/hackerfive/{main,root,scan}.go`), `scanner.{Config,Engine}`, a middleware-decorated `httpclient.Client` (retry/backoff, proxy, TLS, redirects), `ratelimit.Limiter`, `hosterrors.Cache`, `workerpool.Pool`, `vars.Render`/`RangeInt`, and a fully working `idor` detector (baseline + heuristic modes, per [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) Step 3) with unit + integration tests against crAPI. At that point, `pkg/detectors/misconfig/detector.go` and `pkg/template/parser.go` were stubs. `reporter.WriteJSON` is the only output path. This plan builds on that code directly — every new package below reuses `httpclient.Client`, `hosterrors.Cache`, `vars.Render`, and (for template-driven IDOR) the existing `idor.Baseline`/`idor.Signature`/`idor.Establish` rather than reimplementing any of it.

**Since then, Step 1 has landed** (verified against the working tree: `pkg/detectors/misconfig/{rules,detector}.go` are real, `recognizedDetectors`/`Engine.runDetector` are wired, `tests/unit/detector_misconfig_test.go` and `tests/integration/misconfig_dvwa_test.go` exist, README's Status section already marks it ✅) — Steps 2-5 below and `pkg/template/parser.go` are still not started. Step 1's section is kept as originally written (it documents what was built, not a still-open plan) rather than rewritten in the past tense.

**Naming note:** an earlier, incompatible draft of a Phase 1a plan (different project name, different package layout) was committed as `docs/10-implementation-phase-1a.md` and removed for contradicting the doc that was actually built (see `git log` — commit `13c70f0`). This plan is grounded in the *actual* Phase 1a code above, not a fresh redesign, specifically to avoid repeating that mistake.

Dev environment is unchanged from [04-environment-and-testing.md](04-environment-and-testing.md); this plan assumes it's already set up (crAPI running, DVWA/Juice Shop/vAPI available via Docker).

## Dependencies added in this plan

| Package | Version | Used for |
|---|---|---|
| `gopkg.in/yaml.v3` | v3.0.1 (already in `go.sum` as an indirect dep via testify; promoted to direct) | Parsing both template formats (Step 2, Step 3) |

**Deliberately not added**, per [CLAUDE.md](../CLAUDE.md)'s instruction to check current necessity rather than pre-add:
- `github.com/json-iterator/go` — doc 02's original dependency list, but stdlib `encoding/json` is sufficient for both the native JSON extractor (`type: json`) and the misconfig/reporter paths; no measured bottleneck justifies a drop-in replacement. Same reasoning as the `regexp2` carve-out below — add only if a real need appears.
- A third-party regex engine — the curated Nuclei-templates subset (Step 2) is validated against stdlib `regexp` (RE2) first; only if a template in the curated subset genuinely needs a backreference/lookahead does `github.com/dlclark/regexp2` get added, scoped to that one matcher, per [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md).
- A DSL/expression-evaluation library (e.g. `Knetic/govaluate`) — Nuclei's `dsl` matcher/extractor type is supported as a small, hand-rolled subset (comparisons and a handful of functions — see Step 2), not a general-purpose expression language. A template using DSL syntax outside that subset is rejected at load time, the same "fail loudly, don't silently mis-evaluate" pattern already applied to `code:`/`javascript:`/`headless:`/`file:` blocks.

---

## Step 1: Misconfiguration Detector (Week 5) — done

**Goal:** replace the `pkg/detectors/misconfig` stub with a working, Go-native detector using fixed built-in rule tables (paths, headers, methods) — this ships *before* the Nuclei-compatible parser exists (Step 2), so it must not depend on it. This mirrors how Phase 1a's `idor` detector shipped as working Go code before any template engine existed. Once Step 2 lands, upstream Nuclei templates become an *additional* source of misconfig-relevant checks (doc 03's "Misconfiguration/panel checks run against real upstream Nuclei templates" deliverable) — they don't replace this detector, exactly as the roadmap's own week ordering (Week 5 before Week 6-7) implies.

**Explicitly out of scope for this step, and why:** S3 bucket exposure (doc 01's misconfig list) requires asset/subdomain enumeration, not single-target path probing — it belongs with the "Recon Phase (Optional, delegated to external tools)" in [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md), not this detector. Documented as deferred rather than silently dropped.

### Files

| File | Purpose |
|---|---|
| `pkg/detectors/misconfig/rules.go` | Built-in rule tables: exposed paths, security headers, HTTP methods, CORS, verbose-error patterns, default credentials |
| `pkg/detectors/misconfig/detector.go` | Replaces the Phase 1a stub — `Detector` ties the rule tables to `httpclient.Client`, emits `Finding`s |
| `tests/unit/detector_misconfig_test.go` | Table-driven tests against `httptest.Server`, one case per rule category |
| `tests/integration/misconfig_dvwa_test.go` | Build-tag `integration`; runs against a live DVWA instance |

### Key types/functions

```go
// pkg/detectors/misconfig/rules.go
type PathRule struct {
    Path     string   // e.g. "/.env"
    Keywords []string // any keyword present in the body confirms the finding (e.g. "DB_PASSWORD=")
    Severity string
}
type HeaderRule struct {
    Name     string // e.g. "Content-Security-Policy"
    Severity string // flagged when absent from the response
}
type MethodRule struct {
    Method string // "PUT", "DELETE", "PATCH"
    Path   string // "" = target root
}
// A handful of well-known pairs, tried once each, never retried or expanded into
// a dictionary — this is a fixed-size, single-pass check, not credential brute
// force (which CLAUDE.md's read/enumerate-only rule and most program policies
// explicitly prohibit; see docs/follow-up.md §1 for the review finding this
// design directly addresses).
type DefaultCredRule struct {
    LoginPath        string
    Username, Password string
}

var ExposedPaths []PathRule     // ~20 entries: /.env, /.git/config, /debug, /.well-known/security.txt, /swagger, /swagger.json, /graphql, /admin, /admin123, ...
var MissingHeaders []HeaderRule // CSP, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options
var DisallowedMethods []MethodRule
var DefaultCreds []DefaultCredRule // capped at 5 pairs (e.g. test:test, admin:admin)
var VerboseErrorPatterns []string  // regex: stack traces, "at java.", "Traceback (most recent call last)", "ORA-\d+", RFC1918 IPs

// pkg/detectors/misconfig/detector.go
type Detector struct {
    client *httpclient.Client
    hostErrors *hosterrors.Cache
}
func New(client *httpclient.Client) *Detector
// authToken is optional — set as a Bearer header when non-empty, for targets
// where interesting paths sit behind auth.
func (d *Detector) Run(ctx context.Context, target, authToken string) ([]detectors.Finding, error)
```

**Rule execution, explicitly:**
- **Exposed paths:** one `GET` per `PathRule`; a finding requires *both* a non-404 status *and* at least one keyword match in the body — status alone is too weak a signal (many apps return 200 for a custom 404 page).
- **Missing headers:** one `GET` to target root; a finding per `HeaderRule` whose header is absent from the response.
- **Methods:** one request per `MethodRule` against its path (or root); a finding when the response is *not* `405`/`501`/`403` — i.e., the method appears to be accepted.
- **CORS:** one `GET` to target root with `Origin: https://hackerfive-cors-probe.invalid`; a finding when the response reflects that origin (or sends `*`) *and* sets `Access-Control-Allow-Credentials: true` — that specific combination is the actual misconfiguration (a bare wildcard without credentials is low-risk and not flagged).
- **Verbose errors:** one request per exposed/common path with a deliberately malformed query parameter (e.g. `?id='`); body checked against `VerboseErrorPatterns`.
- **Default creds:** one `POST` per `DefaultCredRule` to its login path; a finding only on a clear success signal (redirect away from the login path, or a `Set-Cookie` session token) — never retried, never expanded past the fixed list.

All of this reuses `httpclient.Client` (Step 2 of Phase 1a) and `hosterrors.Cache` exactly as `idor.Detector` does — a target that starts erroring gets skipped early, same as IDOR's sequential-ID enumeration.

`Finding.Type = "misconfig"`, `Confidence = "high"` for every rule category above (each requires a positive, specific signal — status+keyword, absent header, accepted method, reflected-origin+credentials, matched error pattern, or actual login success — not a bare heuristic).

### CLI/config wiring

- `recognizedDetectors` (`pkg/scanner/config.go`) gains `"misconfig": true`.
- `Config.Validate()`: the existing `Detector == "idor"` branches (requiring `--endpoint` and a token) stay `idor`-only; `misconfig` requires neither — no new validation branch needed, the absence of a check *is* the validation for this detector.
- `Engine.runDetector` (`pkg/scanner/engine.go`) gains a `case "misconfig"` constructing `misconfig.New(e.client)` and calling `.Run(ctx, target, e.cfg.AuthToken)`.

### Test cases (`tests/unit/detector_misconfig_test.go`)

| Case | Setup | Expected |
|---|---|---|
| Exposed `.env` | `/.env` returns 200 with `DB_PASSWORD=` in body | 1 finding, high confidence |
| Custom 404 page, not exposed | `/.env` returns 200 but body has none of the keywords | 0 findings |
| Missing CSP | Root response has no `Content-Security-Policy` header | 1 finding per missing header rule |
| Headers all present | Root response sets every checked header | 0 findings |
| PUT accepted | `PUT /api/resource` returns 200 | 1 finding |
| PUT correctly rejected | `PUT /api/resource` returns 405 | 0 findings |
| CORS wildcard + credentials | Reflects `Origin`, sets `Access-Control-Allow-Credentials: true` | 1 finding |
| CORS wildcard, no credentials flag | `Access-Control-Allow-Origin: *`, no credentials header | 0 findings (low-risk combination, not flagged) |
| Verbose error | Malformed query returns a stack trace matching a pattern | 1 finding |
| Default creds succeed | `test:test` POST returns a session cookie | 1 finding |
| Default creds fail | Every pair returns back to the login form | 0 findings |

### Verification

```bash
go test ./tests/unit/... -run TestMisconfig -race -v   # tests live in tests/unit/, not pkg/detectors/misconfig/ itself

export DVWA_BASE_URL=http://localhost   # wherever DVWA is reachable — required, this test skips without it
go test -tags=integration ./tests/integration/... -run TestMisconfigDVWA -v
```
`go vet ./...` and `golangci-lint run ./...` clean, same as every prior step.

---

## Step 2: Nuclei-Compatible Template Parser (Week 6-7) — library done, synced, CLI wiring pending

**Status:** `pkg/template/{matcher,extractor,dsl}` and `pkg/template/nuclei/{schema,loader,executor}.go` are implemented and unit-tested (`tests/unit/template_matcher_test.go`, `template_extractor_test.go`, `nuclei_loader_test.go`, `nuclei_executor_test.go`), and were sanity-checked directly against real, unmodified upstream templates (`angular-detect.yaml`, `adminer-panel.yaml`, `django-debug-config-enabled.yaml` all load correctly — including all 9 of `adminer-panel.yaml`'s `path:` entries and its `stop-at-first-match`; `cors-misconfig.yaml` is correctly rejected for using `raw:`/`payloads:`). `scripts/sync-nuclei-templates.sh` is now pinned (commit `0aa256a344d5b53648575163c61517ac67f57961`, via `git ls-remote ... HEAD` on 2026-08-24) and has been run for real — see "Full synced-set run" below. `--templates` CLI wiring is still Step 3's job by design (see "CLI wiring, explicitly" below), so this step's engine is only reachable from Go tests or a direct package call so far, not from `hackerfive scan` itself.

**Verify against the sample templates:** [templates/nuclei-samples/](../templates/nuclei-samples/) holds four real, unmodified upstream templates (MIT licensed, fetched 2026-08-24, one per curated category plus `cors-misconfig.yaml` as a deliberate rejection example) — see that folder's README for what each one is for. This is a small, permanently-available, hand-picked sample, not the full curated set the roadmap targets (that's still the pinned-commit sync, gitignored, per the "Pinning" note below); it exists so the loader/executor can be exercised without first pinning a commit.
```bash
go test ./tests/unit/... -run TestNucleiSamples -v   # load-correctness regression test, no live target needed
```
**Live-run result against DVWA** (run 2026-08-24, DVWA already up per [20-setup-testing-targets.md](20-setup-testing-targets.md)): all 3 loadable sample templates ran cleanly with zero errors, 0 findings each. This is the expected result, not a bug — see "Realistic yield" above: DVWA is plain PHP, and none of `angular-detect`/`adminer-panel`/`django-debug-config-enabled` target a stack DVWA runs. It confirms the engine executes correctly end-to-end against a live target; it does not exercise the `technologies`-category yield the roadmap actually expects live hits from — that needs the full synced set (or a Juice Shop run, where `angular-detect` should fire) once the sync script has a real commit pin.

**Second live run, [templates/nuclei-samples/dvwa-php/](../templates/nuclei-samples/dvwa-php/), picked *after* reconning DVWA directly** (not guessed) so it had a real chance of firing — see that folder's README for the full breakdown. Result: `apache-detect.yaml` and `php-detect.yaml` both produced genuine findings (DVWA's `Server: Apache/2.4.25` header; the literal substring `PHP` inside its `PHPSESSID` cookie name), `dir-listing.yaml` loaded correctly but found nothing (it only checks root, and DVWA's actual directory listing is at `/docs/`), `apache-mod-negotiation-listing.yaml` was correctly rejected at load time for `raw:`/`payloads:` (already known-excluded), and **`http-missing-security-headers.yaml` initially surfaced a real, previously-unknown gap**: it uses unary `!expr` DSL negation and the `header` built-in variable (`!regex('(?i)strict-transport-security', header)`), neither of which the DSL grammar supported. Both are now fixed (`parseUnary` + `header`/`Header` context, see "DSL matcher/extractor scope" above) — re-run, this template now loads and finds a genuine result: DVWA is missing 10 of its 11 checked security headers.

**A second, related gap found from that same live run, also fixed:** `http-missing-security-headers.yaml` ORs together 11 separately *named* matchers (`name: strict-transport-security`, etc.) — but `matcher.Matcher` had no `Name` field at all, so those names were being silently dropped, and a `matchers-condition: or` match could only report "something matched," not which of the 11 checks. Added `Matcher.Name` and `matcher.MatchingNames` (see Key types/functions above); `nuclei.Executor` now folds the matched names into both `Finding.Description` and `Finding.Evidence["matched_checks"]`. Confirmed against DVWA: the finding now reads `"HTTP Missing Security Headers (strict-transport-security, content-security-policy, permissions-policy, x-frame-options, x-content-type-options, x-permitted-cross-domain-policies, referrer-policy, cross-origin-embedder-policy, cross-origin-opener-policy, cross-origin-resource-policy)"` instead of a generic pass/fail — a concrete example of the difference between "the parser ran without error" and "the finding is actually useful to a human," which matters for a scanner meant to produce real, actionable results.

**Full synced-set run against DVWA, once the commit was actually pinned** (2026-08-24, `make templates-sync` → 2,552 templates loaded, 899 rejected out of ~3,450 total files under the three directories — real corpus, far bigger than the "150-180 per category" estimated before actually syncing). The first full run surfaced three more real, live false positives — not template quirks, engine bugs — each investigated against the actual template source and real Nuclei's own documented/source behavior before fixing, and each with a regression test locking in the fix:

1. **Empty `matchers:` treated as an automatic match.** `EvaluateAll`'s original design ("no matchers disqualifies nothing, so it's trivially true") was never validated against real Nuclei — it turned out to be backwards. Passive fingerprinting templates commonly carry only `extractors:`, no `matchers:` (upstream's `herokuapp-detect.yaml`, `vmware-horizon-version.yaml`, Wappalyzer's `tech-detect.yaml`) — "here's what this regex captured, if anything," not "this target is X." Confirmed against real Nuclei's own source (`pkg/protocols/protocols.go`: an extractor-only result has `Matched=false` and is skipped from output) and fixed: `EvaluateAll` with zero matchers now returns `false`. This alone dropped the false "Detect websites using Herokuapp endpoints," "Vmware Horizon Version Detect," and "WordPress Passive Detection" findings against DVWA — none of which run any of those stacks.
2. **Unrecognized matcher `Part` silently matched against the body.** Upstream's `linkerd-ssrf-detect.yaml` matches `part: interactsh_protocol` (an out-of-band/OAST callback value from an interactsh server this project has no infrastructure for) against the word `"http"`. `Part()` fell through to `"body"` for any unrecognized value, so this was actually checking "does the page body contain the substring 'http'" — true for nearly any real HTML page. Added `matcher.ValidPart`, checked in both `matcher.Validate` and `extractor.Validate`; any OOB/interactsh-style `Part` is now a load-time rejection, not a silent, wrong match. This dropped the false **high-severity** "Linkerd SSRF detection" finding.
3. **`flow:` (conditional multi-request control flow) silently ignored, running every request unconditionally and independently.** Upstream's `apache-server-status-localhost.yaml` uses `flow: http(1) && http(2)`: request 1 is a gate check (`internal: true`, matching `403`/`404`/`401` — "confirm it's blocked before trying the bypass") that should never produce standalone output; request 2 is the actual bypass attempt (spoofed `X-Forwarded-For: 127.0.0.1` etc.). This project's executor doesn't implement `flow:`, so it ran both requests independently — and request 1's own 403 match (DVWA correctly blocks `/server-status`) got reported as a false **"Server Status Disclosure"** finding, backwards from what it meant. Added `Template.Flow` and `Matcher.Internal` as sentinels; the loader now rejects any template using `flow:` or any matcher marked `internal: true`, rather than executing a subset of its requests as if they were independent and unconditional.

**Result after all three fixes, re-run against the same live DVWA target: 4 findings, all genuine** — `http-missing-security-headers` (named, as above), `missing-cookie-samesite-strict`, `apache-detect`, `php-detect`. Down from 12 in the first run, with every removed finding traced to a specific, now-tested engine bug rather than a coincidental miss. This is the strongest evidence yet that the engine's *accuracy*, not just its ability to parse and execute, holds up against a real target and the real, un-curated upstream corpus — directly the project's own `<5% false positives` goal (Step 4/roadmap), demonstrated here at the Step 2 level for the first time.

**Scope decision made during implementation, worth knowing:** the YAML decoder does *not* use strict/`KnownFields` mode. Real templates carry optional fields beyond this schema (e.g. `redirects`, `max-redirects`, `unsafe`, `cookie-reuse`) that don't affect this project's supported behavior — rejecting every template that uses any of them would work against the "≥50 templates parse" goal for fields that are behaviorally inert here. The two fields that *do* silently change behavior if dropped (`raw:`, `payloads:`) are explicitly modeled as sentinel fields and rejected at load time instead of relying on strict mode; the top-level disallowed protocol blocks (`code:`/`javascript:`/etc.) are still caught before decoding even starts, so nothing dangerous can register as merely "an unmodeled field."

**Goal:** parse a defined subset of the upstream Nuclei template schema, execute it against the shared `httpclient.Client`, and validate against a curated set of real upstream templates from a **pinned commit/tag** — no local fork, no redistribution, per [03-development-roadmap.md](03-development-roadmap.md).

**Verified against real upstream templates, not just the Nuclei docs** (fetched `http/technologies/angular-detect.yaml`, `http/misconfiguration/django-debug-config-enabled.yaml`, `http/exposed-panels/adminer-panel.yaml`, `http/vulnerabilities/generic/cors-misconfig.yaml` directly): most templates in the three curated categories fit a `method`/`path`(list)/`headers`/`matchers`/`extractors` shape close to what's modeled below, once `path:` is treated as a list of candidates (not just the first one — see below) rather than a single request. A minority — including the upstream CORS-misconfig template, the direct equivalent of this project's own built-in CORS check — use `raw:` (templated raw HTTP requests) and `payloads:` (a fuzzing engine trying dozens of payload variants with DSL helper functions like `tolower()`/`rand_base()`/`replace()`). That's a small fuzzing engine in its own right, not a matcher-subset extension, and is explicitly out of scope for v0.1.0 — see "Unsupported request styles" below.

### Package layout

`pkg/template/parser.go` (Phase 1a stub) is replaced by a small package tree, because two distinct formats (this step's Nuclei-compatible parser and Step 3's native format) share a matcher/extractor engine rather than each reimplementing it — the same sharing doc 09 already flagged ("a regex matcher... shared by misconfig and IDOR templates alike"):

```
pkg/template/
├── matcher/matcher.go       — shared: status/word/regex/size/dsl matcher evaluation
├── extractor/extractor.go   — shared: regex/kval/json/dsl extractor evaluation
├── nuclei/
│   ├── schema.go            — YAML-decodable struct types for the Nuclei subset
│   ├── loader.go            — LoadDir: parse + reject-at-load-time
│   └── executor.go          — runs a parsed template against a target
└── native/                  — Step 3
```

### Files

| File | Purpose |
|---|---|
| `pkg/template/matcher/matcher.go` | `Matcher` type + `Evaluate(Response) bool`, shared by both template formats |
| `pkg/template/extractor/extractor.go` | `Extractor` type + `Extract(Response) map[string]string`, shared by both template formats |
| `pkg/template/nuclei/schema.go` | YAML structs for `info`, `http` requests, `matchers`, `extractors`, `matchers-condition` |
| `pkg/template/nuclei/loader.go` | `LoadDir` — parses every `.yaml` under a directory, rejects disallowed protocol blocks |
| `pkg/template/nuclei/executor.go` | Renders + fires each request via `vars.Render`/`httpclient.Client`, applies matchers, emits `Finding`s |
| `scripts/sync-nuclei-templates.sh` | Sparse-checks out the pinned `nuclei-templates` commit into a gitignored local cache directory, for use by integration tests and CI — never committed to this repo |
| `tests/unit/template_matcher_test.go` | Table-driven: status/word/regex/size/dsl matchers, `and`/`or` condition combination |
| `tests/unit/template_extractor_test.go` | Table-driven: regex/kval/json/dsl extractors, chain-scoped variable binding |
| `tests/unit/nuclei_loader_test.go` | Valid templates parse; templates with `code:`/`javascript:`/`headless:`/`file:` blocks are rejected with a clear error, not silently skipped |
| `tests/integration/nuclei_templates_test.go` | Build-tag `integration`; syncs the pinned commit, loads every template under the three synced directories, asserts ≥50 parse successfully (rejections from the `raw:`/`payloads:` exclusion above are expected and don't count as failures), runs the full loaded set against DVWA and Juice Shop — see "Realistic yield" below for what to expect from each category |

### Key types/functions

```go
// pkg/template/matcher/matcher.go
type Matcher struct {
    Type      string   // "status" | "word" | "regex" | "size" | "dsl" — no "binary": not used by any
                        // template sampled across exposed-panels/misconfiguration/technologies; add
                        // later if a curated template actually needs it (same "add when needed"
                        // discipline as the regexp2/json-iterator carve-outs above)
    Name      string   // optional label, e.g. "strict-transport-security" — added after a real gap:
                        // upstream templates commonly OR together several named sub-checks, and
                        // without this a matched Finding could only say "something matched," not
                        // which specific check (see MatchingNames below)
    Status    []int
    Words     []string
    Regex     []string
    Size      []int
    DSL       []string // hand-rolled subset — see below
    Part      string   // "body" | "header" | "all"; default "body" — see ValidPart below
    Condition string   // "and" | "or", within a single matcher's own Words/Regex/... list
    Negative  bool
    Internal  bool     // flow-control-only; never a standalone match — rejected at load time,
                        // this project doesn't implement flow: (see Template.Flow below)
}
type MatchersCondition string // "and" | "or", across a request's Matchers list

// ValidPart reports whether part is implemented ("", "body", "header",
// "all") — real templates also use protocol parts this project has no
// underlying support for, most notably interactsh/OAST out-of-band values
// ("interactsh_protocol" etc.), which used to silently fall through to
// matching the body — a live false positive (linkerd-ssrf-detect.yaml),
// fixed by rejecting an unrecognized Part at load time instead.
func ValidPart(part string) bool

// Response is the minimal view matchers/extractors need — decouples this
// package from net/http so both template formats and future protocols
// (see docs/follow-up.md §4) can supply it.
type Response struct {
    StatusCode int
    Headers    http.Header
    Body       []byte
}
func (m Matcher) Evaluate(r Response) bool
// EvaluateAll: an empty matchers slice returns false, NOT true — the
// original "nothing disqualifies it" design was a live false-positive
// generator against real templates that carry only Extractors (see "Full
// synced-set run" above); real Nuclei itself treats extractor-only results
// as Matched=false.
func EvaluateAll(matchers []Matcher, cond MatchersCondition, r Response) bool

// MatchingNames returns the Name of every matcher that individually
// evaluates true, regardless of the overall matchers-condition —
// nuclei.Executor uses this to build a Finding's description/evidence from
// the specific check(s) that actually fired, not just a pass/fail on the
// template as a whole.
func MatchingNames(matchers []Matcher, r Response) []string

// pkg/template/extractor/extractor.go
type Extractor struct {
    Type  string // "regex" | "kval" | "json" | "dsl"
    Name  string // bound as {{Name}} for later requests in the chain
    Part  string
    Regex []string
    Group int      // regex capture group to extract, e.g. version number out of a larger match;
                    // real templates (e.g. adminer-panel.yaml) rely on this — 0 = whole match
    JSON  []string // dot-path, e.g. "token" or "data.user.id" — no array wildcards in v0.1.0
    Kval  []string // header/cookie key name
    DSL   []string
}
func Extract(extractors []Extractor, r Response) map[string]string

// pkg/template/nuclei/schema.go
type Template struct {
    ID    string
    Info  Info
    HTTP  []HTTPRequest `yaml:"http"`

    // Flow is a presence-only sentinel, not implemented: real Nuclei's
    // flow: is small JS controlling conditional/looped execution across a
    // template's HTTP requests. This project runs every HTTP entry
    // unconditionally and independently, which is actively wrong for a
    // flow template (not just incomplete — see "Full synced-set run"
    // above for the live false positive this caused), so it's rejected at
    // load time instead.
    Flow string `yaml:"flow,omitempty"`
}
// Info models only the fields that affect behavior, plus the common
// informational-only fields real templates carry (reference, classification,
// metadata) — loosely typed and unused by the executor, but must be accepted
// rather than rejected so a real template's info: block doesn't fail to load
// just for having them (confirmed present in every sampled template).
type Info struct {
    Name           string
    Author         string
    Severity       string
    Description    string
    Tags           string         // comma-separated, e.g. "tech,angular,discovery"
    Reference      []string       `yaml:"reference"`
    Classification map[string]any `yaml:"classification"`
    Metadata       map[string]any `yaml:"metadata"`
}
type HTTPRequest struct {
    Method   string
    Path     []string // every entry is tried, in order — see "Multi-path requests" below;
                       // NOT Path[0]-only (exposed-panels templates rely on trying several candidate
                       // paths per template — e.g. adminer-panel.yaml tries 9 — as their core mechanism)
    Headers  map[string]string
    Body     string
    StopAtFirstMatch  bool `yaml:"stop-at-first-match"` // stop trying further Path entries once one matches
    MatchersCondition matcher.MatchersCondition `yaml:"matchers-condition"`
    Matchers          []matcher.Matcher
    Extractors        []extractor.Extractor

    // Raw/Payloads are presence-only sentinels, not implemented: a template
    // using either is rejected at load time (see "Unsupported request
    // styles" below) rather than silently parsed with them dropped.
    Raw      []string       `yaml:"raw"`
    Payloads map[string]any `yaml:"payloads"`
}

// pkg/template/nuclei/loader.go
// disallowedBlocks are YAML keys that trigger a load-time error rather than a
// parsed-but-ignored template — RCE/LFI surface from templates nobody on this
// project has reviewed. Same list as documented in doc 02/03.
var disallowedBlocks = []string{"code", "javascript", "headless", "file", "dns", "tcp", "ssl", "network", "websocket", "whois"}
func LoadDir(path string) (templates []*Template, errs []error) // one bad template file doesn't stop the rest from loading — same panic-isolation philosophy as workerpool.Pool.Wait()

// pkg/template/nuclei/executor.go
type Executor struct{ client *httpclient.Client }
func New(client *httpclient.Client) *Executor
func (e *Executor) Run(ctx context.Context, target string, tmpl *Template) ([]detectors.Finding, error)
```

**Multi-path requests, explicitly:** an `HTTPRequest`'s `Path` entries are tried in order, each as its own request against the shared matcher/extractor logic; if `StopAtFirstMatch` is true, the executor stops issuing further `Path` entries once one produces a match. This isn't an optional nicety — it's how exposed-panel templates work at all (a panel could be at any of several conventional paths), so treating `Path` as a single value instead of a list would make that entire category largely non-functional.

**Unsupported request styles, explicitly:** an `HTTPRequest` block using `raw:` (a templated raw HTTP request) or `payloads:` (a named-variable fuzzing list, typically paired with `raw:` and `stop-at-first-match`) is a **load-time error**, not a silently-incomplete parse — same "fail loudly" precedent as the disallowed top-level blocks. Confirmed via a real example: `http/vulnerabilities/generic/cors-misconfig.yaml`, upstream's own CORS-misconfiguration template, uses both — a raw request templated with `{{cors_origin}}`, a 29-entry payload list, and DSL functions (`tolower()`, `rand_base()`, `replace()`) well outside the DSL subset below. Supporting `raw:`/`payloads:` properly is a small fuzzing engine in its own right; it's a reasonable candidate for a later step, not something to half-implement here by ignoring the fields and letting a template silently degrade into a broken, empty-path request.

**DSL matcher/extractor scope, explicitly:** Nuclei's DSL is a general expression language; this parser supports only the subset actually exercised by templates that don't also require `raw:`/`payloads:` (excluded above): the `status_code`/`body`/`header` built-in variables, comparisons (`==`, `!=`, `<`, `>`), `len(...)`/`contains(...)`/`regex(...)` function calls, combined with `&&`/`||`, unary `!` negation, and parenthesized grouping — `!(a && b) || c` — all of which cost little extra in a recursive-descent evaluator (unary `!` is one more precedence level; grouping and `header` fall out of the grammar/context the same way `status_code`/`body` already did) and are worth having rather than assuming every real expression is flat. Confirmed via a real template, not assumed: upstream's `http-missing-security-headers.yaml` — one of the most widely-used templates in `nuclei-templates` — needed both `!` and `header` (`!regex('(?i)strict-transport-security', header)`); without them it was rejected at load time despite being exactly the kind of check this project wants to run. Implemented as a small hand-rolled recursive-descent evaluator — no third-party expression library (see "Dependencies" above). A DSL expression using anything outside this grammar — including the richer helper functions (`tolower`, `rand_base`, `replace`, etc.) real templates use inside `raw:`/`payloads:` blocks — is a **load-time error**, not a silent no-match — consistent with the `code:`/`javascript:`/`headless:`/`file:` rejection precedent: fail loudly on what isn't supported rather than quietly mis-evaluating it.

**Chaining, explicitly:** a template's `HTTP` requests execute in order; `Extractors` on request *N* bind chain-scoped variables available to `vars.Render` for request *N+1* onward (matching doc 02's variable-scope rules exactly). Nuclei's `req-condition: true` (matching against *all* previous responses in a chain, not just the latest) is **not supported** in v0.1.0 — documented as an explicitly out-of-scope feature alongside non-HTTP protocols, since the curated categories are overwhelmingly single- or two-request templates.

**Pinning, explicitly:** `scripts/sync-nuclei-templates.sh` takes a commit/tag constant defined at the top of the script (check https://github.com/projectdiscovery/nuclei-templates/releases for the current tag before pinning, per [CLAUDE.md](../CLAUDE.md) — don't guess a version), sparse-checks out only the three target directories — **`http/exposed-panels/`, `http/misconfiguration/`, `http/technologies/`** (confirmed live against the repo: these categories were reorganized under a top-level `http/` directory at some point; they are not top-level themselves, despite how doc 02/03 describe them) — into `.nuclei-templates-cache/` (gitignored), and is re-run explicitly (`make templates-sync`), never automatically on `HEAD` — an upstream compromise between pins can't silently reach a scan run.

**Scale, for context:** each of the three directories has 150-180+ entries at its own top level alone, plus further vendor-named subdirectories (e.g. `http/exposed-panels/adobe/`, `.../apache/`) — confirmed by listing them directly. `LoadDir` needs to walk recursively, not just one directory level, and "≥50 templates parse successfully" (Definition of Done) is a low bar against that real volume, not an ambitious one.

### Test cases (`tests/unit/nuclei_loader_test.go`)

| Case | Setup | Expected |
|---|---|---|
| Valid `http` template | Well-formed YAML, `matchers-condition: and`, two word matchers | Parses; `Matchers` and `MatchersCondition` populated |
| `code:` block present | Template has a top-level `code:` key | Load error naming the file and the disallowed block, template excluded from results |
| `headless:` block present | Same, for `headless:` | Load error, same shape |
| Unknown DSL expression | `dsl: ["some_undefined_func(x) == 1"]` | Load error at parse time, not a silent always-false matcher |
| `raw:`/`payloads:` present | Template's `http:` entry has a `raw:` block (e.g. modeled on `cors-misconfig.yaml`) | Load error naming the file and the unsupported field, template excluded from results — not silently parsed with `Method`/`Path` empty |
| Multi-path panel template | `path:` has several entries (e.g. modeled on `adminer-panel.yaml`'s 9 paths) with `stop-at-first-match: true` | All entries parse into `HTTPRequest.Path`; `StopAtFirstMatch` is `true` — not just the first entry kept |
| `flow:` present | Template has a top-level `flow:` key (e.g. modeled on `apache-server-status-localhost.yaml`) | Load error naming `flow:`, template excluded — not run as independent, unconditional requests |
| `internal: true` matcher | A matcher sets `internal: true` (flow-control-gate pattern, found live producing a false positive — see "Full synced-set run" above) | Load error naming `internal:`, template excluded — never evaluated as a standalone matcher |
| Malformed YAML | Truncated/invalid YAML | Load error for that file only; other files in the directory still load (`LoadDir`'s per-file error isolation) |

**Realistic yield against DVWA/Juice Shop, explicitly:** neither target has a dedicated upstream template (checked: no `dvwa`/`juice-shop`-named templates exist in `nuclei-templates`), and generic-panel/misconfig templates target frameworks neither app runs (Adminer, Django, phpMyAdmin, etc.) — so `exposed-panels`/`misconfiguration` will mostly exercise the *parser* against DVWA/Juice Shop, producing few or zero live findings there, the same ceiling already measured for Step 1's built-in rules against DVWA. `technologies` is where real hits are actually expected — e.g. `angular-detect.yaml` should genuinely fire against Juice Shop's Angular frontend. Don't treat a low finding count from the first two categories as a bug; treat it the same way Step 1's DVWA gap note does.

**CLI wiring, explicitly: none yet.** `--templates` stays inert after this step — `nuclei.Executor` is only reachable from Go tests or a direct package call. It's wired into `hackerfive scan` in Step 3, alongside the native format, once both loaders exist to wire in together.

### Verification

```bash
go test ./tests/unit/... -run 'TestMatcher|TestEvaluateAll|TestMatchingNames|TestExtract|TestNucleiLoadDir' -race -v   # tests live in tests/unit/, not pkg/template/ itself
make templates-sync   # syncs the pinned commit into .nuclei-templates-cache/ (gitignored) — already done, see "Status" above
go test -tags=integration ./tests/integration/... -run TestNucleiTemplates -v
```
Already run for real (2026-08-24): `make templates-sync` → 2,552 loaded / 899 rejected; `TestNucleiTemplates` against DVWA → see "Full synced-set run" above for the finding count and the fixes that got it there.

---

## Step 3: Native YAML Template Engine (Week 7-8)

**Goal:** parse the HackerFive-native format (the one shown in [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) and previously documentation-only in `templates/idor/example.yaml`), reusing the `matcher`/`extractor` packages from Step 2, and — for IDOR templates specifically — reusing Phase 1a's `idor.Baseline`/`idor.Signature`/`idor.Establish` rather than reimplementing baseline-mode comparison a second time.

### Files

| File | Purpose |
|---|---|
| `pkg/template/native/schema.go` | YAML structs: `Template`, `Request` (method/path/headers/body/extractors/matchers/condition), `Variables` |
| `pkg/template/native/loader.go` | `Parse`/`LoadDir`, same shape as the Nuclei loader |
| `pkg/template/native/executor.go` | Runs a native template; routes `idor`-tagged templates through the existing `idor` package instead of generic matcher logic |
| `templates/idor/*.yaml` | 20+ real, executable native templates (crAPI-style endpoints, generic patterns) — replaces the Phase 1a placeholder |
| `tests/unit/native_loader_test.go` | Parsing + variable-scope tests (global `variables:` vs. chain-scoped extractor output) |
| `tests/unit/native_executor_idor_test.go` | Confirms template-driven baseline mode produces identical findings to the flag-driven path from Phase 1a, given the same fixture responses |

### Key types/functions

```go
// pkg/template/native/schema.go
type Template struct {
    ID        string
    Info      Info
    Tags      []string // "idor" routes through idor.Detector's baseline/heuristic logic
    Variables map[string]string
    Requests  []Request
}
type Request struct {
    Method     string
    Path       string
    Headers    map[string]string
    Body       string
    Extractors []extractor.Extractor
    Matchers   []matcher.Matcher
    Condition  string // evaluated against already-bound variables before firing, per doc 02
}

// pkg/template/native/executor.go
type Executor struct {
    client *httpclient.Client
}
func New(client *httpclient.Client) *Executor
// ownerToken/otherToken are threaded through exactly as in idor.Detector.Run —
// "" for otherToken falls back to heuristic mode. A non-idor-tagged template
// runs through the generic matcher/extractor path instead.
func (e *Executor) Run(ctx context.Context, target string, tmpl *Template, ownerToken, otherToken string) ([]detectors.Finding, error)
```

**Why `idor`-tagged templates don't get a second comparison engine:** Step 3's job is to let a YAML file *supply* what `--endpoint` used to supply (the endpoint template, per doc 09's own "stopgap until Phase 1b's template engine can supply this from a YAML file instead of a flag"), not to reimplement baseline-mode comparison. `native/executor.go`'s `idor` path extracts the endpoint template and ID-range hints from the parsed `Template`/`Request`, then constructs and calls the *existing* `idor.Detector` from `pkg/detectors/idor` — one comparison algorithm, two ways to configure it (flag or YAML).

### CLI wiring

`--templates` (accepted since Phase 1a, previously unused) becomes live: `Engine.Run` loads templates from `cfg.TemplatePaths` via `template/nuclei.LoadDir` and `template/native.LoadDir` for every scan, in addition to whichever built-in detector `--detector` selects — the two are complementary layers (Step 1's rationale), not alternatives. The `--endpoint`-driven `idor` path from Phase 1a is **kept**, not removed: it's still the fastest way to point the IDOR detector at a single endpoint during ad hoc recon without first writing a template file.

`templates/idor/example.yaml` (Phase 1a's documentation-only placeholder) is replaced with real, executable templates now that something actually parses them — either updated in place or split into a still-documentation-only `example.yaml` plus real starter templates alongside it.

### Test cases (`tests/unit/native_executor_idor_test.go`)

Reuses the exact fixture shapes from `tests/fixtures/responses/idor_*.json` (Phase 1a) — same clean-baseline / classic-IDOR / server-error / insufficient-samples cases — but driving them through a parsed `Template` instead of `--endpoint`/`--auth-token` flags, asserting the resulting `Finding`s match Phase 1a's flag-driven output for the same fixtures. This is a regression test for "one algorithm, two entry points," not new IDOR logic.

### Verification

```bash
go test ./pkg/template/native/... -race -v
go run ./cmd/hackerfive scan -t $CRAPI_BASE_URL --detector idor --templates ./templates/idor/ \
  --auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN"
# Expect: same findings as Phase 1a's --endpoint-driven run, now also sourced from templates/idor/*.yaml
```

---

## Step 4: Testing & Validation (Week 8-9)

**Goal:** hit the roadmap's Phase 1b validation bar — coverage gated (not just tracked), integration tests across all four Phase 1 targets, and false-positive rate measured across *both* template paths.

### Files

| File | Purpose |
|---|---|
| `pkg/template/nuclei/fuzz_test.go` | `testing.F` fuzz target seeded with malformed template YAML — expands Phase 1a's fuzzing (HTTP client/response parsing) to the template parsers, per doc 03's "expanded here" |
| `pkg/template/native/fuzz_test.go` | Same, for the native format |
| `tests/integration/vapi_auth_test.go` | New target (vAPI wasn't used in Phase 1a) — misconfig + Nuclei-template checks against vAPI's OWASP API Top 10 scenarios |
| `tests/integration/juiceshop_test.go` | Misconfig + Nuclei-template checks against Juice Shop |
| `scripts/measure-fp-rate.sh` | Runs a scan against each target, diffs findings against a hand-curated expected-findings fixture, reports FP rate per target and per template-source (built-in / nuclei-compatible / native) |

### Verification

```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out | tail -1   # gate: total must be >= 80%

go test -fuzz=FuzzNucleiTemplateParse -fuzztime=30s ./pkg/template/nuclei/
go test -fuzz=FuzzNativeTemplateParse -fuzztime=30s ./pkg/template/native/

go test -tags=integration ./tests/integration/... -v   # crAPI, vAPI, DVWA, Juice Shop

./scripts/measure-fp-rate.sh
# Target from doc 03: crAPI 8+ IDOR findings (100% accuracy), DVWA 15+ misconfig findings,
# Juice Shop 20+ findings across categories, <5% FP rate overall
```
CI (`.github/workflows/ci.yml`) gains a coverage-gate step (`go tool cover -func` piped through a threshold check) alongside the existing build/vet/test/lint matrix — this is the point in the roadmap where "coverage tracked, not gated" (Phase 1a's explicit deferral) becomes gated.

---

## Step 5: Packaging & Documentation (Week 9-10)

**Goal:** ship v0.1.0 — multi-stage Docker image, cross-compiled binaries, and documentation covering both template formats.

### Files

| File | Purpose |
|---|---|
| `Dockerfile` | Replaces Phase 1a's single-stage build: multi-stage, `CGO_ENABLED=0`, `-trimpath`, `-ldflags '-s -w'` for a small static binary |
| `.goreleaser.yml` | Cross-compiled Linux/macOS/Windows binaries (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64) |
| `README.md` | Install instructions (`go install`, Docker, source), quick-start, links to the template-writing guide |
| `docs/template-writing-guide.md` | Covers both the Nuclei-compatible subset (what's supported, what's rejected, what's out of scope) and the native format (variables, chaining, baseline-mode IDOR) |
| `CONTRIBUTING.md` | PR process, code style, required checks (`make build test lint`) before submitting |
| `.github/ISSUE_TEMPLATE/*.md`, `.github/PULL_REQUEST_TEMPLATE.md` | Standard GitHub templates |

**Not in this step, and why:** Markdown/HTML/HackerOne-JSON-schema exporters (listed in doc 02's architecture but not in doc 03's Phase 1b week bullets) stay deferred — doc 03's own note on the GitHub Action says integrations wait until "the CLI output schema is stable (post v0.1.0)." JSON is that schema; v0.1.0 is when it stabilizes. Adding more `Exporter` implementations before that is exactly the kind of premature abstraction the removed `docs/10-implementation-phase-1a.md` got wrong (it built Markdown/HTML reporters in *Phase 1a*, before there was even one detector to report on). `reporter.WriteJSON` stays a plain function, not an interface, until a second concrete format is actually being implemented — same "rule of three, not before" reasoning doc 02 already applies elsewhere.

### Verification

```bash
make build && ./hackerfive --help
docker build -t hackerfive:v0.1.0 .
docker run --rm hackerfive:v0.1.0 --help

goreleaser release --snapshot --clean   # local dry run, no publish
```
Tag `v0.1.0` and cut the GitHub release once the Definition of Done below is met.

---

## Future Enhancements (Not Yet Scoped)

Not part of Steps 1-5's committed Week 5-10 deliverables — ideas surfaced while building and live-testing Step 2, worth scoping deliberately later rather than folding into an already-defined step. Ordered by how directly each moves "finds real issues in real apps," which is the actual goal, not just schema coverage:

1. **`raw:`/`payloads:` support.** The single biggest lever left for coverage: of the ~3,450 real templates across the three curated categories, 899 (~26%) were rejected on the first full sync run, and `raw:`/`payloads:` is the dominant reason (see Step 2's "Unsupported request styles"). It's what excludes upstream's own CORS-misconfiguration template — a real check this project's own built-in `misconfig` detector approximates by hand — and a meaningful slice of fuzzing-style checks generally. It's a small templated-request-plus-payload-substitution engine in its own right, big enough to be its own step rather than an add-on to Step 2.
2. **`flow:` support.** Discovered mid-Step-2, not anticipated when this plan was first written: templates using `flow:` (conditional/sequenced multi-request execution, e.g. "only try the bypass if the direct check was blocked") aren't just unsupported — running their requests unconditionally and independently produces **backwards, actively wrong results** (see Step 2's live `apache-server-status-localhost.yaml` false positive). Currently handled the safe way (reject at load time), but real Nuclei's `flow:` is a small JS-based control-flow layer over the same request/matcher/extractor primitives this project already has — implementing a minimal subset (sequential `http(1) && http(2)`-style chaining with `internal` matcher support) would recover a meaningful number of currently-rejected templates without the redesign `raw:`/`payloads:` needs.
3. **A default template bundle shipped with the binary.** Right now every useful run depends on either the sync script (now pinned, but still a manual step a user has to run and re-run) or hand-picked samples in `templates/nuclei-samples/`. Even a small curated set (the categories/templates most likely to hit real targets, informed by what actually fired against DVWA in Step 2's live runs) baked into `templates/` would make `hackerfive scan --templates ./templates/` produce real findings out of the box, with no setup.
4. **Directory-listing / common-subpath checks beyond root.** `dir-listing.yaml` (used in Step 2's DVWA testing) only checks `{{BaseURL}}` — DVWA's actual directory listing lives at `/docs/`, not root, so this specific real template found nothing there despite the misconfiguration genuinely existing. A short list of common subpaths (`/docs/`, `/uploads/`, `/backup/`, `/files/`, etc.) tried by directory-listing-style checks, similar in spirit to the built-in misconfig detector's `ExposedPaths` table, would close this gap without needing upstream to write a DVWA-specific template.

**Deliberately not on this list:** interactsh/OAST (out-of-band) support. This requires standing up or depending on external callback infrastructure to detect blind SSRF/RCE-style issues — a different category of dependency than anything else this project takes on, and in tension with keeping HackerFive a self-contained, read-only scanner (see [CLAUDE.md](../CLAUDE.md)). Templates needing it are correctly rejected at load time (see Step 2's `ValidPart`) and should stay that way rather than becoming a roadmap item.

---

## Definition of Done (Phase 1b, Weeks 5-10)

- [ ] `go build ./...`, `go vet ./...`, `golangci-lint run ./...` clean on both macOS and WSL2 checkouts
- [ ] GitHub Actions CI green, including the new coverage gate (≥80%)
- [ ] Misconfiguration detector (built-in rules) finds ≥15 issues in DVWA — **at risk:** a live run against DVWA (Security level Low) found only 7 (4 missing-header + 3 disallowed-method findings); exposed-paths/CORS/verbose-errors/default-creds all legitimately found nothing, since DVWA doesn't expose the generic paths this fixed rule table checks and its login form fails the CSRF precondition (see [20-setup-testing-targets.md](20-setup-testing-targets.md)'s caveat). 7 may be close to this detector's ceiling against DVWA as built — closing the gap likely needs Step 2's Nuclei-compatible templates (which include DVWA-relevant checks) rather than more built-in rules
- [ ] IDOR detector finds ≥8 findings in crAPI at 100% accuracy (baseline mode)
- [ ] Juice Shop scan (misconfig + template-driven) returns ≥20 findings across categories
- [ ] Nuclei-compatible parser loads ≥50 templates from the pinned upstream commit's `http/exposed-panels`/`http/misconfiguration`/`http/technologies` categories and runs cleanly against DVWA/Juice Shop — **DVWA half confirmed** (2,552 templates loaded, ran cleanly, 4 genuine findings — see Step 2's "Full synced-set run"); Juice Shop not yet run, leaving this unchecked until it is. Live findings did come from `technologies` as expected (`apache-detect`, `php-detect`), but also from `misconfiguration` (`http-missing-security-headers`, `missing-cookie-samesite-strict`) — the "Realistic yield" note's category prediction was directionally right but not exclusive
- [ ] Templates containing `code:`/`javascript:`/`headless:`/`file:` (or any of the other disallowed blocks) are rejected at load time with a named error, never silently skipped
- [ ] Native YAML engine executes `templates/idor/*.yaml` (20+ templates) and produces the same findings as the Phase 1a flag-driven path on identical fixtures
- [ ] Measured false-positive rate <5%, covering built-in misconfig rules, Nuclei-compatible templates, and native templates
- [ ] `hackerfive scan` scans 100 targets in <2 minutes
- [ ] Fuzz targets exist and run clean for the HTTP client (Phase 1a) and both template parsers (this plan)
- [ ] `docker build` produces a multi-stage image; `goreleaser release --snapshot` produces binaries for all five target platforms
- [ ] README, template-writing guide, CONTRIBUTING.md, and issue/PR templates are complete
- [ ] No hardcoded credentials, no request verb beyond what each detector's design calls for (`GET` for IDOR/misconfig path checks, one bounded `POST` per default-cred pair) — read/enumerate-only rule from [CLAUDE.md](../CLAUDE.md) holds throughout
- [ ] `v0.1.0` tagged and released

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — package layout, dependency, and template-security decisions this plan follows
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-3 roadmap this plan is a slice of
- [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) — the foundation this plan builds directly on top of (package names, types, and conventions carried forward, not re-derived)
- [04-environment-and-testing.md](04-environment-and-testing.md) — dev environment and test-target setup this plan assumes
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — read-only/no-exfiltration constraints reflected in the misconfig detector's default-creds and verbose-error checks
- [follow-up.md](follow-up.md) — the read/enumerate-only-vs-brute-force tension this plan's `DefaultCredRule` design (fixed list, single pass, never retried) is a direct response to
- [20-setup-testing-targets.md](20-setup-testing-targets.md) — DVWA bring-up/database-init steps for Step 1's integration test, including the CSRF caveat on why the default-creds check won't fire against DVWA's real login form
