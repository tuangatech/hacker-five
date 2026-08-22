# Phase 1b Implementation Plan — Weeks 5-10 (Coverage Expansion)

> Part of the [HackerFive documentation set](../README.md).

## Scope

[03-development-roadmap.md](03-development-roadmap.md) splits Phase 1 ("Foundation") into Phase 1a (Weeks 1-4, done — see [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md)) and **Phase 1b (Weeks 5-10)**. This plan covers Phase 1b's five chunks:
1. Misconfiguration Detector (Week 5)
2. Nuclei-Compatible Template Parser (Week 6-7)
3. Native YAML Template Engine (Week 7-8)
4. Testing & Validation (Week 8-9)
5. Packaging & Documentation (Week 9-10)

**What Phase 1a actually shipped** (verified against the working tree, not just the plan): CLI skeleton (`cmd/hackerfive/{main,root,scan}.go`), `scanner.{Config,Engine}`, a middleware-decorated `httpclient.Client` (retry/backoff, proxy, TLS, redirects), `ratelimit.Limiter`, `hosterrors.Cache`, `workerpool.Pool`, `vars.Render`/`RangeInt`, and a fully working `idor` detector (baseline + heuristic modes, per [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) Step 3) with unit + integration tests against crAPI. `pkg/detectors/misconfig/detector.go` and `pkg/template/parser.go` are stubs. `reporter.WriteJSON` is the only output path. This plan builds on that code directly — every new package below reuses `httpclient.Client`, `hosterrors.Cache`, `vars.Render`, and (for template-driven IDOR) the existing `idor.Baseline`/`idor.Signature`/`idor.Establish` rather than reimplementing any of it.

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

## Step 1: Misconfiguration Detector (Week 5)

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
go test ./pkg/detectors/misconfig/... -race -v
go test -tags=integration ./tests/integration/... -run TestMisconfigDVWA -v   # requires DVWA running
```
`go vet ./...` and `golangci-lint run ./...` clean, same as every prior step.

---

## Step 2: Nuclei-Compatible Template Parser (Week 6-7)

**Goal:** parse a defined subset of the upstream Nuclei template schema, execute it against the shared `httpclient.Client`, and validate against a curated set of real upstream templates from a **pinned commit/tag** — no local fork, no redistribution, per [03-development-roadmap.md](03-development-roadmap.md).

### Package layout

`pkg/template/parser.go` (Phase 1a stub) is replaced by a small package tree, because two distinct formats (this step's Nuclei-compatible parser and Step 3's native format) share a matcher/extractor engine rather than each reimplementing it — the same sharing doc 09 already flagged ("a regex matcher... shared by misconfig and IDOR templates alike"):

```
pkg/template/
├── matcher/matcher.go       — shared: status/word/regex/size/binary/dsl matcher evaluation
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
| `tests/unit/template_matcher_test.go` | Table-driven: status/word/regex/size/binary/dsl matchers, `and`/`or` condition combination |
| `tests/unit/template_extractor_test.go` | Table-driven: regex/kval/json/dsl extractors, chain-scoped variable binding |
| `tests/unit/nuclei_loader_test.go` | Valid templates parse; templates with `code:`/`javascript:`/`headless:`/`file:` blocks are rejected with a clear error, not silently skipped |
| `tests/integration/nuclei_templates_test.go` | Build-tag `integration`; syncs the pinned commit, loads templates tagged `exposed-panels`/`misconfiguration`/`technologies` filtered to `http`-only, asserts ≥50 parse successfully, runs a sample against DVWA/Juice Shop |

### Key types/functions

```go
// pkg/template/matcher/matcher.go
type Matcher struct {
    Type      string   // "status" | "word" | "regex" | "size" | "binary" | "dsl"
    Status    []int
    Words     []string
    Regex     []string
    Size      []int
    Binary    []string
    DSL       []string // hand-rolled subset — see below
    Part      string   // "body" | "header" | "all"; default "body"
    Condition string   // "and" | "or", within a single matcher's own Words/Regex/... list
    Negative  bool
}
type MatchersCondition string // "and" | "or", across a request's Matchers list

// Response is the minimal view matchers/extractors need — decouples this
// package from net/http so both template formats and future protocols
// (see docs/follow-up.md §4) can supply it.
type Response struct {
    StatusCode int
    Headers    http.Header
    Body       []byte
}
func (m Matcher) Evaluate(r Response) bool
func EvaluateAll(matchers []Matcher, cond MatchersCondition, r Response) bool

// pkg/template/extractor/extractor.go
type Extractor struct {
    Type  string // "regex" | "kval" | "json" | "dsl"
    Name  string // bound as {{Name}} for later requests in the chain
    Part  string
    Regex []string
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
}
type HTTPRequest struct {
    Method            string
    Path              []string // Nuclei allows a list; v0.1.0 uses Path[0] only, documents the rest as unsupported
    Headers           map[string]string
    Body              string
    MatchersCondition matcher.MatchersCondition `yaml:"matchers-condition"`
    Matchers          []matcher.Matcher
    Extractors        []extractor.Extractor
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

**DSL matcher/extractor scope, explicitly:** Nuclei's DSL is a general expression language; this parser supports only the subset actually exercised by the curated `exposed-panels`/`misconfiguration`/`technologies` categories: comparisons (`==`, `!=`, `<`, `>`) against `status_code`, `len(body)`, and `contains(body, "...")`/`regex("...", body)` function calls, combined with `&&`/`||`. Implemented as a small hand-rolled recursive-descent evaluator — no third-party expression library (see "Dependencies" above). A DSL expression using anything outside this grammar is a **load-time error**, not a silent no-match — consistent with the `code:`/`javascript:`/`headless:`/`file:` rejection precedent: fail loudly on what isn't supported rather than quietly mis-evaluating it.

**Chaining, explicitly:** a template's `HTTP` requests execute in order; `Extractors` on request *N* bind chain-scoped variables available to `vars.Render` for request *N+1* onward (matching doc 02's variable-scope rules exactly). Nuclei's `req-condition: true` (matching against *all* previous responses in a chain, not just the latest) is **not supported** in v0.1.0 — documented as an explicitly out-of-scope feature alongside non-HTTP protocols, since the curated categories are overwhelmingly single- or two-request templates.

**Pinning, explicitly:** `scripts/sync-nuclei-templates.sh` takes a commit/tag constant defined at the top of the script (check https://github.com/projectdiscovery/nuclei-templates/releases for the current tag before pinning, per [CLAUDE.md](../CLAUDE.md) — don't guess a version), sparse-checks out only the three target directories (`exposed-panels/`, `misconfiguration/`, `technologies/`) into `.nuclei-templates-cache/` (gitignored), and is re-run explicitly (`make templates-sync`), never automatically on `HEAD` — an upstream compromise between pins can't silently reach a scan run.

### Test cases (`tests/unit/nuclei_loader_test.go`)

| Case | Setup | Expected |
|---|---|---|
| Valid `http` template | Well-formed YAML, `matchers-condition: and`, two word matchers | Parses; `Matchers` and `MatchersCondition` populated |
| `code:` block present | Template has a top-level `code:` key | Load error naming the file and the disallowed block, template excluded from results |
| `headless:` block present | Same, for `headless:` | Load error, same shape |
| Unknown DSL expression | `dsl: ["some_undefined_func(x) == 1"]` | Load error at parse time, not a silent always-false matcher |
| Malformed YAML | Truncated/invalid YAML | Load error for that file only; other files in the directory still load (`LoadDir`'s per-file error isolation) |

### Verification

```bash
go test ./pkg/template/... -race -v
make templates-sync   # syncs the pinned commit into .nuclei-templates-cache/ (gitignored)
go test -tags=integration ./tests/integration/... -run TestNucleiTemplates -v
```

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

## Definition of Done (Phase 1b, Weeks 5-10)

- [ ] `go build ./...`, `go vet ./...`, `golangci-lint run ./...` clean on both macOS and WSL2 checkouts
- [ ] GitHub Actions CI green, including the new coverage gate (≥80%)
- [ ] Misconfiguration detector (built-in rules) finds ≥15 issues in DVWA
- [ ] IDOR detector finds ≥8 findings in crAPI at 100% accuracy (baseline mode)
- [ ] Juice Shop scan (misconfig + template-driven) returns ≥20 findings across categories
- [ ] Nuclei-compatible parser loads ≥50 templates from the pinned upstream commit's `exposed-panels`/`misconfiguration`/`technologies` categories and produces matching results against DVWA/Juice Shop
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
