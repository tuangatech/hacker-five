# Phase 1a Implementation Plan — Weeks 1-4 (Foundation Kickoff)

> Part of the [HackerFive documentation set](../README.md).

## Scope

[03-development-roadmap.md](03-development-roadmap.md) splits Phase 1 ("Foundation") into **Phase 1a (Weeks 1-4)** and **Phase 1b** (see that doc for Phase 1b's current week numbers). This plan covers Phase 1a only — the three chunks that get a working, IDOR-only scanner running end-to-end:
1. Project Setup & Architecture (Week 1-2)
2. HTTP Client & Request Engine (Week 2-3)
3. IDOR Detector (Week 3-4)

Phase 1b (misconfiguration detector, Nuclei-compatible template parser, native YAML template engine, full testing/validation pass, packaging) has its own follow-up plan — see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — written after this foundation was merged and working end-to-end. The repo currently has no code — this is a from-scratch build.

**Boundary this plan does *not* cross:** the roadmap's Phase 1b success metrics ("8+ IDOR findings in crAPI, 100% accuracy," "<5% false positives") are targets for Phase 1b's Testing & Validation step (see [03-development-roadmap.md](03-development-roadmap.md) for its current week numbers), which needs both template engines and a dedicated validation pass. The exit bar for *this* plan is Phase 1a's own checkpoint: the IDOR detector's logic is correct, unit-tested, and demonstrably finds at least one known issue against a live crAPI instance — not the full accuracy claim.

Dev environment (macOS + WSL2/Windows 11) is already covered by [04-environment-and-testing.md](04-environment-and-testing.md); this plan assumes that setup is done. Every command below runs identically on both.

## Dependencies used in this plan

Per [CLAUDE.md](../CLAUDE.md), versions are pinned to what's actually current rather than guessed:

| Package | Version | Used for |
|---|---|---|
| `github.com/spf13/cobra` | v1.10.2 | CLI commands/flags |
| `golang.org/x/time/rate` | v0.15.0 | Token-bucket rate limiter (Step 2) |
| `github.com/stretchr/testify` | v1.11.1 | Test assertions (dev dependency) |

Regex matching uses the standard library `regexp` (RE2) — no third-party regex dependency yet (see the fix in [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md), which previously named a package that doesn't exist). `gopkg.in/yaml.v3` and `github.com/json-iterator/go` aren't added until Phase 1b's template-parser work (see [03-development-roadmap.md](03-development-roadmap.md)), when the Nuclei-compatible parser and native YAML template engine actually need them — no point pulling a dependency before the code that uses it exists.

Note this Phase 1a plan's IDOR detector (Step 3) doesn't use `regexp` at all — `compare.go`'s `Signature` diff is status code + body-size tolerance + hash + sorted keyword list, no pattern matching. A regex matcher only enters the picture once Phase 1b's native YAML template engine parses a `type: regex` matcher generically (shared by misconfig and IDOR templates alike) — see [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)'s note on the IDOR baseline-comparison format being the one place a PCRE-only pattern (backreference, lookahead) could force adding `regexp2`.

---

## Step 1: Project Setup & Architecture (Week 1-2)

**Goal:** a compiling skeleton with a working `scan` CLI command, CI green, and every package stubbed so Steps 2-3 have somewhere to land.

**Convention from this step on:** errors are wrapped with context via `fmt.Errorf("doing X: %w", err)` and inspected with `errors.Is`/`errors.As` — no custom error type, per [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md).

### Files

| File | Purpose |
|---|---|
| `go.mod` | Module `github.com/tuangatech/hacker-five`, `go 1.26.5` directive (matches the dev toolchain per env doc — no need to support older Go for this project) |
| `Makefile` | Wraps `build`/`test`/`lint`/`fuzz`/`integration` targets (see [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)) — same commands already used ad hoc in this plan's Verification sections, just given one canonical entry point |
| `cmd/hackerfive/main.go` | Thin entrypoint — builds a `context.Context` via `signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)`, passes it to the root command, and sets the process exit code from the returned error (non-nil → exit 1) |
| `cmd/hackerfive/root.go` | Root Cobra command, persistent (inherited by all subcommands) flags: `--proxy`, `--timeout`, `--output/-o` |
| `cmd/hackerfive/scan.go` | `scan` subcommand — flags (`--targets/-t`, `--templates`, `--concurrency/-c`, `--rate-limit`, `--detector`, `--auth-token`, `--other-auth-token`, `--insecure`) wired into `scanner.Config`; `RunE` calls `cfg.Validate()` before constructing the `Engine` |
| `pkg/scanner/config.go` | Shared `Config` struct passed from CLI into the engine, plus `Validate() error` |
| `pkg/scanner/engine.go` | `Engine` orchestrating a scan run — stub `Run()` in this step, fleshed out in Steps 2-3 |
| `pkg/detectors/types.go` | `Finding` struct shared by every detector and the reporter |
| `pkg/detectors/idor/detector.go` | Stub only — real logic in Step 3 |
| `pkg/detectors/misconfig/detector.go` | Stub only — real logic lands in Phase 1b (see [03-development-roadmap.md](03-development-roadmap.md)), out of scope here |
| `pkg/template/parser.go` | Stub only (`type Template struct{}`) — real template parsing (Phase 1b's Nuclei-compatible and native YAML parsers — see [03-development-roadmap.md](03-development-roadmap.md)) is out of scope here |
| `pkg/reporter/output.go` | Minimal JSON writer so `--output json` works end-to-end from day one |
| `templates/idor/example.yaml` | Documentation-only example of the eventual template shape (not consumed by code yet) |
| `Dockerfile` | Minimal single-stage build for now — just needs `docker build` to succeed; multi-stage optimization is a Phase 1b packaging task (see [03-development-roadmap.md](03-development-roadmap.md)) |
| `.github/workflows/ci.yml` | As specified in [04-environment-and-testing.md](04-environment-and-testing.md) — `go test -race`, `go vet`, `golangci-lint run` |
| `.gitignore` | As specified in [04-environment-and-testing.md](04-environment-and-testing.md) |

### CLI flags

| Flag | Short | Type | Default | Env var | Level | Notes |
|---|---|---|---|---|---|---|
| `--proxy` | | string | `""` | | root (persistent) | e.g. `http://127.0.0.1:8080` for Burp/MitmProxy; applies to every request the process makes |
| `--timeout` | | duration | `30s` | | root (persistent) | per-request timeout (Step 2) |
| `--output` | `-o` | string | `""` (stdout) | | root (persistent) | file path; format is fixed JSON in Phase 1a — `--format` for Markdown/HTML is Phase 1b+ (see [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)'s Exporter interface) |
| `--targets` | `-t` | string | *(required)* | | `scan` | either a literal target (`http://example.com`) or a path to a file with one target per line — `cobra`'s `RunE` distinguishes the two by checking `os.Stat` first, falling back to treating the value as a literal URL |
| `--templates` | | string | `./templates/` | | `scan` | directory path; stored as a single-element `Config.TemplatePaths` (the slice type is there for Phase 1b's multi-directory support, unused in Phase 1a); accepted for CLI stability but unused until Phase 1b's template engine parses it |
| `--concurrency` | `-c` | int | `25` | | `scan` | worker pool size (Step 2) |
| `--rate-limit` | | int | `50` | | `scan` | requests/sec across the whole scan, shared by all workers (Step 2) |
| `--detector` | | string | *(required)* | | `scan` | which detector to run; only `"idor"` is recognized in Phase 1a — any other value is a `Validate()` error |
| `--endpoint` | | string | `""` | | `scan` | endpoint path with an `{{id}}` placeholder to enumerate, e.g. `/identity/api/v2/user/dashboard/{{id}}`; joined with each target to build the `idor.Detector` endpoint template. Required when `--detector idor` — stopgap until Phase 1b's template engine can supply this from a YAML file instead of a flag |
| `--auth-token` | | string | `""` | `HACKERFIVE_AUTH_TOKEN` | `scan` | owner/primary account token (Step 3); flag wins if both flag and env var are set |
| `--other-auth-token` | | string | `""` | `HACKERFIVE_OTHER_AUTH_TOKEN` | `scan` | second account token for IDOR baseline mode; omitting both falls back to heuristic mode (Step 3) |
| `--insecure` | | bool | `false` | | `scan` | skips TLS verification (`InsecureSkipVerify`, Step 2) — lab targets only (crAPI/DVWA self-signed certs), never the default |

`Config.Validate()` (called from `scan.go`'s `RunE`, before the `Engine` is constructed) rejects: empty `Targets`, `Concurrency <= 0`, `RateLimit <= 0`, `Detector` not in the recognized set, `Detector == "idor"` with both `AuthToken` and `OtherAuthToken` empty (Step 3 needs at least one token to run at all, even in heuristic mode), `Detector == "idor"` with an empty `EndpointTemplate`, and a `ProxyURL` that fails `url.Parse`.

### Key types/functions

```go
// cmd/hackerfive/scan.go
func newScanCmd() *cobra.Command

// pkg/scanner/config.go
type Config struct {
    Targets            []string
    TemplatePaths      []string
    Concurrency        int
    RateLimit          int
    ProxyURL           string
    Timeout            time.Duration
    OutputFormat       string // fixed "json" in Phase 1a — no CLI flag selects it yet
    OutputPath         string // from --output/-o; "" = stdout
    Detector           string // "idor" is the only recognized value in Phase 1a
    EndpointTemplate   string // e.g. "/identity/api/v2/user/dashboard/{{id}}" — joined with each target to build the idor.Detector endpoint template; stopgap until Phase 1b's template engine can supply this from a YAML file instead of a flag
    Insecure           bool   // maps to httpclient.Config.InsecureSkipVerify (Step 2); default false
    HostErrorThreshold int    // 0 = use hosterrors.DefaultThreshold (Step 2)
    AuthToken      string // primary/"owner" account token — from --auth-token or HACKERFIVE_AUTH_TOKEN, never hardcoded
    OtherAuthToken string // second, unrelated account token used for IDOR baseline comparison (Step 3) — from --other-auth-token or HACKERFIVE_OTHER_AUTH_TOKEN; optional, but required for high-confidence IDOR findings
}
func (c Config) Validate() error // see "CLI flags" above for the exact rejection rules

// pkg/scanner/engine.go
type Engine struct {
    cfg Config
}
func New(cfg Config) *Engine
func (e *Engine) Run(ctx context.Context) ([]detectors.Finding, error) // stub: returns nil, nil in this step; Step 3 wires cfg.Detector to the idor detector — an unrecognized Detector value is caught by Config.Validate() before Run is ever called, so Run itself doesn't need a default/error branch for it

// pkg/detectors/types.go
type Finding struct {
    ID          string
    Type        string // "idor", "misconfig", ...
    Severity    string // "low" | "medium" | "high" | "critical"
    Confidence  string // "high" (cross-account baseline evidence) | "low" (single-account heuristic, needs manual triage)
    Target      string
    Description string
    Evidence    map[string]string
}

// pkg/reporter/output.go
func WriteJSON(w io.Writer, findings []detectors.Finding) error
```

### Example files

`templates/idor/example.yaml` — documentation-only in Phase 1a (not parsed by code until Phase 1b's template engine lands); shows the target shape referenced in [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md):

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
variables:
  base_path: /api/users
requests:
  - method: GET
    path: "{{base_path}}/{{RangeInt(1|100)}}"
    headers:
      Authorization: Bearer {{auth_token}}
    matchers:
      - type: status
        status: [200]
```

`Dockerfile` — single-stage, just needs to produce a runnable image (multi-stage/size optimization is a Phase 1b packaging task):

```dockerfile
FROM golang:1.26-alpine
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /usr/local/bin/hackerfive ./cmd/hackerfive
ENTRYPOINT ["hackerfive"]
```
(Pin the `golang:` tag to whatever [04-environment-and-testing.md](04-environment-and-testing.md) currently specifies as the dev toolchain version — don't let this Dockerfile and that doc drift to different Go versions.)

`.github/workflows/ci.yml` — matrix build so macOS/WSL2 parity (per [04-environment-and-testing.md](04-environment-and-testing.md)) is actually checked in CI, not just asserted by hand:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]   # ubuntu-latest stands in for WSL2's linux/amd64 runtime
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go build ./...
      - run: go vet ./...
      - run: go test -race ./...
      - uses: golangci/golangci-lint-action@v6
```

### Verification

```bash
go build ./...                        # compiles clean
go vet ./...                           # no issues
golangci-lint run ./...                # clean, v2.12.2

./hackerfive --help                  # shows `scan` subcommand + flags
./hackerfive scan -t http://example.com   # exits 0, prints "no findings" JSON (stub engine)

docker build -t hackerfive:dev .     # succeeds
docker run --rm hackerfive:dev --help     # same usage output as native binary
```
Push a branch/PR and confirm the GitHub Actions run is green. Do this on **both** a macOS checkout and a WSL2 checkout — Step 1's whole point is proving the skeleton behaves identically on both dev machines before Steps 2-3 build on top of it.

---

## Step 2: HTTP Client & Request Engine (Week 2-3)

**Goal:** the scanner can fire concurrent, rate-limited HTTP requests with retry/backoff and proxy support, at 150+ req/sec against a local target.

### Files

| File | Purpose |
|---|---|
| `pkg/scanner/httpclient/client.go` | Wraps `net/http.Client` with a middleware chain |
| `pkg/scanner/httpclient/middleware.go` | Concrete middlewares: logging, retry-with-backoff, custom headers |
| `pkg/scanner/ratelimit/limiter.go` | Thin wrapper over `golang.org/x/time/rate` for configurable QPS |
| `pkg/scanner/hosterrors/cache.go` | Tracks consecutive errors per host; `ShouldSkip` lets the engine stop hitting a host that's crossed the error threshold instead of burning the rest of an ID-enumeration run on a dead target |
| `pkg/scanner/workerpool/pool.go` | Fixed-size worker pool for concurrent job execution |
| `pkg/scanner/vars/substitute.go` | Request templating: `{{BaseURL}}`, `{{RangeInt(a\|b)}}`, arbitrary `{{Var}}` substitution |
| `pkg/scanner/engine.go` | Extended (not new) — wires httpclient + workerpool + ratelimit + hosterrors into `Run()` |
| `pkg/scanner/httpclient/fuzz_test.go` | `testing.F` fuzz target seeded with malformed/edge-case responses — the scanner parses untrusted target responses, which is its own attack surface |
| `tests/unit/httpclient_test.go` | Middleware chain + retry/backoff behavior against `httptest.Server` |
| `tests/unit/workerpool_test.go` | Pool submission/drain correctness + throughput benchmark |
| `tests/unit/ratelimit_test.go` | QPS enforcement within tolerance |
| `tests/unit/hosterrors_test.go` | Error-count threshold and skip behavior, including reset on a subsequent success |

### Key types/functions

```go
// pkg/scanner/httpclient/client.go
type Config struct {
    Timeout             time.Duration // per-request; a stuck request must not stall the whole worker pool
    MaxRedirects        int           // 0 = don't follow; net/http follows by default, this makes it explicit
    InsecureSkipVerify  bool          // TLS verify off — only for lab targets with self-signed certs; defaults to false (verify on)
    MaxIdleConnsPerHost int           // explicit connection-pool size instead of relying on http.DefaultTransport's default
}
type Client struct { http *http.Client }
func New(cfg Config, mws ...Middleware) *Client
func (c *Client) Do(req *http.Request) (*http.Response, error)

// pkg/scanner/httpclient/middleware.go
type Middleware func(http.RoundTripper) http.RoundTripper
func WithLogging() Middleware
func WithRetry(maxAttempts int, backoff time.Duration) Middleware
func WithHeaders(h map[string]string) Middleware
// Proxy is set directly on the underlying http.Transport.Proxy, not a middleware

// pkg/scanner/ratelimit/limiter.go
type Limiter struct{ rl *rate.Limiter }
func New(qps int) *Limiter
func (l *Limiter) Wait(ctx context.Context) error

// pkg/scanner/hosterrors/cache.go
const DefaultThreshold = 5 // consecutive errors before ShouldSkip returns true; Config.HostErrorThreshold (Step 1) overrides this, 0 means "use the default"
type Cache struct{ threshold int } // mu + map[string]int internal, not exported
func New(threshold int) *Cache
func (c *Cache) RecordError(host string)   // increments the host's consecutive-error count
func (c *Cache) RecordSuccess(host string) // resets the host's count to 0
func (c *Cache) ShouldSkip(host string) bool // true once the host's count has reached threshold

// pkg/scanner/workerpool/pool.go
type Job func(ctx context.Context) error
type Pool struct{ size, queueDepth int }
func New(ctx context.Context, size, queueDepth int) *Pool // ctx cancellation drains the pool and stops accepting new jobs; engine.go constructs this with queueDepth = 2 * size unless a caller has a reason to override
func (p *Pool) Submit(job Job) error // blocks until queued or ctx is done; returns ctx.Err() if cancelled — bounded queue, not unbounded, so a slow target can't OOM the scanner
func (p *Pool) Wait() []error // each worker goroutine recovers a panicking Job and converts it to an error in the returned slice — one bad job must not crash the whole scan

// pkg/scanner/vars/substitute.go
type Context struct {
    BaseURL string
    Vars    map[string]string
}
func Render(input string, ctx Context) (string, error)
func RangeInt(min, max int) []int
```
`vars.Render` is a plain string-substitution helper, not tied to the (stubbed) `pkg/template` YAML engine — the IDOR detector (Step 3) calls it directly to turn an `endpointTemplate` string like `/api/users/{{id}}` plus a generated ID into a request path, so IDOR doesn't have to wait on Phase 1b's template parser. The same function gets reused by the real YAML engine in Phase 1b once that exists — built once, two callers.

**Retry policy, explicitly:**
- Retried: connection errors (refused/reset/timeout) and `5xx` and `429` responses.
- Not retried: any other `4xx` — a 401/403/404 is a real answer, not a transient failure, and retrying it would corrupt the Step 3 baseline sampling (a flaky retry could turn a clean "denied" signature into a mixed one).
- Backoff: attempt *n*'s delay is `min(backoff * 2^(n-1), 2*backoff)` plus up to ±20% jitter (avoids a thundering-herd retry pattern against a target that's rate-limiting the scanner) — with the `WithRetry(maxAttempts, backoff)` signature above, `maxAttempts=3` and `backoff=500ms` gives delays of ~500ms, ~1s, capped at 2s.

**Request lifecycle, explicitly (this is what item 3 of the review flagged as missing):**
- **Timeout:** every request gets `Config.Timeout` via `context.WithTimeout` per-call, not just a client-wide default — a single stuck request must not hold a worker-pool slot indefinitely.
- **Redirects:** `MaxRedirects` defaults to a small number (e.g. 5); IDOR/misconfig checks generally want to inspect the redirect response itself (a 302 to `/login` is itself a signal), so the detector layer can also set `http.Client.CheckRedirect` to stop-and-report rather than silently follow.
- **TLS:** verify is on by default; `--insecure` (mapped to `InsecureSkipVerify`) is an explicit, opt-in CLI flag for lab targets with self-signed certs (crAPI, DVWA, etc.) — never the default, since real bug-bounty targets should be verified.
- **Connection pooling:** `MaxIdleConnsPerHost` is set explicitly (not left at `http.DefaultTransport`'s default of 2, which throttles concurrent requests to the same host) — sized to roughly match `Config.Concurrency` so the worker pool isn't bottlenecked by connection reuse limits.
- **Proxy:** `Config.ProxyURL` (from `--proxy`, Step 1), if non-empty, is parsed with `url.Parse` and set on `http.Transport.Proxy` via `http.ProxyURL(...)`; an invalid URL is a `Config.Validate()` error, not a runtime failure discovered mid-scan.
- **Target down / rate-limited:** a non-2xx/3xx response or connection error is not itself a `Finding` — it's returned to the caller (detector) as a normal `(*http.Response, error)` pair; retry/backoff (via `WithRetry`) absorbs transient failures, and a target that's consistently unreachable surfaces as a scan-level error, not a silent empty result.
- **Host error cache:** every connection error or 5xx increments that host's count in `hosterrors.Cache`; a success resets it. Once a host crosses the threshold, the engine calls `ShouldSkip` before issuing further requests to it and stops early — this matters most for IDOR's sequential-ID enumeration, where a broken target would otherwise absorb the full ID range in retries instead of failing fast.

### Verification

```bash
go test ./pkg/scanner/... -race -v          # unit tests pass on both platforms
```
- **Retry/backoff:** test spins up `httptest.Server` returning 500 for the first N requests, 200 after — assert the client eventually succeeds within the configured `maxAttempts`.
- **Rate limiter:** test asserts requests against a QPS=10 limiter land within tolerance over a 1s window (real wall-clock, small enough to be fast and deterministic in CI).
- **Proxy:** covered by a unit test using a local `httptest`-based proxy stub, not a live MitmProxy — manual smoke test via MitmProxy (per [04-environment-and-testing.md](04-environment-and-testing.md)) is a nice-to-have, not a CI gate.
- **Backpressure/cancellation:** test submits more jobs than `queueDepth` from a slow producer and asserts `Submit` blocks (doesn't drop or OOM); a second test cancels the pool's `context.Context` mid-run and asserts `Wait()` returns promptly with in-flight jobs reporting `context.Canceled` rather than hanging.
- **Panic isolation:** test submits one `Job` that panics alongside several normal jobs; asserts `Wait()` returns an error for the panicking job (not an unrecovered panic that kills the test binary) and that the other jobs still complete.
- **Retry policy:** table-driven test asserting `429` and `5xx` responses are retried up to `maxAttempts` while a `401`/`403`/`404` is returned to the caller on the first attempt, no retry.
- **Host error cache:** test asserts `ShouldSkip` flips to `true` only after `threshold` consecutive errors, and that an intervening `RecordSuccess` resets the count.
- **Fuzzing (seeded, not a CI gate yet):** `go test -fuzz=FuzzResponseParsing -fuzztime=30s ./pkg/scanner/httpclient/` runs locally/nightly against a seed corpus of malformed responses (truncated bodies, invalid headers, oversized content-length) — not part of the required PR check in Phase 1a, just seeded now so it exists to run.
- **Throughput (the roadmap's actual Week 2-3 deliverable):**
  ```bash
  go test -bench=BenchmarkWorkerPool -benchtime=3s ./pkg/scanner/workerpool/
  ```
  Benchmark hits a local `httptest.Server`, not a live network target, so the ≥150 req/sec bar is reproducible identically on the Mac (native arm64) and the Windows teammate's WSL2 (linux/amd64) — no dependency on network conditions or which machine runs it.
- `go vet ./...` and `golangci-lint run ./...` still clean.

---

## Step 3: IDOR Detector (Week 3-4)

**Goal:** a working IDOR detector that finds at least one real cross-account access issue in crAPI, with a design that treats "different content per ID" and "unauthorized access" as the two different things they are (see the review discussion above — a public/private content split across sequential IDs is not an IDOR, and conflating the two is the main source of false positives in naive IDOR scanners).

Two modes, both implemented in this step:
- **Baseline mode (primary, high-confidence):** requires two unrelated account tokens — `ownerToken` (presumed to legitimately own some resources) and `otherToken` (a different account with no business accessing them). Algorithm, concretely:
  1. `strategy.Generate()` produces the candidate ID list.
  2. For every candidate ID, the detector issues **two** `GET`s — one with `ownerToken`, one with `otherToken` — and signs both responses (`compare.Sign`).
  3. `baseline.Establish` runs a majority vote over all the `otherToken` signatures to find the "denied" cluster (see `MinBaselineSamples`/`BaselineMajorityThreshold` below) — this is what most of the ID space should look like from an account with no access.
  4. An ID is flagged as a `Finding` only when **both** hold: `otherToken`'s signature for that ID is `Bypassed` (differs from the denied baseline) **and** `ownerToken`'s signature for that ID looks like real content (status `200` and non-trivial `BodySize`). The `ownerToken` check exists specifically so a bare 5xx or a broken-endpoint anomaly on the `otherToken` side isn't mistaken for a genuine content leak — the `otherToken` deviation only counts as a finding if there's real, owner-confirmed data behind that ID.
  This is a real authorization test, not a content-difference test.
- **Heuristic mode (fallback, low-confidence):** used only when a second account token isn't available (e.g. quick recon). Single token, sequential-ID enumeration, response-signature diff between IDs. Explicitly labeled `Confidence: "low"` on the resulting `Finding` and intended for manual triage, not as a standalone signal — it cannot distinguish "IDOR" from "this ID legitimately has different, non-sensitive content" (e.g. two different public product pages).

### Files

| File | Purpose |
|---|---|
| `pkg/detectors/idor/strategy.go` | ID enumeration strategies (sequential ints, wordlist) |
| `pkg/detectors/idor/compare.go` | Response signature type + equality/diff check |
| `pkg/detectors/idor/baseline.go` | Establishes the "denied" signature from sampled responses and flags deviations from it — the baseline-mode core |
| `pkg/detectors/idor/detector.go` | Ties strategy + HTTP client + baseline/heuristic comparison together, emits `Finding`s |
| `tests/unit/detector_idor_test.go` | Table-driven tests against mocked `httptest.Server` responses, covering both modes |
| `tests/fixtures/responses/idor_*.json` | Canned per-ID, per-account response bodies for the mock server (owner-account and other-account variants, per the example in [04-environment-and-testing.md](04-environment-and-testing.md)) |
| `tests/integration/idor_crapi_test.go` | Build-tag `integration`; runs against a live crAPI instance with two real test accounts, skipped unless `CRAPI_BASE_URL` is set |

### Key types/functions

```go
// pkg/detectors/idor/strategy.go
type Strategy interface {
    Generate() []string
}
type SequentialIntStrategy struct{ Start, End int }
type WordlistStrategy struct{ Words []string }

// pkg/detectors/idor/compare.go
type Signature struct {
    StatusCode int
    BodySize   int
    Hash       string   // SHA256 of body
    Keywords   []string // presence of "email", "name", "user_id", etc. — sorted, so two signatures with the same keyword set compare equal regardless of extraction order
}
func Sign(resp *http.Response, body []byte) Signature
// Same reports two signatures as equivalent: StatusCode must match exactly, AND
// (Hash matches OR (BodySize within 5% of each other AND Keywords sets are equal)).
// The size+keywords fallback exists because two "denied" bodies can differ byte-for-byte
// (a timestamp or request-id in an error envelope) while still being the same denial.
func (a Signature) Same(b Signature) bool
func (a Signature) DiffersFrom(b Signature) bool // !Same(b)

// pkg/detectors/idor/baseline.go
const MinBaselineSamples = 3 // fewer than this and a majority signature can't be trusted — Establish returns an error, and detector.go falls back to heuristic mode for that endpoint with a logged warning
const BaselineMajorityThreshold = 0.8 // >=80% of samples must be Same() as each other to call the cluster "the" denied signature
type Baseline struct{ denied Signature } // the majority-vote "denied" signature sampled from otherToken across many IDs
func Establish(samples []Signature) (Baseline, error) // error if len(samples) < MinBaselineSamples, or if no cluster reaches BaselineMajorityThreshold (samples too inconsistent to establish a denial pattern — e.g. the endpoint doesn't consistently reject otherToken at all, which is itself worth logging, not silently swallowing)
func (b Baseline) Bypassed(sig Signature) bool // true if sig.DiffersFrom(b.denied) — i.e. access that should've been refused wasn't

// pkg/detectors/idor/detector.go
type Detector struct {
    client   *httpclient.Client
    strategy Strategy
}
func New(client *httpclient.Client, strategy Strategy) *Detector
// otherToken == "" falls back to heuristic mode (single-token signature diff, Confidence: "low")
// endpointTemplate is a path like "/api/users/{{id}}" — the detector substitutes each generated ID via vars.Render (Step 2) to build the actual request path
func (d *Detector) Run(ctx context.Context, endpointTemplate, ownerToken, otherToken string) ([]detectors.Finding, error)
```

Enumeration and comparison only ever issue `GET` requests — no state-mutating verbs — consistent with the read-only-scanner rule in [CLAUDE.md](../CLAUDE.md). Both tokens are threaded through from `Config.AuthToken` / `Config.OtherAuthToken` (Step 1), which only ever come from a flag or environment variable, never a literal in code.

**Example `Finding` for a baseline-mode hit** (shape from `pkg/detectors/types.go`, Step 1):
```json
{
  "id": "idor-crapi-user-1234",
  "type": "idor",
  "severity": "high",
  "confidence": "high",
  "target": "http://localhost:8888/identity/api/v2/user/dashboard/1234",
  "description": "otherToken retrieved real user data for ID 1234, which does not match the established denied-access baseline for this endpoint",
  "evidence": {
    "id": "1234",
    "owner_status": "200",
    "other_status": "200",
    "denied_baseline_status": "403",
    "denied_baseline_sample_size": "17"
  }
}
```

### Test cases (`tests/unit/detector_idor_test.go`)

Table-driven, each case backed by a fixture in `tests/fixtures/responses/idor_*.json` mapping (ID, token) pairs to canned responses on the mock `httptest.Server`:

| Case | Setup | Expected |
|---|---|---|
| Clean baseline, no leak | `otherToken` gets 403 for every ID (20 IDs); `ownerToken` gets 200 for its own ID | 0 findings |
| Classic IDOR | `otherToken` gets 403 for 19/20 IDs, 200 (real content) for 1; `ownerToken` gets 200 for that same ID | 1 finding, `Confidence: "high"` |
| Server error, not a leak | `otherToken` gets 403 for 19/20 IDs, 500 for 1; `ownerToken` also gets 500 for that ID | 0 findings — deviation exists but `ownerToken` doesn't confirm real content |
| Broken endpoint, not IDOR | `otherToken` gets 500 for the ID in question, but `ownerToken` gets 200 | 0 findings — `otherToken`'s deviation is a server error, not evidence of unauthorized *access* |
| Insufficient samples | Only 2 candidate IDs (`< MinBaselineSamples`) | `Establish` returns an error; detector logs a warning and falls back to heuristic mode for this run |
| No consistent denial pattern | `otherToken` responses split ~50/50 between two different signatures across 20 IDs | `Establish` returns an error (no cluster reaches `BaselineMajorityThreshold`); falls back to heuristic mode |
| Heuristic mode, uniform content | `otherToken` only; all sequential IDs return the same signature | 0 findings |
| Heuristic mode, differing content | `otherToken` only; one ID's signature differs from the rest | 1 finding, `Confidence: "low"`, description notes manual triage needed |
| Heuristic mode, legitimately varied public content | `otherToken` only; every ID returns a *different* signature (e.g. distinct public product pages) | every differing ID is flagged `Confidence: "low"` — this is the known, documented limitation of heuristic mode, not a bug; the test exists to lock in that documented behavior rather than to assert it's "correct" |

### Integration test setup: crAPI as an unmodified, separate target

**Principle:** crAPI (and DVWA/Juice Shop later) is the *target*, HackerFive is the *scanner* — they run as two separate things connected only by network, exactly like a real bug-bounty engagement. Never copy HackerFive into crAPI's container or otherwise give it filesystem/exec access to the target; that would test a mode of operation ("scanner has local access to the target") that doesn't exist in production and would validate nothing real. Keep crAPI's `docker-compose` stack unmodified/upstream, so it stays easy to pull a newer crAPI release later.

1. **Bring up the target, from a clean state:**
   ```bash
   git clone https://github.com/OWASP/crAPI.git
   cd crAPI/deploy && docker compose down -v   # wipe any stale data from a prior run
   docker compose up -d
   ```
2. **Script the two test accounts** — crAPI has no pre-seeded owner/other tokens; they come from its signup flow. Don't do this by hand each time. A small setup script (`tests/integration/scripts/crapi_setup.sh`, or a Go `TestMain` helper under the `integration` build tag) should: sign up two accounts via crAPI's `/identity/api/auth/signup`, log in via `/identity/api/auth/login` to get each token, and print/export them as `CRAPI_OWNER_TOKEN`/`CRAPI_OTHER_TOKEN` — this is what makes the integration test repeatable instead of a manual, undocumented step.
3. **Run the scanner against it** — either natively, or from its own container joined to crAPI's Docker network (see below); both are "outside, over HTTP," matching real usage.

### Verification

```bash
go test ./pkg/detectors/idor/... -race -v     # mocked, no network — covers both modes, passes on both platforms
```
Manual run against the live target (identical steps on Mac Docker Desktop and Windows/WSL2 Docker Desktop), using the two accounts from the setup script above:
```bash
export CRAPI_BASE_URL=http://localhost:8888
go run ./cmd/hackerfive scan -t $CRAPI_BASE_URL --detector idor \
  --endpoint /identity/api/v2/user/dashboard/{{id}} \
  --auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN"
# Expect: at least 1 finding of type "idor", Confidence: "high", printed as JSON
```
**Same run, from HackerFive's own container** instead of `go run` (validates the Step 1 `Dockerfile`, and is what CI would eventually do without needing a Go toolchain on the runner):
```bash
docker build -t hackerfive:dev .
# Join crAPI's compose network so the container can reach crAPI by service name instead of localhost
docker run --rm --network crapi_default hackerfive:dev \
  scan -t http://web:8888 --detector idor \
  --endpoint /identity/api/v2/user/dashboard/{{id}} \
  --auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN"
```
(`crapi_default` and `web` are crAPI's compose project/service names — confirm with `docker compose ps`/`docker network ls` if a newer crAPI release renames them. On Linux/WSL2, `--network host` is a quicker one-off alternative; it's not available on Docker Desktop for Mac, where `http://host.docker.internal:8888` is the equivalent.)

Then the opt-in integration test:
```bash
go test -tags=integration ./tests/integration/... -v   # only runs with CRAPI_BASE_URL set (and two account tokens)
```
`go vet ./...` and `golangci-lint run ./...` clean, same as prior steps.

---

## Definition of Done (Phase 1a, Weeks 1-4)

- [ ] `go build ./...`, `go vet ./...`, `golangci-lint run ./...` clean — verified on **both** a macOS and a WSL2 checkout
- [ ] GitHub Actions CI green on the branch/PR
- [ ] `hackerfive scan` runs against a live crAPI instance (two test accounts) and returns ≥1 high-confidence IDOR finding as JSON
- [ ] Worker pool respects context cancellation and backpressure (bounded queue, `Submit` blocks rather than drops or OOMs)
- [ ] Host error cache skips a host after its consecutive-error threshold is crossed, and resets on success
- [ ] `make build`, `make test`, `make lint` all work and match the manual commands above
- [ ] Unit tests pass for `scanner/httpclient`, `scanner/ratelimit`, `scanner/workerpool`, `scanner/hosterrors`, `detectors/idor` (both baseline and heuristic modes; coverage tracked, not gated at 80% yet — that's a Phase 1b Testing & Validation target, see [03-development-roadmap.md](03-development-roadmap.md))
- [ ] No hardcoded credentials/tokens anywhere — auth comes from `--auth-token`/`--other-auth-token` or their env-var equivalents only
- [ ] No request path other than `GET` is issued by any detector — scanner remains read-only
- [ ] `docker build` succeeds and the resulting image's `--help` output matches the native binary's

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — package layout and dependency choices this plan follows
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-3 roadmap this plan is a slice of
- [04-environment-and-testing.md](04-environment-and-testing.md) — dev environment (macOS + WSL2) and test-target setup this plan assumes
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — read-only/no-exfiltration constraints reflected in the IDOR detector design
- [20-setup-testing-targets.md](20-setup-testing-targets.md) — step-by-step crAPI bring-up and account/token minting for this step's integration test
