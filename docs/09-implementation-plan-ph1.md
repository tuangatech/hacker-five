# Phase 1a Implementation Plan — Weeks 1-4 (Foundation Kickoff)

> Part of the [VulnDetector documentation set](../README.md).

## Scope

[03-development-roadmap.md](03-development-roadmap.md) splits Phase 1 ("Foundation") into **Phase 1a (Weeks 1-4)** and **Phase 1b** (see that doc for Phase 1b's current week numbers). This plan covers Phase 1a only — the three chunks that get a working, IDOR-only scanner running end-to-end:
1. Project Setup & Architecture (Week 1-2)
2. HTTP Client & Request Engine (Week 2-3)
3. IDOR Detector (Week 3-4)

Phase 1b (misconfiguration detector, Nuclei-compatible template parser, native YAML template engine, full testing/validation pass, packaging) gets its own follow-up plan once this foundation is merged and working end-to-end. The repo currently has no code — this is a from-scratch build.

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

---

## Step 1: Project Setup & Architecture (Week 1-2)

**Goal:** a compiling skeleton with a working `scan` CLI command, CI green, and every package stubbed so Steps 2-3 have somewhere to land.

### Files

| File | Purpose |
|---|---|
| `go.mod` | Module `github.com/<org>/vulndetector`, `go 1.21` minimum directive (toolchain itself is 1.26.5 per env doc) |
| `cmd/vulndetector/main.go` | Thin entrypoint — calls into the root Cobra command and sets the process exit code |
| `cmd/vulndetector/root.go` | Root Cobra command, global flags (`--proxy`, `--timeout`, `--output`) |
| `cmd/vulndetector/scan.go` | `scan` subcommand — flags (`--targets/-t`, `--templates`, `--concurrency/-c`, `--rate-limit`, `--auth-token`, `--other-auth-token`) wired into `scanner.Config` |
| `pkg/scanner/config.go` | Shared `Config` struct passed from CLI into the engine |
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

### Key types/functions

```go
// cmd/vulndetector/scan.go
func newScanCmd() *cobra.Command

// pkg/scanner/config.go
type Config struct {
    Targets       []string
    TemplatePaths []string
    Concurrency   int
    RateLimit     int
    ProxyURL      string
    Timeout       time.Duration
    OutputFormat  string
    AuthToken      string // primary/"owner" account token — from --auth-token or VULNDETECTOR_AUTH_TOKEN, never hardcoded
    OtherAuthToken string // second, unrelated account token used for IDOR baseline comparison (Step 3) — from --other-auth-token or VULNDETECTOR_OTHER_AUTH_TOKEN; optional, but required for high-confidence IDOR findings
}

// pkg/scanner/engine.go
type Engine struct {
    cfg Config
}
func New(cfg Config) *Engine
func (e *Engine) Run(ctx context.Context) ([]detectors.Finding, error) // stub: returns nil, nil

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

### Verification

```bash
go build ./...                        # compiles clean
go vet ./...                           # no issues
golangci-lint run ./...                # clean, v2.12.2

./vulndetector --help                  # shows `scan` subcommand + flags
./vulndetector scan -t http://example.com   # exits 0, prints "no findings" JSON (stub engine)

docker build -t vulndetector:dev .     # succeeds
docker run --rm vulndetector:dev --help     # same usage output as native binary
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
| `pkg/scanner/workerpool/pool.go` | Fixed-size worker pool for concurrent job execution |
| `pkg/scanner/vars/substitute.go` | Request templating: `{{BaseURL}}`, `{{RangeInt(a\|b)}}`, arbitrary `{{Var}}` substitution |
| `pkg/scanner/engine.go` | Extended (not new) — wires httpclient + workerpool + ratelimit into `Run()` |
| `tests/unit/httpclient_test.go` | Middleware chain + retry/backoff behavior against `httptest.Server` |
| `tests/unit/workerpool_test.go` | Pool submission/drain correctness + throughput benchmark |
| `tests/unit/ratelimit_test.go` | QPS enforcement within tolerance |

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

// pkg/scanner/workerpool/pool.go
type Job func(ctx context.Context) error
type Pool struct{ size, queueDepth int }
func New(ctx context.Context, size, queueDepth int) *Pool // ctx cancellation drains the pool and stops accepting new jobs
func (p *Pool) Submit(job Job) error // blocks until queued or ctx is done; returns ctx.Err() if cancelled — bounded queue, not unbounded, so a slow target can't OOM the scanner
func (p *Pool) Wait() []error

// pkg/scanner/vars/substitute.go
type Context struct {
    BaseURL string
    Vars    map[string]string
}
func Render(input string, ctx Context) (string, error)
func RangeInt(min, max int) []int
```

**Request lifecycle, explicitly (this is what item 3 of the review flagged as missing):**
- **Timeout:** every request gets `Config.Timeout` via `context.WithTimeout` per-call, not just a client-wide default — a single stuck request must not hold a worker-pool slot indefinitely.
- **Redirects:** `MaxRedirects` defaults to a small number (e.g. 5); IDOR/misconfig checks generally want to inspect the redirect response itself (a 302 to `/login` is itself a signal), so the detector layer can also set `http.Client.CheckRedirect` to stop-and-report rather than silently follow.
- **TLS:** verify is on by default; `--insecure` (mapped to `InsecureSkipVerify`) is an explicit, opt-in CLI flag for lab targets with self-signed certs (crAPI, DVWA, etc.) — never the default, since real bug-bounty targets should be verified.
- **Connection pooling:** `MaxIdleConnsPerHost` is set explicitly (not left at `http.DefaultTransport`'s default of 2, which throttles concurrent requests to the same host) — sized to roughly match `Config.Concurrency` so the worker pool isn't bottlenecked by connection reuse limits.
- **Target down / rate-limited:** a non-2xx/3xx response or connection error is not itself a `Finding` — it's returned to the caller (detector) as a normal `(*http.Response, error)` pair; retry/backoff (via `WithRetry`) absorbs transient failures, and a target that's consistently unreachable surfaces as a scan-level error, not a silent empty result.

### Verification

```bash
go test ./pkg/scanner/... -race -v          # unit tests pass on both platforms
```
- **Retry/backoff:** test spins up `httptest.Server` returning 500 for the first N requests, 200 after — assert the client eventually succeeds within the configured `maxAttempts`.
- **Rate limiter:** test asserts requests against a QPS=10 limiter land within tolerance over a 1s window (real wall-clock, small enough to be fast and deterministic in CI).
- **Proxy:** covered by a unit test using a local `httptest`-based proxy stub, not a live MitmProxy — manual smoke test via MitmProxy (per [04-environment-and-testing.md](04-environment-and-testing.md)) is a nice-to-have, not a CI gate.
- **Backpressure/cancellation:** test submits more jobs than `queueDepth` from a slow producer and asserts `Submit` blocks (doesn't drop or OOM); a second test cancels the pool's `context.Context` mid-run and asserts `Wait()` returns promptly with in-flight jobs reporting `context.Canceled` rather than hanging.
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
- **Baseline mode (primary, high-confidence):** requires two unrelated account tokens — `ownerToken` (presumed to legitimately own some resources) and `otherToken` (a different account with no business accessing them). For each candidate ID, the detector samples `otherToken`'s response across many IDs to establish the "denied" signature (typically a 401/403/404 cluster) — the actual baseline — then flags any ID where `otherToken` gets back something that does *not* match that denied baseline, i.e. it saw real data it shouldn't have. This is a real authorization test, not a content-difference test.
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
    Keywords   []string // presence of "email", "name", "user_id", etc.
}
func Sign(resp *http.Response, body []byte) Signature
func (a Signature) DiffersFrom(b Signature) bool

// pkg/detectors/idor/baseline.go
type Baseline struct{ denied Signature } // majority-vote "denied" signature sampled from otherToken across many IDs
func Establish(samples []Signature) Baseline
func (b Baseline) Bypassed(sig Signature) bool // true if sig doesn't match the denied baseline — i.e. access that should've been refused wasn't

// pkg/detectors/idor/detector.go
type Detector struct {
    client   *httpclient.Client
    strategy Strategy
}
func New(client *httpclient.Client, strategy Strategy) *Detector
// otherToken == "" falls back to heuristic mode (single-token signature diff, Confidence: "low")
func (d *Detector) Run(ctx context.Context, endpointTemplate, ownerToken, otherToken string) ([]detectors.Finding, error)
```

Enumeration and comparison only ever issue `GET` requests — no state-mutating verbs — consistent with the read-only-scanner rule in [CLAUDE.md](../CLAUDE.md). Both tokens are threaded through from `Config.AuthToken` / `Config.OtherAuthToken` (Step 1), which only ever come from a flag or environment variable, never a literal in code.

### Verification

```bash
go test ./pkg/detectors/idor/... -race -v     # mocked, no network — covers both modes, passes on both platforms
```
Manual run against a live target (start crAPI per [04-environment-and-testing.md](04-environment-and-testing.md)'s Docker Compose instructions — identical steps on Mac Docker Desktop and Windows/WSL2 Docker Desktop), using two distinct crAPI test accounts:
```bash
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy && docker compose up -d

export CRAPI_BASE_URL=http://localhost:8888
go run ./cmd/vulndetector scan -t $CRAPI_BASE_URL --detector idor \
  --auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN"
# Expect: at least 1 finding of type "idor", Confidence: "high", printed as JSON
```
Then the opt-in integration test:
```bash
go test -tags=integration ./tests/integration/... -v   # only runs with CRAPI_BASE_URL set (and two account tokens)
```
`go vet ./...` and `golangci-lint run ./...` clean, same as prior steps.

---

## Definition of Done (Phase 1a, Weeks 1-4)

- [ ] `go build ./...`, `go vet ./...`, `golangci-lint run ./...` clean — verified on **both** a macOS and a WSL2 checkout
- [ ] GitHub Actions CI green on the branch/PR
- [ ] `vulndetector scan` runs against a live crAPI instance (two test accounts) and returns ≥1 high-confidence IDOR finding as JSON
- [ ] Worker pool respects context cancellation and backpressure (bounded queue, `Submit` blocks rather than drops or OOMs)
- [ ] Unit tests pass for `scanner/httpclient`, `scanner/ratelimit`, `scanner/workerpool`, `detectors/idor` (both baseline and heuristic modes; coverage tracked, not gated at 80% yet — that's a Phase 1b Testing & Validation target, see [03-development-roadmap.md](03-development-roadmap.md))
- [ ] No hardcoded credentials/tokens anywhere — auth comes from `--auth-token`/`--other-auth-token` or their env-var equivalents only
- [ ] No request path other than `GET` is issued by any detector — scanner remains read-only
- [ ] `docker build` succeeds and the resulting image's `--help` output matches the native binary's

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — package layout and dependency choices this plan follows
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-3 roadmap this plan is a slice of
- [04-environment-and-testing.md](04-environment-and-testing.md) — dev environment (macOS + WSL2) and test-target setup this plan assumes
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — read-only/no-exfiltration constraints reflected in the IDOR detector design
