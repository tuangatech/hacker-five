# Phase 1a Implementation Plan — Weeks 1-4 (Foundation Kickoff)

> Part of the [HackerFive documentation set](../README.md).

## Objective

Phase 1a's job is to prove the scanner works at all, end-to-end, on one real vulnerability class — before spending time on breadth (Phase 1b). That class is IDOR (Insecure Direct Object Reference): an endpoint that returns another user's data for an ID it shouldn't, because it checks that the ID is *valid* but not that the caller *owns* it.

**What it detects, and how:**
- **Baseline mode (primary, high-confidence):** two accounts, `ownerToken` and `otherToken`. The detector requests the same range of candidate IDs with both, and asks: what does "access denied" normally look like for `otherToken`? It builds that answer by majority vote across all the IDs it tried. Any ID where `otherToken` gets something that *doesn't* match that denied pattern — but `ownerToken` gets real content for the same ID — is flagged. The `ownerToken` check exists so a broken endpoint or a random 5xx isn't mistaken for a leak.
- **Heuristic mode (fallback, low-confidence):** only one token available, no second account to compare against. Just checks whether responses across sequential IDs look different from each other. Cheaper, but can't tell "this is someone else's private data" apart from "this is just a different public page" — flagged low-confidence for manual review, not treated as a real finding on its own.

The detector only ever issues `GET` requests — it reads and compares, never writes or mutates target state, per [CLAUDE.md](../CLAUDE.md)'s read-only rule.

## Scope

[03-development-roadmap.md](03-development-roadmap.md) splits Phase 1 ("Foundation") into **Phase 1a (Weeks 1-4)** and **Phase 1b** (see that doc for Phase 1b's current week numbers). This plan covers Phase 1a only — the three chunks that get a working, IDOR-only scanner running end-to-end:
1. Project Setup & Architecture (Week 1-2)
2. HTTP Client & Request Engine (Week 2-3)
3. IDOR Detector (Week 3-4)

Phase 1b (misconfiguration detector, Nuclei-compatible template parser, native YAML template engine, full testing/validation pass, packaging) has its own follow-up plan — see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — written after this foundation was merged and working end-to-end. This plan started from an empty repo; Phase 1a is now complete (see the Definition of Done below) and Phase 1b Step 1 (the misconfig detector) has since landed on top of it.

**Boundary this plan does *not* cross:** the roadmap's Phase 1b success metrics ("8+ IDOR findings in crAPI, 100% accuracy," "<5% false positives") are targets for Phase 1b's Testing & Validation step (see [03-development-roadmap.md](03-development-roadmap.md) for its current week numbers), which needs both template engines and a dedicated validation pass. The exit bar for *this* plan is Phase 1a's own checkpoint: the IDOR detector's logic is correct, unit-tested, and demonstrably finds at least one known issue against a live crAPI instance — not the full accuracy claim.

Dev environment (macOS + WSL2/Windows 11) is already covered by [04-environment-and-testing.md](04-environment-and-testing.md); this plan assumes that setup is done. Every command below runs identically on both.

## Dependencies used in this plan

Exact pins live in `go.mod` — source of truth, not duplicated here. Two reasoning notes worth keeping:

Regex matching uses the standard library `regexp` (RE2) — no third-party regex dependency yet (see the fix in [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md), which previously named a package that doesn't exist). `gopkg.in/yaml.v3` and `github.com/json-iterator/go` aren't added until Phase 1b's template-parser work (see [03-development-roadmap.md](03-development-roadmap.md)), when the Nuclei-compatible parser and native YAML template engine actually need them — no point pulling a dependency before the code that uses it exists.

This Phase 1a plan's IDOR detector (Step 3) doesn't use `regexp` at all — `compare.go`'s `Signature` diff is status code + body-size tolerance + hash + sorted keyword list, no pattern matching. A regex matcher only enters the picture once Phase 1b's native YAML template engine parses a `type: regex` matcher generically (shared by misconfig and IDOR templates alike) — see [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)'s note on the IDOR baseline-comparison format being the one place a PCRE-only pattern (backreference, lookahead) could force adding `regexp2`.

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
| `pkg/detectors/misconfig/detector.go` | Stub in Phase 1a, out of scope here — real logic (fixed built-in rule tables, not the Nuclei-compatible parser) landed in Phase 1b Step 1, see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) |
| `pkg/template/parser.go` | Stub only (`type Template struct{}`) — real template parsing (Phase 1b's Nuclei-compatible and native YAML parsers — see [03-development-roadmap.md](03-development-roadmap.md)) is out of scope here |
| `pkg/reporter/output.go` | Minimal JSON writer so `--output json` works end-to-end from day one |
| `templates/idor/example.yaml` | Documentation-only example of the eventual template shape (not consumed by code yet) |
| `Dockerfile` | Minimal single-stage build for now — just needs `docker build` to succeed; multi-stage optimization is a Phase 1b packaging task (see [03-development-roadmap.md](03-development-roadmap.md)). Keep its `golang:` tag pinned to whatever [04-environment-and-testing.md](04-environment-and-testing.md) currently specifies as the dev toolchain version — don't let the two drift apart |
| `.github/workflows/ci.yml` | As specified in [04-environment-and-testing.md](04-environment-and-testing.md) — `go test -race`, `go vet`, `golangci-lint run`. Matrix build (`ubuntu-latest`, `macos-latest`) so macOS/WSL2 parity is actually checked in CI, not just asserted by hand |
| `.gitignore` | As specified in [04-environment-and-testing.md](04-environment-and-testing.md) |

### CLI flags

Run `hackerfive scan --help` / `hackerfive --help` for the full flag list, types, and defaults — not duplicated here. A few flags carry design reasoning worth keeping:
- `--endpoint` takes a path with an `{{id}}` placeholder (e.g. `/workshop/api/mechanic/mechanic_report?report_id={{id}}`) — a stopgap until Phase 1b's template engine can supply this from a YAML file instead of a flag.
- `--insecure` (skip TLS verification) defaults to `false` and must always be explicitly opted into — lab targets only (crAPI/DVWA self-signed certs), never the default, since real bug-bounty targets should be verified.
- `--auth-token`/`--other-auth-token` (env: `HACKERFIVE_AUTH_TOKEN`/`HACKERFIVE_OTHER_AUTH_TOKEN`) — the flag wins if both are set; omitting `--other-auth-token` falls back to IDOR's heuristic (low-confidence) mode rather than failing.
- `--templates` is accepted for CLI stability but unused until Phase 1b's template engine parses it.

`Config.Validate()` (`pkg/scanner/config.go`) rejects: empty `Targets`, `Concurrency <= 0`, `RateLimit <= 0`, an unrecognized `Detector`, `Detector == "idor"` with both tokens empty, `Detector == "idor"` with an empty `EndpointTemplate`, and a `ProxyURL` that fails `url.Parse`.

### Key types/functions

Signatures and field comments live in the source, not duplicated here: `cmd/hackerfive/scan.go` (`newScanCmd`), `pkg/scanner/config.go` (`Config`, `Validate`), `pkg/scanner/engine.go` (`Engine`, `Run`), `pkg/detectors/types.go` (`Finding`), `pkg/reporter/output.go` (`WriteJSON`).

### Verification

```bash
go build ./...                        # compiles clean
go vet ./...                           # no issues
golangci-lint run ./...                # clean, v2.12.2

./hackerfive --help                  # shows `scan` subcommand + flags
./hackerfive scan -t http://example.com   # exits 1: "validating config: unrecognized detector \"\"" — Config.Validate() requires --detector even at this stage, so this failure is the expected smoke-test result, not a bug

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

Signatures live in the source, not duplicated here: `pkg/scanner/httpclient/client.go` (`Config`, `Client`, `New`, `Do`), `middleware.go` (`Middleware`, `WithLogging`, `WithRetry`, `WithHeaders`), `pkg/scanner/ratelimit/limiter.go` (`Limiter`), `pkg/scanner/hosterrors/cache.go` (`Cache`, `DefaultThreshold = 5`), `pkg/scanner/workerpool/pool.go` (`Pool`, `Job`), `pkg/scanner/vars/substitute.go` (`Render`, `RangeInt`).

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
| `tests/integration/idor_crapi_test.go` | Build-tag `integration`; runs against a live crAPI instance — a positive-finding test (two real test accounts) and a negative-control test (owner token + a deliberately invalid one), both skipped unless their required env vars are set |

### Key types/functions

Signatures live in the source, not duplicated here: `pkg/detectors/idor/strategy.go` (`Strategy`, `SequentialIntStrategy`, `WordlistStrategy`), `compare.go` (`Signature`, `Sign`, `Same`/`DiffersFrom` — status code must match exactly, plus a hash match or a 5%-size-tolerance-and-keyword-set fallback, since two "denied" bodies can differ byte-for-byte on a timestamp/request-id while still being the same denial), `baseline.go` (`Baseline`, `Establish`, `MinBaselineSamples = 3`, `BaselineMajorityThreshold = 0.8`, `Bypassed`), `detector.go` (`Detector` — client, strategy, and a `hosterrors.Cache` from Step 2 — `New`, `Run`).

Enumeration and comparison only ever issue `GET` requests — no state-mutating verbs — consistent with the read-only-scanner rule in [CLAUDE.md](../CLAUDE.md). Both tokens are threaded through from `Config.AuthToken` / `Config.OtherAuthToken` (Step 1), which only ever come from a flag or environment variable, never a literal in code.

**Example `Finding` for a baseline-mode hit** (shape from `pkg/detectors/types.go`, Step 1):
```json
{
  "id": "idor-crapi-user-1234",
  "type": "idor",
  "severity": "high",
  "confidence": "high",
  "target": "http://localhost:8888/workshop/api/mechanic/mechanic_report?report_id=1234",
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

1. **Bring up the target, from a clean state** — see [20-setup-testing-targets.md](20-setup-testing-targets.md)'s crAPI "Bring it up" section for the exact, actively-maintained commands (not duplicated here, to avoid the two drifting apart).
2. **Script the two test accounts** — crAPI has no pre-seeded owner/other tokens; they come from its signup flow. Don't do this by hand each time. A small setup script (`tests/integration/scripts/crapi_setup.sh`, or a Go `TestMain` helper under the `integration` build tag) should: sign up two accounts via crAPI's `/identity/api/auth/signup`, log in via `/identity/api/auth/login` to get each token, and print/export them as `CRAPI_OWNER_TOKEN`/`CRAPI_OTHER_TOKEN` — this is what makes the integration test repeatable instead of a manual, undocumented step.
3. **Run the scanner against it** — either natively, or from its own container joined to crAPI's Docker network (see below); both are "outside, over HTTP," matching real usage.

### Verification

```bash
go test ./pkg/detectors/idor/... -race -v     # mocked, no network — covers both modes, passes on both platforms
```
Manual run against a live crAPI instance — account setup, report creation, and the exact scan command are in [20-setup-testing-targets.md](20-setup-testing-targets.md) (not duplicated here). Expect at least 1 finding of type `idor`, `Confidence: "high"`, printed as JSON.

**Same run, from HackerFive's own container** instead of the built binary (validates the Step 1 `Dockerfile`, and is what CI would eventually do without needing a Go toolchain on the runner):
```bash
docker build -t hackerfive:dev .
# Join crAPI's compose network so the container can reach crAPI by service name instead of localhost
docker run --rm --network crapi_default hackerfive:dev \
  scan -t http://web:8888 --detector idor \
  --endpoint '/workshop/api/mechanic/mechanic_report?report_id={{id}}' \
  --auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN"
```
(`crapi_default` and `web` are crAPI's compose project/service names — confirm with `docker compose ps`/`docker network ls` if a newer crAPI release renames them. On Linux/WSL2, `--network host` is a quicker one-off alternative; it's not available on Docker Desktop for Mac, where `http://host.docker.internal:8888` is the equivalent.)

Then the opt-in integration test:
```bash
go test -tags=integration ./tests/integration/... -v   # only runs with CRAPI_BASE_URL set (and two account tokens)
```
`TestIDORAgainstCRAPI` is the positive case above; `TestIDORAgainstCRAPI_NoFalsePositive` is its negative-control counterpart — same detector, same endpoint, but `otherToken` swapped for a syntactically-invalid one, asserting 0 findings. This strengthens Step 3's own exit bar (the detector's logic is demonstrably sound in both directions on a live target) without claiming the roadmap's broader `<5% false positives` metric, which — per this plan's Scope section — is still Phase 1b's dedicated validation pass to establish; see [20-setup-testing-targets.md](20-setup-testing-targets.md) for the manual/CLI equivalent of both.

`go vet ./...` and `golangci-lint run ./...` clean, same as prior steps.

---

## Definition of Done (Phase 1a, Weeks 1-4)

- [ ] `go build ./...`, `go vet ./...`, `golangci-lint run ./...` clean — verified on **both** a macOS and a WSL2 checkout. WSL2 side confirmed clean in this session (via `/mnt/c`); macOS has not been verified in any session on record — leaving unchecked until it is
- [ ] GitHub Actions CI green on the branch/PR — not re-checked in this session
- [x] `hackerfive scan` runs against a live crAPI instance (two test accounts) and returns ≥1 high-confidence IDOR finding as JSON — confirmed against `report_id` 1-6
- [x] Worker pool respects context cancellation and backpressure (bounded queue, `Submit` blocks rather than drops or OOMs)
- [x] Host error cache skips a host after its consecutive-error threshold is crossed, and resets on success
- [x] `make build`, `make test`, `make lint` all work and match the manual commands above
- [x] Unit tests pass for `scanner/httpclient`, `scanner/ratelimit`, `scanner/workerpool`, `scanner/hosterrors`, `detectors/idor` (both baseline and heuristic modes; coverage tracked, not gated at 80% yet — that's a Phase 1b Testing & Validation target, see [03-development-roadmap.md](03-development-roadmap.md))
- [x] No hardcoded credentials/tokens anywhere — auth comes from `--auth-token`/`--other-auth-token` or their env-var equivalents only
- [x] No request path other than `GET` is issued by **this plan's** `idor` detector — still true today. Repo-wide this no longer holds: Phase 1b Step 1's `misconfig` detector deliberately issues bounded `PUT`/`DELETE`/`PATCH` method probes and a capped `POST` default-creds check, justified against [CLAUDE.md](../CLAUDE.md)'s read-only rule in [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — not a regression of this item, just outside its original (idor-only) scope
- [x] `docker build` succeeds and the resulting image's `--help` output matches the native binary's

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — package layout and dependency choices this plan follows
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-3 roadmap this plan is a slice of
- [04-environment-and-testing.md](04-environment-and-testing.md) — dev environment (macOS + WSL2) and test-target setup this plan assumes
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — read-only/no-exfiltration constraints reflected in the IDOR detector design
- [20-setup-testing-targets.md](20-setup-testing-targets.md) — step-by-step crAPI bring-up and account/token minting for this step's integration test
