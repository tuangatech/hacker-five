# Phase 1a Implementation Plan (Foundation — Weeks 1-4)

> Part of the [VulnDetector documentation set](../README.md).
> See [03-development-roadmap.md](03-development-roadmap.md) for the authoritative week-by-week schedule.

## Overview

Phase 1a establishes the **core infrastructure** — the CLI skeleton, HTTP client, configuration system, and data models. No detection logic yet. Everything is scaffolding for Phase 1b (IDOR + Misconfiguration detectors).

**Target:** A working CLI that accepts targets, prints help, and exits cleanly — with all plumbing wired up for detectors to plug in later.

---

## File Inventory

### Entry Point

| File | Purpose |
|------|---------|
| `cmd/vulndetector/main.go` | CLI entry point. Initializes the Cobra root command, parses flags, and delegates to the scanner engine. Calls `cmd.Execute()` and handles OS signals (SIGINT/SIGTERM for graceful shutdown). |
| `cmd/root.go` | Defines the Cobra root command (`vulndetector`) with subcommands (`scan`, `version`). Registers global flags (`-t`, `-l`, `-c`, `-o`, `-v`, `--proxy`). Provides `Execute()` for `main.go` to call. |

### Configuration

| File | Purpose |
|------|---------|
| `pkg/config/config.go` | Reads and validates global configuration: concurrency limit, rate limit (requests/sec), timeout per request, proxy URL, output format, template directory path. Provides a singleton `Config` struct accessible across packages. |
| `pkg/config/default.go` | Defines sensible defaults: 25 workers, 50 req/sec, 30s request timeout, JSON output, templates from `./templates/`. Returns a `Config` with defaults applied so callers never deal with zero values. |

### Data Models

| File | Purpose |
|------|---------|
| `pkg/models/finding.go` | Represents a single vulnerability finding: ID, name, severity, target URL, template name, timestamp, raw request/response, and metadata. Implements `MarshalJSON()` for output formatting. |
| `pkg/models/result.go` | Aggregates findings from a single scan target: target URL, total requests, duration, finding count, and a slice of `Finding`. Used by the reporter to produce final output. |
| `pkg/models/template.go` | Represents a parsed YAML detection template: ID, name, severity, tags, list of `Request` definitions (method, path, headers, body, matchers, extractors). The core data structure the scanner engine operates on. |

### HTTP Client

| File | Purpose |
|------|---------|
| `pkg/httpclient/client.go` | Wraps `net/http.Client` with configurable timeouts, redirect policy (follow up to 10 redirects), and transport settings (keep-alive, TLS config). Provides `Do(*http.Request) (*http.Response, error)`. |
| `pkg/httpclient/middleware.go` | Interceptor chain applied to every request: rate limiting (token bucket), retry with exponential backoff (max 3 retries, 500ms–2s backoff), proxy routing (if configured), user-agent rotation from a predefined pool, and request/response logging (debug mode). |
| `pkg/httpclient/mock.go` | In-memory HTTP server for unit tests. Returns configurable responses per path, used by detector unit tests without needing live targets. |

### Scanner Engine

| File | Purpose |
|------|---------|
| `pkg/scanner/engine.go` | Orchestrates the scan: loads templates, dispatches requests to the worker pool, collects results, and handles cancellation via context. Entry point: `Scan(targets []string, templates []Template) ([]Result, error)`. |
| `pkg/scanner/worker.go` | Worker pool implementation: configurable number of goroutines (default 25), job queue for targets + templates, progress tracking (requests sent/total), and graceful shutdown on signal. |
| `pkg/scanner/pool.go` | Generic worker pool abstraction: manages goroutine lifecycle, handles job distribution, tracks idle/active workers, and provides a `Close()` method for clean shutdown. |

### Reporter

| File | Purpose |
|------|---------|
| `pkg/reporter/reporter.go` | Abstract reporter interface: `Write([]Result) error`. Concrete implementations for JSON, Markdown, and HTML output. Selects format based on the `-o` flag (default: JSON to stdout). |
| `pkg/reporter/json.go` | JSON reporter: writes findings as a JSON array to the specified file or stdout. Includes metadata (scan duration, targets scanned, tool version). |
| `pkg/reporter/markdown.go` | Markdown reporter: formatted table output suitable for GitHub issues. Columns: Severity, Type, Target, Path, Description. |
| `pkg/reporter/html.go` | HTML reporter: styled HTML report with severity color-coding, sortable tables, and summary statistics. Intended for stakeholder sharing. |

### Template System (Phase 1b prep)

| File | Purpose |
|------|---------|
| `pkg/template/parser.go` | Parses YAML templates into `Template` structs. Validates required fields (id, info.name, requests). Returns structured errors for malformed templates. |
| `pkg/template/matcher.go` | Evaluates matchers against HTTP responses: status code matching, word/regex matching (using Go `regexp`/RE2), size matching, JSON extraction. Returns `MatchResult` with match details. |
| `pkg/template/extractor.go` | Extracts values from response bodies: JSON path extraction, regex group extraction, header extraction. Binds extracted values to template-scoped variables for request chaining (Phase 1b). |

### CLI Subcommands

| File | Purpose |
|------|---------|
| `cmd/scan.go` | `vulndetector scan` subcommand: accepts `-t` (targets file or single URL), `-l` (template directory), `-c` (concurrency), `-o` (output file), `-f` (output format), `--proxy`. Validates inputs, loads templates, runs the scanner, and passes results to the reporter. |
| `cmd/version.go` | `vulndetector version` subcommand: prints version string, Go version, and build timestamp. |

### Templates

| File | Purpose |
|------|---------|
| `templates/default/README.md` | Documentation for the templates directory: explains the template format, provides a minimal example, and links to the full docs. |

### Build & CI

| File | Purpose |
|------|---------|
| `go.mod` | Go module definition: `github.com/tuangatech/vulndetector`. Lists dependencies: `cobra`, `yaml.v3`, `json-iterator/go`. |
| `go.sum` | Dependency checksums (generated by `go mod tidy`). |
| `Makefile` | Build targets: `make build` (compile binary to `./vulndetector`), `make test` (run all tests), `make lint` (golangci-lint), `make clean` (remove binary). |
| `.github/workflows/ci.yml` | GitHub Actions CI: runs on push/PR. Steps: checkout, setup Go 1.21+, `go test -v -race -coverprofile=coverage.out ./...`, `go vet ./...`, `golangci-lint run ./...`. |

### Testing

| File | Purpose |
|------|---------|
| `tests/unit/config_test.go` | Tests: default config values, explicit overrides, invalid config rejection. |
| `tests/unit/client_test.go` | Tests: HTTP client with mock responses, timeout handling, proxy routing, retry logic. |
| `tests/unit/pool_test.go` | Tests: worker pool creation, job distribution, graceful shutdown, goroutine leak detection. |
| `tests/unit/parser_test.go` | Tests: valid template parsing, missing required fields, malformed YAML, unsupported request fields. |
| `tests/unit/matcher_test.go` | Tests: status code matchers, word matchers, regex matchers, negative matchers, combined matchers. |
| `tests/integration/scan_test.go` | Integration test: runs scanner against a mock HTTP server (from `httpclient/mock.go`), verifies findings are collected and reported correctly. |
| `tests/fixtures/templates/` | Fixture directory: valid YAML templates for unit/integration tests (simple status check, word match, regex match). |
| `tests/fixtures/responses/` | Fixture directory: sample HTTP response bodies (JSON, HTML, plain text) used in matcher tests. |

---

## Build Order (Suggested)

1. **Day 1–2:** `go.mod` + `Makefile` + `.github/workflows/ci.yml` — project scaffolding
2. **Day 2–3:** `pkg/config/` (config.go, default.go) — configuration system
3. **Day 3–4:** `pkg/models/` (finding.go, result.go, template.go) — data models
4. **Day 4–5:** `pkg/httpclient/` (client.go, middleware.go, mock.go) — HTTP layer
5. **Day 5–6:** `cmd/root.go` + `cmd/scan.go` + `cmd/version.go` + `cmd/vulndetector/main.go` — CLI
6. **Day 6–7:** `pkg/scanner/` (engine.go, worker.go, pool.go) — scanner engine
7. **Day 7–8:** `pkg/reporter/` (reporter.go, json.go, markdown.go, html.go) — output
8. **Day 8–9:** `pkg/template/` (parser.go, matcher.go, extractor.go) — template system
9. **Day 9–10:** `templates/` + unit tests + integration tests
10. **Day 10:** End-to-end verification: `vulndetector scan -t http://localhost:PORT -l templates/`

---

## See also

- [01-overview-and-strategy.md](01-overview-and-strategy.md) — why IDOR + misconfiguration are Phase 1 priorities
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — technology decisions
- [03-development-roadmap.md](03-development-roadmap.md) — full timeline (Phase 1a, 1b, 2, 3)
