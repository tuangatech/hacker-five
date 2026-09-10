# HackerFive

Template-driven vulnerability scanner in Go, built for HackerOne bug-bounty recon and triage. Deterministic detectors and YAML templates are the auditable core; an optional MCP server and tiered LLM fallback let an AI agent extend recon, template coverage, and triage — always behind explicit human approval.

Repo: https://github.com/tuangatech/hacker-five

[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/tuangatech/hacker-five/actions/workflows/ci.yml/badge.svg)](https://github.com/tuangatech/hacker-five/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tuangatech/hacker-five)](https://github.com/tuangatech/hacker-five/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- **Five detectors** (`pkg/detectors`) — `idor` (two-account baseline comparison, or single-token heuristic mode), `misconfig` (known-bad paths, missing security headers, CORS, disallowed methods, default logins), `authbypass` (`alg:none` / stripped-signature JWT, offline weak-secret check, cross-user token reuse, rate-limit signal), `ssrf` (`file://`/`gopher://` redirection plus blind out-of-band via a first-party Interactsh client), `businesslogic` (coupon mint/apply, check-then-act races — the only detector that mutates state, gated behind `--allow-writes`).
- **Two template engines, run additively** — Nuclei-compatible YAML (`pkg/template/nuclei`) and a richer native format (`pkg/template/native`) for checks with no Nuclei equivalent (two-account IDOR baselines, `{{RangeInt}}` enumeration). The synced corpus is a sparse checkout of a pinned `nuclei-templates` commit across 7 categories (~9,700 templates, ~96% load-clean) in a per-user config dir that survives binary upgrades; prompt-injection templates ship for chat-shaped LLM endpoints. `hackerfive templates sync`.
- **Escalating recon** (`pkg/recon`) — waves 0–3: zero-touch → passive (`subfinder`/`tlsx`) → active (`dnsx`/`naabu`/`httpx` tech-detect) → bounded crawl (`katana`). Fully deterministic; emits a schema-frozen `ReconResult` where every fact carries its source and confidence.
- **Deterministic decision engine** (`pkg/registry`) — resolves recon facts into a `PlanTree` of candidate detector/template work via a static, versioned registry. Every unmapped signal becomes a visible `unresolved` leaf, never a silent drop.
- **Optional tiered LLM fallback** (`pkg/llmfallback`) — invoked *only* on a registry miss: a local model first, then an OpenRouter frontier tier for drafting new templates (validated, never auto-executed). Stateless per call, two USD spend ceilings, and a later pass can only ever weaken a plan.
- **Three frontends, one engine** — Cobra CLI, a loopback-only Web UI (`hackerfive serve` — htmx + SSE, Plan Preview approval), and an MCP server (`hackerfive mcp-serve` — approval via MCP elicitation). No scan logic is duplicated across them.
- **Hardened HTTP client** — stdlib `net/http` with rate limiting, retry-with-backoff, Burp/mitmproxy proxy support, and a per-host error circuit-breaker.
- **Reporting** (`pkg/reporter`) — `json` / `markdown` / `html` / `hackerone-json` export with automatic dedup; optional SQLite finding history.

Planned ([Phase 8](docs/17-implementation-plan-ph8.md) / [9](docs/18-implementation-plan-ph9.md)): a `tcp:` network-service detector, a TLS detector, JS static analysis, OOB blind-RCE verification, and first-party `sqli`/`xss`/`lfi`/`uploadbypass` with WAF-aware probing. Full shipped/planned inventory: [doc01](docs/01-overview-and-strategy.md#capabilities-at-a-glance).

## Safety model

- **Read and enumerate only** — HackerFive never writes or destroys target state, never exfiltrates data, and never touches a host outside an explicit scope. `--allow-writes` (businesslogic checks only) is the sole opt-in exception; without it those checks are skipped with a warning.
- **HackerOne reports are draft-only** — `hackerfive report` builds a private, unsubmitted draft; only an explicit `report submit --yes` ever makes one visible to a program.
- **Scope** — `--scope <file>` (domain / wildcard / CIDR) switches to strict default-deny; the MCP server refuses to run recon/plan/scan without one.
- Credentials and tokens are read from environment variables only.

## Install

Pre-built binaries (linux/macOS/Windows, amd64 + arm64) are attached to each [release](https://github.com/tuangatech/hacker-five/releases) — extract and run. The archive bundles `templates/`, so `--templates ./templates/` works from inside the extracted folder with no clone.

```bash
# build from source (Go 1.26+)
go install github.com/tuangatech/hacker-five/cmd/hackerfive@latest

# or Docker
docker build -t hackerfive . && docker run --rm hackerfive --help
```

The Windows binary is unsigned — SmartScreen's "More info → Run anyway" is expected; verify against the release `checksums.txt` if in doubt.

## Usage

```bash
# misconfig needs no auth and is the safe first pass against any target
hackerfive scan -t https://example.com --detector misconfig -o findings.json
```

`-t/--targets` takes a URL or a file of targets, one per line. Common flags: `--tags` (load only templates carrying a tag), `--concurrency/-c` (default 25), `--rate-limit` (default 10 req/s), `--proxy`, `--timeout`, `--insecure` (lab only). `hackerfive scan --help` lists them all.

IDOR against a lab target, baseline mode:

```bash
export HACKERFIVE_AUTH_TOKEN=...        # account A
export HACKERFIVE_OTHER_AUTH_TOKEN=...  # account B
hackerfive scan -t http://localhost:8888 --detector idor \
  --endpoint '/workshop/api/mechanic/mechanic_report?report_id={{id}}' -o findings.json
```

Omitting `--other-auth-token` runs lower-confidence heuristic mode.

## Recon & plan

```bash
hackerfive recon -t http://localhost:8888 --recon-depth active --scope scope.txt
hackerfive plan  -t http://localhost:8888 --recon-depth active --scope scope.txt
```

`recon` runs waves 0–3 standalone; `plan` resolves the result through the deterministic registry into a `PlanTree`. Waves 2–3 need the ProjectDiscovery CLIs (`subfinder`/`tlsx`/`dnsx`/`naabu`/`httpx`/`katana`) on `PATH` or via `hackerfive recon setup` (downloads + checksum-verifies, no Go toolchain). Without them, waves 0–1 still run; a missing binary degrades a wave to a warning.

## Web UI

```bash
hackerfive serve   # → http://127.0.0.1:8877
```

The same scanner core in a browser: launch scans with live findings/logs over SSE, a reconnect-safe status page, Plan Preview for approving a recon-derived plan, and a Templates view. Loopback-only by default; binding wider needs the token printed at startup.

## MCP server

```bash
hackerfive mcp-serve   # stdio; --agency readonly for a recon+triage-only server
```

Exposes `recon` / `plan` / `scan` / `templates.*` / `tools.search` / `findings.export` / `findings.triage` to any MCP client over the same engine. The `plan` tool runs recon, resolves it deterministically, falls back to the tiered LLM for the rest, and requires MCP-elicitation approval before anything executes or is returned. An agent cannot self-grant `--allow-writes`. Current status: [docs/15](docs/15-implementation-plan-ph6.md).

## Local testing

Validated against **crAPI, DVWA, Juice Shop, vAPI, WebGoat, bWAPP, and AIGoat** as self-contained Docker lab targets. [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md) covers bring-up, token minting, and per-target notes; opt-in integration tests run with `go test -tags=integration ./tests/integration/...`.

> Lab credentials and assumptions are for these containers only — never point `-t` / `--endpoint` at a live host with them. Only scan targets you are authorized to test: see [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md).

## Docs

- [Overview & Strategy](docs/01-overview-and-strategy.md) — mission, capability inventory
- [Architecture & Tech Stack](docs/02-architecture-and-tech-stack.md) — design principles, module map, the agent pipeline
- [Development Roadmap](docs/03-development-roadmap.md) — phases 1–9
- [HackerOne & Legal](docs/05-hackerone-and-legal.md) — bug-bounty workflow, safe harbor
- [Scanning a Real Target](docs/21-scanning-real-targets.md) · [Test Targets](docs/20-setup-testing-targets.md) · [Template Writing Guide](docs/template-writing-guide.md)

Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · [CLAUDE.md](CLAUDE.md). Vulnerability in HackerFive itself: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
