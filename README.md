# HackerFive

Open-source, high-performance vulnerability scanner in Go — deterministic detectors and templates as the auditable core, with an optional MCP server and tiered LLM fallback that let an AI agent extend recon, template coverage, and finding triage beyond what's built in, always gated behind explicit human approval.

crAPI, DVWA, Juice Shop, vAPI, WebGoat, bWAPP, and AIGoat are the lab targets it's validated against — see [Test Targets](#test-targets).

Repo: https://github.com/tuangatech/hacker-five

[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/tuangatech/hacker-five/actions/workflows/ci.yml/badge.svg)](https://github.com/tuangatech/hacker-five/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tuangatech/hacker-five)](https://github.com/tuangatech/hacker-five/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- **Detectors** — `idor` (baseline two-account comparison or single-token heuristic mode), `misconfig` (exposed paths, missing security headers, CORS, disallowed methods, default creds), `authbypass` (JWT tampering, offline weak-secret check, rate-limit signal, token reuse, broken sessions), `ssrf` (internal/cloud-metadata probes plus blind out-of-band callback via a first-party Interactsh-protocol client), `businesslogic` (coupon abuse, check-then-act race conditions — the one detector that mutates state, gated behind `--allow-writes`). See [Run a Scan](#run-a-scan) for flags, and each detector's own docs for the full mechanics.
- **Templates** — Nuclei-compatible (synced from real upstream `nuclei-templates`, ~9,600 templates across 7 categories) and a native YAML format sharing the same matcher/extractor engine, both run automatically alongside any detector. Prompt-injection templates ship for chat-shaped LLM endpoints. See [Template Writing Guide](docs/template-writing-guide.md).
- **Recon** — passive (subdomain/TLS/WHOIS) through active (DNS, port scan, HTTP/tech fingerprinting, bounded crawl) reconnaissance, standalone via `hackerfive recon` or feeding `plan` below.
- **Plan** — a deterministic capability registry resolves recon output into a `PlanTree` of candidate detector/template work, zero LLM calls, every unmapped tech signal surfaced as a visible `unresolved` leaf rather than silently dropped.
- **Agent / MCP integration** — `hackerfive mcp-serve` exposes recon/plan/scan/triage to any MCP client (Claude Desktop, Claude Code, ...); a tiered LLM fallback (local model, then OpenRouter) fills gaps the deterministic registry can't resolve, with a hard spend ceiling and every LLM-influenced action gated behind human approval via MCP elicitation. See [MCP Server](#mcp-server-agent-integration).
- **`--scope`** — a target allow-list file (domain/wildcard/CIDR), strict default-deny enforcement once given.
- **Output & reporting** — `json`/`markdown`/`html`/`hackerone-json` export with automatic dedup; `hackerfive report` drafts a real HackerOne report. **Permanent invariant: draft-only** — only an explicit human `report submit --yes` ever makes a report visible to a program.

Full capability inventory — every detector/recon-tool/template category, shipped and planned — lives in [doc01's Capabilities at a Glance](docs/01-overview-and-strategy.md#capabilities-at-a-glance), not duplicated here to avoid the two lists drifting apart.

## Using HackerFive

For running scans against a target — just a downloaded binary, no Go toolchain needed. Contributing to HackerFive, or want to try it against a local lab target first? See [Building & Local Testing](#building--local-testing) below instead.

### Download & Install

Pre-built cross-platform binaries (linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64) are attached to each [GitHub release](https://github.com/tuangatech/hacker-five/releases) — download the archive for your platform and extract it.

**On Windows**, download `hackerfive_<version>_windows_amd64.zip`, extract it anywhere, then run from PowerShell:
```powershell
.\hackerfive.exe --version
```
It's an unsigned binary (no code-signing certificate), so the first run typically shows a SmartScreen "Windows protected your PC" prompt — click "More info" → "Run anyway". This is standard for unsigned OSS binaries, not a sign of tampering; verify against `hackerfive_<version>_checksums.txt` from the same release if you want to confirm the download wasn't corrupted/modified.

### Run a Scan

The zip/tarball bundles `templates/`, so as long as you run the binary from inside the extracted folder, the default `--templates ./templates/` just works — no separate clone needed:
```powershell
.\hackerfive.exe scan -t https://www.example.com --detector misconfig -o findings.json
```
```bash
# Linux/macOS
./hackerfive scan -t https://www.example.com --detector misconfig -o findings.json
```
`--detector misconfig` needs no auth token and is the safe first thing to run against any target. `-t/--targets` accepts either a single URL or a path to a file with one target per line. Other useful flags: `--tags` (comma-separated, loads only templates carrying at least one — mirrors upstream Nuclei's `-tags`), `--concurrency/-c` (default 25), `--rate-limit` (default 10 req/s — raise it for a lab benchmark), `--proxy`, `--timeout`, `--insecure` (skip TLS verification — lab targets only). `--detector idor` additionally needs `--endpoint` plus `--auth-token`/`--other-auth-token` (or `HACKERFIVE_AUTH_TOKEN`/`HACKERFIVE_OTHER_AUTH_TOKEN`) — see [Quick Start](#quick-start) below for a full worked example against a lab target. Run `hackerfive scan --help` for the full flag list.

**`www.example.com` is IANA's reserved documentation domain** (safe for a syntax check) — **only scan a real site you're actually authorized to test.** See [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md) and the next section.

### Scanning a Real, Authorized Target

Once you have an actual authorized target — a HackerOne program or a published VDP/`security.txt` policy, not a lab container — [docs/21-scanning-real-targets.md](docs/21-scanning-real-targets.md) walks through the rest: finding one, the recon to run before scanning, building a Nuclei template set that fits that target's tech stack instead of firing the full synced corpus, and conservative `--rate-limit`/`--concurrency` settings for a live program.

## Web UI

Prefer a browser over flags? `hackerfive serve` runs a local-only web UI on top of the same scanner core:
```bash
./hackerfive serve
# → opens http://127.0.0.1:8877 in your default browser and prints the URL
#   (in case the auto-open is blocked/skipped, e.g. over SSH)
```
Loopback-only by default (`--port`/`--host` to change) — nothing you scan or any token you enter ever leaves your machine. Binding beyond `127.0.0.1` requires the access token printed on startup (`?token=...`), exchanged for a session cookie on first use.

From there: **New Scan** (the same targets/detector/flags as the CLI, in a form) starts a scan and streams findings/logs live as they're detected; **Scan Status** is bookmarkable and safe to refresh mid-scan; **Scan History** and **Dashboard** list past runs from this session; **Templates** shows what's currently loaded (bundled vs. synced), lets you filter by tag, and has a "Sync now" button for the same corpus sync described below.

For scripted/headless use, the equivalent CLI subcommands work without the web UI:
```bash
./hackerfive templates sync   # fetch the pinned upstream Nuclei-templates corpus
./hackerfive templates list   # show what's currently active, --tags to filter
```
Synced templates land in a persistent per-user directory (`os.UserConfigDir()` — e.g. `%AppData%\hackerfive\` on Windows, `~/.config/hackerfive/` on Linux) outside the extracted release folder, so upgrading to a new `hackerfive` release never requires re-syncing or copying anything forward.

## MCP Server (Agent Integration)

`hackerfive mcp-serve` runs HackerFive as an MCP server over stdio — a third frontend (alongside the CLI and Web UI) for Claude Desktop, Claude Code, or any MCP client, built on the same unchanged scanner/recon/registry core. **Phase 6, Steps 1-2 of 5 are done** (server + tools; approval gate, executor, spend ceiling) — hard safety blockers, an approval UI, and a tagged release are still open; see [docs/15-implementation-plan-ph6.md](docs/15-implementation-plan-ph6.md).

```bash
./hackerfive mcp-serve
```

Nine tools are exposed:
- **`plan`** — the flagship tool: runs recon, resolves it via the same deterministic registry the CLI's `plan` command uses (below), and for whatever that can't resolve, falls back to a tiered LLM to decide whether an existing template/tag covers it, a new template should be drafted, or a human should decide. The resulting plan requires explicit human approval via MCP elicitation before anything executes; only then does it run and return real findings.
- **`recon`**, **`scan`** — the same recon phase and detector/template scan the CLI runs, callable by an agent.
- **`tools.search`**, **`templates.search`**, **`templates.list`**, **`templates.sync`** — capability/template lookups an agent can use to reason about what's available before calling `plan`/`scan`.
- **`findings.export`** — render a finding list via the same `pkg/reporter` the CLI's `--format` flag uses.
- **`findings.triage`** — ranks findings by what's worth investigating first via the same tiered LLM fallback; never adds a finding or changes severity/confidence, and its ranking also requires elicitation approval before being returned.

`recon`/`plan`/`scan` refuse to run at all without an explicit scope allow-list — stricter than the CLI's own `--scope`, which only warns when omitted.

**Tiered LLM fallback** — a local tier first (any Ollama-compatible endpoint: `HACKERFIVE_LOCAL_MODEL_URL`/`HACKERFIVE_LOCAL_MODEL_NAME`, default `http://localhost:11434`/`llama3.1`), then OpenRouter as the frontier tier (`OPENROUTER_API_KEY`, `HACKERFIVE_OPENROUTER_MODEL` — set explicitly; no specific model is assumed current). A per-plan `HACKERFIVE_SPEND_CEILING_USD` (default $1.00) hard-caps cumulative LLM spend — once hit, no further fallback calls are made. Any of these can also go in a `.env` file in the working directory, loaded automatically (a real env var always wins). Same permanent human-in-the-loop posture as HackerOne report submission (above): nothing an LLM decides here executes, or is returned, without an explicit human approval step first.

## Building & Local Testing

For contributing to HackerFive, or trying it out against local lab targets before ever pointing it at something real.

### Build from Source

```bash
# via go install (requires Go 1.26+)
go install github.com/tuangatech/hacker-five/cmd/hackerfive@latest

# via Docker (build locally — see Dockerfile)
docker build -t hackerfive .
docker run --rm hackerfive --help

# from source
git clone https://github.com/tuangatech/hacker-five.git && cd hacker-five
make build
./hackerfive --version
```

### Test Targets

Full walkthrough for every target below (Docker bring-up, account/token minting, one-time setup steps, and per-target caveats) lives in [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md). Short version:

| Target | What it's for | One-line bring-up |
|---|---|---|
| **crAPI** | `--detector idor`/`authbypass`/`businesslogic` — real cross-account BOLA, plus a real coupon-flow business-logic bug (unearned credit + a TOCTOU race, needs `--allow-writes`) | `docker compose up -d`, then `source tests/integration/scripts/crapi_setup.sh` to mint two account tokens |
| **DVWA** | `--detector misconfig` | `docker run -d -p 80:80 vulnerables/web-dvwa`, then click "Create / Reset Database" once at `http://localhost/setup.php`. No tokens needed |
| **Juice Shop** | `--detector misconfig`; Nuclei-compatible templates | `docker run -d -p 3000:3000 bkimminich/juice-shop`. No tokens needed |
| **vAPI** | `--detector idor`/`misconfig`/`authbypass`/`ssrf` — real BOLA, custom `Authorization-Token` auth scheme, real SSRF via `/serversurfer` | `git clone https://github.com/roottusk/vapi.git && cd vapi && docker-compose up -d` |
| **WebGoat** | `--detector misconfig` — Spring Boot lesson app, real Actuator (`/actuator/env`) exposure | `docker run --name webgoat -d -p 127.0.0.1:18080:8080 -p 127.0.0.1:19090:9090 webgoat/webgoat:v2025.3`. No tokens needed |
| **bWAPP** | `--detector misconfig` — PHP/MySQL, broader vuln-class coverage than DVWA | `docker run --name bwapp -d -p 127.0.0.1:8079:80 raesene/bwapp`, then hit `/install.php?install=yes` once. No tokens needed |
| **AIGoat** | Prompt-injection templates — deliberately-vulnerable LLM chatbot (OWASP LLM Top 10), self-hosted via Ollama | `git clone https://github.com/AISecurityConsortium/AIGoat.git`, then follow doc20's model/port setup before `docker compose up -d --build` |

### Quick Start

With a target up, run the IDOR detector against crAPI (baseline mode — recommended), using the tokens from the setup step above:
```bash
export HACKERFIVE_AUTH_TOKEN="$CRAPI_OWNER_TOKEN"
export HACKERFIVE_OTHER_AUTH_TOKEN="$CRAPI_OTHER_TOKEN"

./hackerfive scan -t http://localhost:8888 \
  --detector idor \
  --endpoint '/workshop/api/mechanic/mechanic_report?report_id={{id}}' \
  -o findings.json
# Expect: at least 1 finding of type "idor", confidence "high"
```
Tokens can also be passed via `--auth-token`/`--other-auth-token` instead of the env vars (flag wins if both are set). Omitting `--other-auth-token` runs heuristic mode instead — lower confidence, useful for quick recon without a second account.

Run the misconfiguration detector against DVWA — no `--endpoint` or tokens needed:
```bash
./hackerfive scan -t http://localhost --detector misconfig -o findings.json
```

Once a target is up (crAPI with tokens exported, and/or `export DVWA_BASE_URL=http://localhost`), the equivalent opt-in Go integration tests also run directly:
```bash
go test -tags=integration ./tests/integration/... -v
```

**crAPI/DVWA/Juice Shop/vAPI/WebGoat/bWAPP/AIGoat are self-contained local Docker targets built for this purpose — never point `--endpoint` or `-t` at a live/external host with these lab credentials/assumptions.** See [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md).

### Recon & Planning

`hackerfive recon` runs the recon phase standalone — no agent required — against a target: passive subdomain/TLS/WHOIS enumeration, then (with `--recon-depth active|full`) DNS resolution, port scanning, HTTP/tech fingerprinting, and a bounded crawl. `hackerfive plan` runs recon and then resolves the result through a deterministic capability registry (zero LLM calls) into a `PlanTree` of candidate detector/template leaves — a tech signal the registry can't map to anything becomes a visible `unresolved` leaf, never a silent drop. (The MCP server's own `plan` tool, [above](#mcp-server-agent-integration), does the same resolution but additionally falls back to a tiered LLM for what the registry leaves unresolved, gated behind human approval.)
```bash
./hackerfive templates index                                  # generate templates/index.json once
./hackerfive plan -t http://localhost:8888 --recon-depth active --scope path/to/scope.txt
```
Wave 2+ (DNS/port-scan/HTTP-probe) and Wave 3 (crawl) need 6 external ProjectDiscovery CLI tools (subfinder/tlsx/dnsx/naabu/httpx/katana) on `PATH` or installed via `./hackerfive recon setup` (downloads, checksum-verifies, and installs all 6 — no Go toolchain needed; `--check` reports status without any network call) — see [docs/04-environment-and-testing.md](docs/04-environment-and-testing.md#2-recon-binaries-pkgrecon-hackerfive-recon--docs14-implementation-plan-ph5md-step-3) for the manual `go install` alternative. Without them, Wave 0-1 (zero-touch + passive) still work; a missing binary degrades that wave to a warning, not a hard failure — **the Dockerfile doesn't bundle these binaries today**, so `docker run hackerfive recon --recon-depth active` is passive-only unless you run `hackerfive recon setup` inside the container (or build your own image with them installed) first.

## Docs

A few high-level starting points — the full plan (including phase-by-phase implementation docs, environment setup, research write-ups, and the engineering discussion log) lives under [docs/](docs/):

1. [Overview & Strategy](docs/01-overview-and-strategy.md) — mission, market analysis, target vulnerability classes, capability inventory (detectors/recon tools/template categories)
2. [Architecture & Tech Stack](docs/02-architecture-and-tech-stack.md) — Go/YAML/Cobra stack, system design
3. [Development Roadmap](docs/03-development-roadmap.md) — phase-by-phase plan, timeline, milestones, and links to each phase's own implementation-plan doc
4. [HackerOne & Legal](docs/05-hackerone-and-legal.md) — bug bounty workflow, security/legal/ethics, safe harbor
5. [Setting Up Test Targets](docs/20-setup-testing-targets.md) — crAPI, DVWA, Juice Shop, vAPI, WebGoat, bWAPP, and AIGoat bring-up, account/token minting, per-target setup steps and caveats
6. [Scanning a Real, Authorized Target](docs/21-scanning-real-targets.md) — finding a program/VDP, recon before scanning, building a target-fit Nuclei template set, running the scan conservatively
7. [Template Writing Guide](docs/template-writing-guide.md) — writing Nuclei-compatible and native YAML templates: supported fields, what's rejected at load time, the shared DSL

See [CLAUDE.md](CLAUDE.md) for conventions when working in this repo. Contributing? See [CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability in HackerFive itself (not a finding it produced against some other target)? See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
