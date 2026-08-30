# HackerFive

Open-source, high-performance vulnerability scanner (Go) built to support bug bounty hunting on HackerOne and similar platforms.

HackerFive is the scanner. crAPI, DVWA, Juice Shop, vAPI, and AIGoat are the lab targets it's validated against — see [Test Targets](#test-targets).

Repo: https://github.com/tuangatech/hacker-five

[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![CI](https://github.com/tuangatech/hacker-five/actions/workflows/ci.yml/badge.svg)](https://github.com/tuangatech/hacker-five/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tuangatech/hacker-five)](https://github.com/tuangatech/hacker-five/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Features

- **IDOR** (`--detector idor`) — sequential/wordlist ID enumeration, two modes:
  - **Baseline mode** (high confidence): give both `--auth-token` and `--other-auth-token`. Two unrelated accounts are compared against each ID; a finding fires only when the second account gets real content where the majority "denied" baseline says it shouldn't.
  - **Heuristic mode** (low confidence, manual triage): only `--auth-token` given. Flags any ID whose response signature differs from the rest — cannot tell an IDOR from legitimately varying public content, so treat findings as leads, not confirmed bugs.
  - Targets that don't speak plain `Authorization: Bearer <token>` (e.g. vAPI's `Authorization-Token: base64(username:password)`) can override the header via `--auth-header-name`/`--auth-header-format` (the latter must contain the literal placeholder `{token}`) — see [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md)'s vAPI section.
- **Misconfiguration** (`--detector misconfig`) — fixed built-in rule tables (`pkg/detectors/misconfig/`): exposed paths (`.env`, `.git`, `/admin`, `/swagger`, ...), missing security headers (CSP, HSTS, X-Frame-Options, ...), disallowed HTTP methods (PUT/DELETE/PATCH accepted where they shouldn't be), CORS misconfiguration (reflected origin + credentials), verbose error messages, and a fixed, capped (5 pairs, never retried) default-credentials check. No token required; `--auth-token` is used as a Bearer header when set, for paths that sit behind auth.
- **API Auth Bypass** (`--detector authbypass`) — missing-authentication, JWT `alg:none`/signature-stripping bypass, an **offline-only** JWT weak-secret dictionary check (never sent to the target — see `pkg/detectors/authbypass`), a bounded rate-limit-signal probe (fixed request count, one known-invalid credential, never real credential guessing), token reuse across two accounts, and broken-session (logout-then-reuse) detection. Requires `--auth-token` and `--protected-paths` (comma-separated candidate endpoints); `--other-auth-token` additionally enables the token-reuse check. `--login-paths`/`--logout-paths` override the rate-limit/broken-session checks' fixed candidate lists (real targets rarely use the generic defaults); `--auth-header-name`/`--auth-header-format` (above) apply here too, not just to IDOR.
- **Templates** (`--templates`, default `./templates/`) — both formats run automatically alongside whichever `--detector` is selected, additive, not an alternative:
  - **Nuclei-compatible** (`pkg/template/nuclei`) — a defined, fail-loudly subset of real upstream `nuclei-templates` (`scripts/sync-nuclei-templates.sh` syncs a pinned commit); supports `raw:`/`payloads:` (single/multi-entry, cross-request correlation) and `flow:` (boolean compositions of `http(N)`) within a documented v1 scope, and rejects disallowed protocol blocks and out-of-band/OAST matchers outright at load time rather than silently mis-evaluating them — see [docs/template-writing-guide.md](docs/template-writing-guide.md) for the exact boundaries. Real reflected-XSS/error-based-SQLi/blind-SQLi/stored-XSS samples ship under `templates/nuclei-samples/`.
  - **Native YAML** (`pkg/template/native`) — HackerFive's own format, sharing the same matcher/extractor engine. `idor`-tagged templates (`templates/idor/*.yaml`) route through the real `idor.Detector`, so a YAML file can supply what `--endpoint` used to.
  - **`--header 'Name: Value'`** (repeatable) — static headers applied to every template-driven request (both formats), the primary use for a session cookie a target's login flow issued outside the scan (e.g. DVWA), since template placeholders can't carry one yet.
  - **Prompt injection** (`templates/nuclei-samples/promptinjection/`, tag `prompt-injection`) — a field-deployable system-prompt-extraction check for any chat-shaped LLM endpoint, plus a lab-only seeded-secret variant for validating the detector itself; live-verified against [AIGoat](https://github.com/AISecurityConsortium/AIGoat) (see [Test Targets](#test-targets)). Every request here can trigger a real, metered LLM call on the target's backend — loading a `prompt-injection`-tagged template with `--concurrency` above 5 (the safe default) prints a stderr warning.
- **`--scope`** — an optional target allow-list file (one domain/`*.domain`/CIDR entry per line, `#` comments). Omitted by default (every existing documented command keeps working unmodified) but prints a warning when it is; given, enforcement is strict default-deny.

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
`--detector misconfig` needs no auth token and is the safe first thing to run against any target. `-t/--targets` accepts either a single URL or a path to a file with one target per line. Other useful flags: `--tags` (comma-separated, loads only templates carrying at least one — mirrors upstream Nuclei's `-tags`), `--concurrency/-c` (default 25), `--rate-limit` (default 50 req/s), `--proxy`, `--timeout`, `--insecure` (skip TLS verification — lab targets only). `--detector idor` additionally needs `--endpoint` plus `--auth-token`/`--other-auth-token` (or `HACKERFIVE_AUTH_TOKEN`/`HACKERFIVE_OTHER_AUTH_TOKEN`) — see [Quick Start](#quick-start) below for a full worked example against a lab target. Run `hackerfive scan --help` for the full flag list.

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
| **crAPI** | `--detector idor` — real cross-account BOLA | `docker compose up -d`, then `source tests/integration/scripts/crapi_setup.sh` to mint two account tokens |
| **DVWA** | `--detector misconfig` | `docker run -d -p 80:80 vulnerables/web-dvwa`, then click "Create / Reset Database" once at `http://localhost/setup.php`. No tokens needed |
| **Juice Shop** | `--detector misconfig`; Nuclei-compatible templates | `docker run -d -p 3000:3000 bkimminich/juice-shop`. No tokens needed |
| **vAPI** | `--detector idor`/`misconfig`/`authbypass` — real BOLA, custom `Authorization-Token` auth scheme | `git clone https://github.com/roottusk/vapi.git && cd vapi && docker-compose up -d` |
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

**crAPI/DVWA/Juice Shop/vAPI/AIGoat are self-contained local Docker targets built for this purpose — never point `--endpoint` or `-t` at a live/external host with these lab credentials/assumptions.** See [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md).

## Docs

Project plan split by concern under [docs/](docs/):

1. [Overview & Strategy](docs/01-overview-and-strategy.md) — mission, market analysis, target vulnerability classes, capability inventory (detectors/recon tools/template categories)
2. [Architecture & Tech Stack](docs/02-architecture-and-tech-stack.md) — Go/YAML/Cobra stack, system design
3. [Development Roadmap](docs/03-development-roadmap.md) — Phase 1 (1a/1b)/2/3/4/5/6/7 plan, timeline, milestones
4. [Environment & Testing](docs/04-environment-and-testing.md) — dev setup, testing strategy
5. [HackerOne & Legal](docs/05-hackerone-and-legal.md) — bug bounty workflow, security/legal/ethics
6. [Metrics, Resources & FAQ](docs/06-metrics-resources-faq.md) — success metrics, resources, FAQ
7. [Phase 1a Implementation Plan (Weeks 1-4)](docs/09-implementation-plan-ph1a.md) — file-by-file build plan and verification steps for the Foundation kickoff
8. [Phase 1b Implementation Plan (Weeks 5-10)](docs/10-implementation-plan-ph1b.md) — misconfiguration detector, Nuclei-compatible parser, native YAML engine, testing/validation, packaging
9. [Phase 2 Implementation Plan (Weeks 11-18)](docs/11-implementation-plan-ph2.md) — API auth-bypass detector, XSS/SQLi templates, `--scope` enforcement; `v0.2.0` results
10. [Phase 3 Implementation Plan (Weeks 19-24)](docs/12-implementation-plan-ph3.md) — local-only web UI (`hackerfive serve`) and upgradeable template sync; `v0.3.0` results
11. [Phase 4 Implementation Plan (Weeks 25-32)](docs/13-implementation-plan-ph4.md) — Prompt Injection, SSRF, and Business Logic Flaw detectors
12. [Phase 5 Implementation Plan (Weeks 33-40)](docs/14-implementation-plan-ph5.md) — recon package, `Finding`-schema freeze, task-tree data model, a deterministic decision engine + capability registry, read-only recon/plan-preview UI (no MCP dependency)
13. [Phase 6 Implementation Plan (Weeks 41-48)](docs/15-implementation-plan-ph6.md) — MCP server, `tools.search`/`templates.search`, elicitation-based approval gate seeded from recon, tiered LLM fallback, hard safety blockers, actionable approval UI
14. [Phase 7 Implementation Plan (Weeks 49-56)](docs/16-implementation-plan-ph7.md) — `AllowWrites` attestation, live Web UI Agent tab, OWASP Agentic Top 10 mapping, eval maturity
15. [Follow-Up: Security Review, Expansion Strategy & Protocol Scope](docs/follow-up.md) — security review notes, open-source/VDP expansion plan, XBOW research, non-HTTP protocol assessment
16. [Setting Up Test Targets](docs/20-setup-testing-targets.md) — crAPI, DVWA, Juice Shop, vAPI and AIGoat bring-up, account/token minting, per-target setup steps and caveats
17. [Scanning a Real, Authorized Target](docs/21-scanning-real-targets.md) — finding a program/VDP, recon before scanning, building a target-fit Nuclei template set, running the scan conservatively
18. [Authorized Targets Registry](docs/22-authorized-targets.md) — living list of vetted real targets (policy, scope, safe harbor, fit for HackerFive), so vetting isn't repeated
19. [Template Writing Guide](docs/template-writing-guide.md) — writing Nuclei-compatible and native YAML templates: supported fields, what's rejected at load time, the shared DSL
20. [Agent Integration Research: "Hacker-in-the-Loop"](docs/90-research-hackerbot.md) — research behind Phases 5-7: how other LLM-driven pentesting tools structure themselves (including a deterministic-first, tiered-LLM-fallback hybrid model), and the design decisions/backlog this project scheduled from it
21. [Recon Phase Research](docs/91-research-recon-phase.md) — research behind Phase 5's recon package: how comparable agentic pentesting tools perform reconnaissance, and the wave-based design scheduled from it

See [CLAUDE.md](CLAUDE.md) for conventions when working in this repo. Contributing? See [CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability in HackerFive itself (not a finding it produced against some other target)? See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
