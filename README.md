# HackerFive

Open-source, high-performance vulnerability scanner (Go) built to support bug bounty hunting on HackerOne and similar platforms.

HackerFive is the scanner. crAPI, DVWA and Juice Shop are the targets.

Repo: https://github.com/tuangatech/hacker-five

## Status

Phase 1a (Weeks 1-4) is done: CLI, HTTP engine, and a working **IDOR detector**. Phase 1b ([docs/10-implementation-plan-ph1b.md](docs/10-implementation-plan-ph1b.md)) is also done: misconfig detector, Nuclei-compatible template parser, native YAML template engine (`--templates`), testing/validation, and packaging. `v0.1.0` is tagged and released — see [Using HackerFive](#using-hackerfive) below to get started. See [docs/09-implementation-plan-ph1a.md](docs/09-implementation-plan-ph1a.md) for Phase 1a. Phase 2 ([docs/11-implementation-plan-ph2.md](docs/11-implementation-plan-ph2.md)) is in progress: `--scope` allow-list enforcement, an **API auth-bypass detector**, and reflected-XSS/error-based-SQLi/comment-leak checks are implemented and unit-tested; live verification against crAPI/vAPI/DVWA/Juice Shop and the `v0.2.0` release are still pending.

- ✅ **IDOR** (`--detector idor`) — sequential/wordlist ID enumeration, two modes:
  - **Baseline mode** (high confidence): give both `--auth-token` and `--other-auth-token`. Two unrelated accounts are compared against each ID; a finding fires only when the second account gets real content where the majority "denied" baseline says it shouldn't.
  - **Heuristic mode** (low confidence, manual triage): only `--auth-token` given. Flags any ID whose response signature differs from the rest — cannot tell an IDOR from legitimately varying public content, so treat findings as leads, not confirmed bugs.
  - Targets that don't speak plain `Authorization: Bearer <token>` (e.g. vAPI's `Authorization-Token: base64(username:password)`) can override the header via `--auth-header-name`/`--auth-header-format` (the latter must contain the literal placeholder `{token}`) — see [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md)'s vAPI section.
- ✅ **Misconfiguration** (`--detector misconfig`) — fixed built-in rule tables (`pkg/detectors/misconfig/`): exposed paths (`.env`, `.git`, `/admin`, `/swagger`, ...), missing security headers (CSP, HSTS, X-Frame-Options, ...), disallowed HTTP methods (PUT/DELETE/PATCH accepted where they shouldn't be), CORS misconfiguration (reflected origin + credentials), verbose error messages, and a fixed, capped (5 pairs, never retried) default-credentials check. No token required; `--auth-token` is used as a Bearer header when set, for paths that sit behind auth.
- ✅ **Templates** (`--templates`, default `./templates/`) — both formats run automatically alongside whichever `--detector` is selected, additive, not an alternative:
  - **Nuclei-compatible** (`pkg/template/nuclei`) — a defined, fail-loudly subset of real upstream `nuclei-templates` (`scripts/sync-nuclei-templates.sh` syncs a pinned commit); supports `raw:`/`payloads:` (single/multi-entry, cross-request correlation) and `flow:` (boolean compositions of `http(N)`) within a documented v1 scope, and rejects disallowed protocol blocks and out-of-band/OAST matchers outright at load time rather than silently mis-evaluating them — see [docs/template-writing-guide.md](docs/template-writing-guide.md) for the exact boundaries. Live-verified against DVWA, crAPI, and Juice Shop — see doc10 Step 2. Real reflected-XSS/error-based-SQLi samples live under `templates/nuclei-samples/{xss,sqli}/` (Phase 2, not yet live-verified).
  - **Native YAML** (`pkg/template/native`) — HackerFive's own format, sharing the same matcher/extractor engine. `idor`-tagged templates (`templates/idor/*.yaml`) route through the real `idor.Detector`, so a YAML file can now supply what `--endpoint` used to — see doc10 Step 3.
- 🚧 **API Auth Bypass** (`--detector authbypass`, Phase 2, not yet live-verified) — missing-authentication, JWT `alg:none`/signature-stripping bypass, an **offline-only** JWT weak-secret dictionary check (never sent to the target — see `pkg/detectors/authbypass`), a bounded rate-limit-signal probe (fixed request count, one known-invalid credential, never real credential guessing), token reuse across two accounts, and broken-session (logout-then-reuse) detection. Requires `--auth-token` and `--protected-paths` (comma-separated candidate endpoints); `--other-auth-token` additionally enables the token-reuse check.
- 🚧 **`--scope`** (Phase 2) — an optional target allow-list file (one domain/`*.domain`/CIDR entry per line, `#` comments). Omitted by default (every existing documented command keeps working unmodified) but prints a warning when it is; given, enforcement is strict default-deny.

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

## Building & Local Testing

For contributing to HackerFive, or trying it out against local lab targets (crAPI, DVWA, Juice Shop) before ever pointing it at something real.

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

### Setting Up a Target

Full walkthrough (Docker bring-up, account/token minting, one-time setup steps, and a per-detector caveat about DVWA's login form) lives in [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md). Short version:

- **crAPI** (for `--detector idor`): `docker compose up -d`, then `source tests/integration/scripts/crapi_setup.sh` to mint two account tokens.
- **DVWA** (for `--detector misconfig`): `docker run -d -p 80:80 vulnerables/web-dvwa`, then click "Create / Reset Database" once at `http://localhost/setup.php`. No tokens needed.

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

**crAPI/DVWA/Juice Shop are self-contained local Docker targets built for this purpose — never point `--endpoint` or `-t` at a live/external host with these lab credentials/assumptions.** See [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md).

## Docs

Project plan split by concern under [docs/](docs/):

1. [Overview & Strategy](docs/01-overview-and-strategy.md) — mission, market analysis, target vulnerability classes
2. [Architecture & Tech Stack](docs/02-architecture-and-tech-stack.md) — Go/YAML/Cobra stack, system design
3. [Development Roadmap](docs/03-development-roadmap.md) — Phase 1 (1a/1b)/2/3 plan, timeline, milestones
4. [Environment & Testing](docs/04-environment-and-testing.md) — dev setup, testing strategy
5. [HackerOne & Legal](docs/05-hackerone-and-legal.md) — bug bounty workflow, security/legal/ethics
6. [Metrics, Resources & FAQ](docs/06-metrics-resources-faq.md) — success metrics, resources, FAQ
7. [Phase 1a Implementation Plan (Weeks 1-4)](docs/09-implementation-plan-ph1a.md) — file-by-file build plan and verification steps for the Foundation kickoff
8. [Phase 1b Implementation Plan (Weeks 5-10)](docs/10-implementation-plan-ph1b.md) — misconfiguration detector, Nuclei-compatible parser, native YAML engine, testing/validation, packaging
9. [Follow-Up: Security Review, Expansion Strategy & Protocol Scope](docs/follow-up.md) — security review notes, open-source/VDP expansion plan, XBOW research, non-HTTP protocol assessment
10. [Web UI & Template Sync (Proposal)](docs/14-web-ui-and-template-sync.md) — local-only scan/results dashboard design and a cross-platform `templates sync` subcommand; not yet scheduled
11. [Setting Up Test Targets](docs/20-setup-testing-targets.md) — crAPI and DVWA bring-up, account/token minting, per-target setup steps and caveats
12. [Scanning a Real, Authorized Target](docs/21-scanning-real-targets.md) — finding a program/VDP, recon before scanning, building a target-fit Nuclei template set, running the scan conservatively
13. [Authorized Targets Registry](docs/22-authorized-targets.md) — living list of vetted real targets (policy, scope, safe harbor, fit for HackerFive), so vetting isn't repeated
14. [Template Writing Guide](docs/template-writing-guide.md) — writing Nuclei-compatible and native YAML templates: supported fields, what's rejected at load time, the shared DSL

See [CLAUDE.md](CLAUDE.md) for conventions when working in this repo. Contributing? See [CONTRIBUTING.md](CONTRIBUTING.md). Found a vulnerability in HackerFive itself (not a finding it produced against some other target)? See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
