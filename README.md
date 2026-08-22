# HackerFive

Open-source, high-performance vulnerability scanner (Go) built to support bug bounty hunting on HackerOne and similar platforms.

Repo: https://github.com/tuangatech/hacker-five

## Status

Phase 1a (Weeks 1-4) is done: CLI, HTTP engine, and a working **IDOR detector**. Phase 1b's misconfiguration detector (Step 1 of [docs/10-implementation-plan-ph1b.md](docs/10-implementation-plan-ph1b.md)) is also done. See [docs/09-implementation-plan-ph1a.md](docs/09-implementation-plan-ph1a.md) for Phase 1a.

- ✅ **IDOR** (`--detector idor`) — sequential/wordlist ID enumeration, two modes:
  - **Baseline mode** (high confidence): give both `--auth-token` and `--other-auth-token`. Two unrelated accounts are compared against each ID; a finding fires only when the second account gets real content where the majority "denied" baseline says it shouldn't.
  - **Heuristic mode** (low confidence, manual triage): only `--auth-token` given. Flags any ID whose response signature differs from the rest — cannot tell an IDOR from legitimately varying public content, so treat findings as leads, not confirmed bugs.
- ✅ **Misconfiguration** (`--detector misconfig`) — fixed built-in rule tables (`pkg/detectors/misconfig/`), no template engine involved yet: exposed paths (`.env`, `.git`, `/admin`, `/swagger`, ...), missing security headers (CSP, HSTS, X-Frame-Options, ...), disallowed HTTP methods (PUT/DELETE/PATCH accepted where they shouldn't be), CORS misconfiguration (reflected origin + credentials), verbose error messages, and a fixed, capped (5 pairs, never retried) default-credentials check. No token required; `--auth-token` is used as a Bearer header when set, for paths that sit behind auth.
- 🚧 **Nuclei-compatible template parser & native YAML engine** — not started. Lands in later Phase 1b steps — see [docs/10-implementation-plan-ph1b.md](docs/10-implementation-plan-ph1b.md). Template files (`--templates`) are accepted on the CLI but not parsed yet — the `--endpoint` flag is the stopgap for pointing IDOR at an endpoint.

## Setting Up a Target

Full walkthrough (Docker bring-up, account/token minting, one-time setup steps, and a per-detector caveat about DVWA's login form) lives in [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md). Short version:

- **crAPI** (for `--detector idor`): `docker compose up -d`, then `source tests/integration/scripts/crapi_setup.sh` to mint two account tokens.
- **DVWA** (for `--detector misconfig`): `docker run -d -p 80:80 vulnerables/web-dvwa`, then click "Create / Reset Database" once at `http://localhost/setup.php`. No tokens needed.

## Quick Start

Build:
```bash
go build -o hackerfive ./cmd/hackerfive
# or: make build
```

Run the IDOR detector against crAPI (baseline mode — recommended), using the tokens from the setup step above:
```bash
export HACKERFIVE_AUTH_TOKEN="$CRAPI_OWNER_TOKEN"
export HACKERFIVE_OTHER_AUTH_TOKEN="$CRAPI_OTHER_TOKEN"

./hackerfive scan -t http://localhost:8888 \
  --detector idor \
  --endpoint /identity/api/v2/user/dashboard/{{id}} \
  -o findings.json
# Expect: at least 1 finding of type "idor", confidence "high"
```
Tokens can also be passed via `--auth-token`/`--other-auth-token` instead of the env vars (flag wins if both are set). Omitting `--other-auth-token` runs heuristic mode instead — lower confidence, useful for quick recon without a second account.

Run the misconfiguration detector against DVWA — no `--endpoint` or tokens needed:
```bash
./hackerfive scan -t http://localhost --detector misconfig -o findings.json
```

`-t/--targets` accepts either a single URL or a path to a file with one target per line. Other useful flags: `--concurrency/-c` (default 25), `--rate-limit` (default 50 req/s), `--proxy`, `--timeout`, `--insecure` (skip TLS verification — lab targets only, e.g. crAPI/DVWA self-signed certs). Run `./hackerfive scan --help` for the full list.

Once a target is up (crAPI with tokens exported, and/or `export DVWA_BASE_URL=http://localhost`), the equivalent opt-in Go integration tests also run directly:
```bash
go test -tags=integration ./tests/integration/... -v
```

**Only scan targets you're authorized to test** — see [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md). crAPI/DVWA/Juice Shop are self-contained local Docker targets built for this purpose; never point `--endpoint` or `-t` at a live/external host without explicit authorization.

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
10. [Setting Up Test Targets](docs/20-setup-testing-targets.md) — crAPI and DVWA bring-up, account/token minting, per-target setup steps and caveats

See [CLAUDE.md](CLAUDE.md) for conventions when working in this repo.
