# HackerFive

Open-source, high-performance vulnerability scanner (Go) built to support bug bounty hunting on HackerOne and similar platforms.

Repo: https://github.com/tuangatech/hacker-five

## Status

Phase 1a (Weeks 1-4) is done: CLI, HTTP engine, and a working **IDOR detector**. See [docs/09-implementation-plan-ph1a.md](docs/09-implementation-plan-ph1a.md).

- ✅ **IDOR** (`--detector idor`) — sequential/wordlist ID enumeration, two modes:
  - **Baseline mode** (high confidence): give both `--auth-token` and `--other-auth-token`. Two unrelated accounts are compared against each ID; a finding fires only when the second account gets real content where the majority "denied" baseline says it shouldn't.
  - **Heuristic mode** (low confidence, manual triage): only `--auth-token` given. Flags any ID whose response signature differs from the rest — cannot tell an IDOR from legitimately varying public content, so treat findings as leads, not confirmed bugs.
- 🚧 **Misconfiguration** — stubbed only (`pkg/detectors/misconfig/`), no detection logic yet. Lands in Phase 1b along with the Nuclei-compatible template parser and native YAML engine — see [docs/10-implementation-plan-ph1b.md](docs/10-implementation-plan-ph1b.md).
- Template files (`--templates`) are accepted on the CLI but not parsed yet — the `--endpoint` flag is the Phase 1a stopgap for pointing IDOR at an endpoint.

## Setting Up a Target

Only the IDOR detector is functional today (see Status above), and it's a stateful, two-account check — so the only test target this repo currently has first-class support for is **crAPI**, which ships a deliberately vulnerable "vehicle access" endpoint and a scriptable signup/login flow to mint the two account tokens IDOR needs. DVWA and Juice Shop are useful once the misconfiguration/XSS detectors land in later phases, but there's no detector yet that would find anything on them — skip those for now.

**1. Bring up crAPI, from a clean state:**
```bash
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy
docker compose down -v   # wipe any stale data from a prior run
docker compose up -d
# crAPI is now at http://localhost:8888
```

**2. Mint two account tokens** — crAPI has no pre-seeded accounts; they come from its signup flow. The repo includes a script that does this for you: it signs up two unrelated throwaway accounts and exports their tokens.
```bash
cd /path/to/hacker-five
export CRAPI_BASE_URL=http://localhost:8888   # optional, this is the default
source tests/integration/scripts/crapi_setup.sh
# → exports CRAPI_OWNER_TOKEN and CRAPI_OTHER_TOKEN
```
Requires `curl` and `jq`. Must be `source`d (not executed) so the exports land in your current shell — running it as `./crapi_setup.sh` won't work.

These tokens are single-session JWTs tied to the accounts the script just created — there's no fixed sample value to hardcode; re-run the script (or crAPI's `/identity/api/auth/signup` + `/identity/api/auth/login` endpoints by hand) whenever you need fresh ones, e.g. after a `docker compose down -v`.

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

`-t/--targets` accepts either a single URL or a path to a file with one target per line. Other useful flags: `--concurrency/-c` (default 25), `--rate-limit` (default 50 req/s), `--proxy`, `--timeout`, `--insecure` (skip TLS verification — lab targets only, e.g. crAPI/DVWA self-signed certs). Run `./hackerfive scan --help` for the full list.

Once crAPI is up and tokens are exported, the equivalent opt-in Go integration test also runs directly:
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

See [CLAUDE.md](CLAUDE.md) for conventions when working in this repo.
