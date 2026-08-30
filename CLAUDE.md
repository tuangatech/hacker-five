# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

HackerFive — an open-source vulnerability scanner in Go, template-driven (YAML, Nuclei-style), built for HackerOne bug bounty hunting. See [docs/](docs/) for full plan; start with [docs/02-architecture-and-tech-stack.md](docs/02-architecture-and-tech-stack.md) and [docs/03-development-roadmap.md](docs/03-development-roadmap.md).

## Stack & conventions

- **Language:** Go 1.21+, CLI via Cobra, templates via `gopkg.in/yaml.v3`.
- **Layout:** `cmd/hackerfive/` (entrypoint), `pkg/{scanner,detectors,template,reporter}/`, `templates/{idor,misconfig,...}/`, `tests/{unit,integration,fixtures}/`.
- **Testing:** Go `testing` + testify; integration tests run against local vulnerable targets (crAPI, DVWA, Juice Shop, vAPI) via Docker Compose — never against live/external hosts.
- **Lint:** `golangci-lint run ./...` before considering work done.

## Verification (this environment)

This checkout is `c:\ML-Projects\Weekend-Projects\hacker-five` (Windows-side). No Go toolchain on Windows PATH — instead, shell out to WSL2's toolchain via `wsl.exe`, against this checkout through its `/mnt/c` mount (no separate clone needed):
```bash
wsl.exe -e bash -lc "cd /mnt/c/ML-Projects/Weekend-Projects/hacker-five && go build ./... && go vet ./... && go test ./... -race && PATH=\$PATH:\$HOME/go/bin golangci-lint run ./..."
```
(`golangci-lint` needs the explicit `PATH` prepend — it's not on a non-interactive shell's PATH; see [docs/04-environment-and-testing.md](docs/04-environment-and-testing.md).)

`~/projects/hacker-five` is the user's separate, native-Linux clone — used for what the `/mnt/c` mount can't do: `docker compose` for live crAPI/DVWA targets and running `./hackerfive scan` against them (see [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md)). It has its own git history and needs its own `git pull`; edits here don't reach it automatically.

## Rules

- Never add code that exfiltrates data, writes/destroys target state, or targets a host outside an explicitly authorized scope — this tool only reads/enumerates (see [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md)).
- Load credentials/tokens from environment variables only; never hardcode them.
- Keep new detectors and templates consistent with the false-positive targets in [docs/03-development-roadmap.md](docs/03-development-roadmap.md) (<5%) — flag doubtful matchers instead of guessing.
- Do not rely on your own knowledge about library, framework versions. Please search for new, stable version of library, framework before use.
- Before committing to a new dependency in a plan doc, check its real transitive footprint (run `go get` in a scratch branch, read the `go.mod` diff / `go list -m all`) — a package's own doc page can look lightweight while its import pulls in unrelated subsystems (see [docs/02-architecture-and-tech-stack.md](docs/02-architecture-and-tech-stack.md) §8's `interactsh-client` lesson: 134 new go.mod lines from server-mode code the client didn't need). If the real footprint is disproportionate, prefer a first-party implementation of just the needed protocol subset over accepting the bloat.

## Workflow

- Read existing files before writing code. Prefer editing over rewriting.
- For non-trivial tasks: discuss impact → plan affected code → update specs → implement.
- Push back with evidence when appropriate.
- Never mark a task complete without proving it works.
- Proactively recommend features/practices that raise the tool's maturity (feature parity with established tools, robustness, real-world usability), not just answers to the literal question asked.
- User instructions always override this file.
