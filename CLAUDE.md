# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

HackerFive — an open-source vulnerability scanner in Go, template-driven (YAML, Nuclei-style), built for HackerOne bug bounty hunting. See [docs/](docs/) for full plan; start with [docs/02-architecture-and-tech-stack.md](docs/02-architecture-and-tech-stack.md) and [docs/03-development-roadmap.md](docs/03-development-roadmap.md).

## Stack & conventions

- **Language:** Go 1.21+, CLI via Cobra, templates via `gopkg.in/yaml.v3`.
- **Layout:** `cmd/hackerfive/` (entrypoint), `pkg/{scanner,detectors,template,reporter}/`, `templates/{idor,misconfig,...}/`, `tests/{unit,integration,fixtures}/`.
- **Testing:** Go `testing` + testify; integration tests run against local vulnerable targets (crAPI, DVWA, Juice Shop, vAPI) via Docker Compose — never against live/external hosts.
- **Lint:** `golangci-lint run ./...` before considering work done.

## Rules

- Never add code that exfiltrates data, writes/destroys target state, or targets a host outside an explicitly authorized scope — this tool only reads/enumerates (see [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md)).
- Load credentials/tokens from environment variables only; never hardcode them.
- Keep new detectors and templates consistent with the false-positive targets in [docs/03-development-roadmap.md](docs/03-development-roadmap.md) (<5%) — flag doubtful matchers instead of guessing.
- Do not rely on your own knowledge about library, framework versions. Please search for new, stable version of library, framework before use.
