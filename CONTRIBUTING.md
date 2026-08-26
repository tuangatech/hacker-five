# Contributing to HackerFive

Thanks for considering a contribution. This project follows the conventions in [CLAUDE.md](CLAUDE.md) — read it first if you're touching the Go code; this doc covers the process around that.

## Before you start

For anything beyond a small fix, open an issue first (or comment on an existing one) describing what you want to change and why. It's a lot cheaper to align on approach before writing code than after — this project has a documented history (see [docs/](docs/)) of catching real design gaps during review rather than mid-implementation, and issues are where that happens for outside contributions.

## Workflow

1. Fork the repo, branch off `main`.
2. Make your change. Read existing files before writing new code — prefer editing over rewriting, and match the patterns already in the package you're touching rather than introducing a new one.
3. Add or update tests. This project doesn't accept untested detector/template-engine logic — see the coverage gate in `.github/workflows/ci.yml`.
4. Run the required checks locally before opening a PR:
   ```bash
   make build test lint
   ```
   (mirrors [CLAUDE.md](CLAUDE.md)'s own verification command — CI runs the same checks, plus a coverage gate)
5. Open a PR against `main`. Describe *why*, not just *what* — the diff already shows what changed.

## Code style

- Go: standard `gofmt`/`go vet` conventions, enforced by `golangci-lint run ./...`.
- Comments explain *why*, not *what* — a hidden constraint, a workaround for a specific bug, a non-obvious invariant. Skip comments that just restate what well-named code already says.
- No speculative abstractions. A single implementation of something doesn't need an interface; three similar lines don't need a helper. This project has an explicit "rule of three, not before" precedent (see `docs/02-architecture-and-tech-stack.md` and `docs/10-implementation-plan-ph1b.md`'s Step 5 notes on `reporter.WriteJSON`).

## Contributing detectors or templates

Both are held to the false-positive-rate target in [docs/03-development-roadmap.md](docs/03-development-roadmap.md) (**<5%**) — a detector or template that fires on things that aren't real findings isn't a net improvement, even if it adds coverage. If a matcher is doubtful, flag it in your PR description rather than guessing it's fine.

If you're adding a Nuclei-compatible template by hand (rather than syncing from upstream), it must stay inside the supported subset — see [docs/template-writing-guide.md](docs/template-writing-guide.md) for exactly what's supported and what's rejected at load time (`raw:`/`payloads:`, `flow:`, `code:`/`javascript:`/`headless:`/`file:`, and the other disallowed protocol blocks). These are rejected deliberately, not gaps to work around.

## Security

Found a vulnerability *in HackerFive itself* (not a finding the tool produced against some other target)? See [SECURITY.md](SECURITY.md) — please don't open a public issue for that.

## Legal

By contributing, you agree your contribution is licensed under this project's [MIT License](LICENSE).
