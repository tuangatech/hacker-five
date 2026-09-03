# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

HackerFive — an open-source vulnerability scanner in Go, template-driven (YAML, Nuclei-style), built for HackerOne bug bounty hunting. See [docs/](docs/) for full plan; start with [docs/02-architecture-and-tech-stack.md](docs/02-architecture-and-tech-stack.md) and [docs/03-development-roadmap.md](docs/03-development-roadmap.md).

## Stack & conventions

- **Language:** Go 1.21+, CLI via Cobra, templates via `gopkg.in/yaml.v3`.
- **Layout:** `cmd/hackerfive/` (entrypoint), `pkg/{scanner,detectors,template,reporter}/`, `templates/idor/` (native detector templates), `templates/nuclei-samples/` (bundled nuclei-compatible samples), `templates/index.json` (synced-corpus index), `tests/{unit,integration,fixtures}/`.
- **Testing:** Go `testing` + testify; integration tests run against local vulnerable targets (crAPI, DVWA, Juice Shop, vAPI) via Docker Compose.
- **Lint:** `golangci-lint run ./...` before considering work done.

## Verification (this environment)

This checkout is `c:\ML-Projects\Weekend-Projects\hacker-five` (Windows-side). No Go toolchain on Windows PATH — instead, shell out to WSL2's toolchain via `wsl.exe`, against this checkout through its `/mnt/c` mount (no separate clone needed):
```bash
wsl.exe -e bash -lc "cd /mnt/c/ML-Projects/Weekend-Projects/hacker-five && go build ./... && go vet ./... && go test ./... -race && PATH=\$PATH:\$HOME/go/bin golangci-lint run ./..."
```
(`golangci-lint` needs the explicit `PATH` prepend — it's not on a non-interactive shell's PATH; see [docs/04-environment-and-testing.md](docs/04-environment-and-testing.md).)

`~/projects/hacker-five` is the user's separate, native-Linux clone — used for what the `/mnt/c` mount can't do: `docker compose` for live crAPI/DVWA targets and running `./hackerfive scan` against them (see [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md)). It has its own git history and needs its own `git pull`; edits here don't reach it automatically.

## Detection philosophy

- Push for broad vulnerability coverage — don't self-limit to a narrow slice out of caution; look for legitimate ways to widen what HackerFive can detect rather than treating current coverage as a ceiling.
- Avoid hallucinated findings/matchers (false positives erode trust — see the <5% target below), but don't over-correct into unnecessary restrictions or a defensively high safety bar that suppresses real detection capability just to be safe. Precision and coverage are both goals — don't sacrifice one by default to protect the other; flag genuine uncertainty instead of either guessing or refusing.
- Favor collecting more signal from a target during recon over less, whenever it's read-only and in-scope — a thin recon pass starves every later step of what it could have worked with.
- Treat everything recon collects as reusable downstream: a detector, template-selection, or reporting step should draw on the full available data set, not just the slice it gathers itself.
- Actively look for connections across steps/tasks — e.g. correlating a fingerprinted technology with an endpoint discovered separately — since combined signal from multiple sources is usually worth more than any one source alone.

## Rules

- `./hackerfive scan --detector X` still additively runs the full ~9,652-template synced corpus (7 nuclei-templates categories, widened 2026-09-03) unless scoped with `--templates <empty-dir>` or a non-matching `--tags` (see [docs/20-setup-testing-targets.md](docs/20-setup-testing-targets.md)'s gotcha note, hit twice on 2026-08-29).
- Never add code that exfiltrates data, writes/destroys target state, or targets a host outside an explicitly authorized scope — this tool only reads/enumerates (see [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md)). `--allow-writes` is the sole opt-in exception, scoped to `pkg/detectors/businesslogic`'s mutating checks (coupon mint/apply, race probes); absent, those checks are skipped with a stderr warning, never silently run.
- **HackerOne report submission is report-drafting assistance only — never unattended/automatic, a permanent invariant** (doc90 §B3: HackerOne's own "Responsible AI" update plus a public researcher-trust incident show how fast trust erodes once an agentic feature's boundaries blur). `pkg/hackerone.Client.CreateReportIntent` only ever creates a private, unsubmitted draft; `report create` never chains into submission; only `report submit --yes` calls `SubmitReportIntent`. Any future agent/automation work (see [docs/90-research-hackerbot.md](docs/90-research-hackerbot.md)) must preserve this human-in-the-loop gate on submission.
- Load credentials/tokens from environment variables only; never hardcode them.
- Keep new detectors/templates within the <5% false-positive target ([docs/03-development-roadmap.md](docs/03-development-roadmap.md)) — flag doubtful matchers instead of guessing.
- Search for the current stable version of a library/framework before use; don't rely on your own knowledge of versions.
- Before adding a new dependency, check its real transitive footprint (`go get` in a scratch branch, read the `go.mod` diff / `go list -m all`) — a lightweight-looking package can pull in unrelated subsystems (see [docs/02-architecture-and-tech-stack.md](docs/02-architecture-and-tech-stack.md) §8: `interactsh-client` added 134 unneeded go.mod lines from server-mode code). If the footprint is disproportionate, prefer a first-party implementation of just the needed protocol subset.

## Workflow

- Read existing files before writing code. Prefer editing over rewriting.
- For non-trivial tasks: discuss impact → plan affected code → update specs → implement.
- Push back with evidence when appropriate.
- Never mark a task complete without proving it works.
- Proactively recommend features/practices that raise the tool's maturity (feature parity with established tools, robustness, real-world usability), not just answers to the literal question asked.
- While testing or reviewing, raise any enhancement opportunity you notice (scanning quality, speed, maintainability) as soon as you see it; if it can't be done right away, log it to [docs/follow-up.md](docs/follow-up.md) instead of letting it drop.
- User instructions always override this file.
