# Web UI & Template Sync (Proposal — Not Yet Scheduled)

> Part of the [HackerFive documentation set](../README.md).

**Status:** Discussion/proposal, not committed to [03-development-roadmap.md](03-development-roadmap.md). Phase 1a/1b are done (`v0.1.0` released — CLI, IDOR + misconfig detectors, both template engines); Phase 2 (API auth bypass, XSS, SQLi) is next per the roadmap. This doc captures the design so it's ready to slot in as a later milestone (post-Phase-2/3, alongside or after Milestone 4 "Community") without re-deriving the reasoning from scratch.

## Why

The CLI (`hackerfive scan -t ... --detector ...`) works but has real friction for anyone who isn't comfortable in a terminal: remembering flags, reading raw JSON findings, and manually running `scripts/sync-nuclei-templates.sh` to refresh the Nuclei template corpus. A web UI removes that friction for the "run a scan, read the results" workflow. It should **not** replace the CLI — CI/scripted use, and power users who want full flag control, keep using `hackerfive scan` exactly as today.

## Scope

### In scope (v1)
- **Start a scan from a form:** target URL(s), detector selection, template tags, and the same knobs the CLI already exposes (`--rate-limit`, `--concurrency`, `--proxy`, `--auth-token`/`--other-auth-token`, `--endpoint` for IDOR) — the UI is a frontend over the existing `pkg/scanner` engine, not a second implementation of it.
- **View results:** findings rendered from the same `Finding` struct / `Exporter` interface (doc02 §5) that already produces JSON/Markdown/HTML — the UI adds an interactive HTML view (filter by severity/detector, expand request/response evidence), it doesn't reinvent finding storage.
- **Template management:** browse synced Nuclei templates by category/tag, see which are enabled for the next scan, and trigger a sync — see [Template Sync](#template-sync-command) below.
- **Scan history (v1, minimal):** a list of past scans in this session/process, so results aren't lost when you start a second scan. Not a durable multi-user history store (see Non-Goals).

### Answering directly: target URL + results on the same page?
**Yes.** A "start scan" form (target + options) and a "results" view are the two things this UI exists to provide — without them it's not a scanning UI, just a template browser. Concretely:
- One page: target input (single URL or paste a list, mirroring `-t`), detector/template/tag selection, an explicit **"I am authorized to scan this target"** acknowledgment checkbox (see [Authorization guardrail](#authorization-guardrail-ui-specific-risk) — this risk doesn't exist the same way on the CLI), then "Start Scan."
- On submit, the scan runs as a background job (see [Async job model](#async-job-model)); the same page (or a `/scans/{id}` route) shows live progress and then the finding list once complete, with a link to download the JSON/HTML/HackerOne-schema export.
- Optionally, pre-fill the target dropdown from [22-authorized-targets.md](22-authorized-targets.md)'s vetted list — reduces the chance of typo-scanning an unauthorized host, but free-text entry stays available since most real engagements aren't in that registry.

### Non-goals (explicitly out of scope)
- **No hosted/cloud SaaS mode.** See [Local-only architecture](#local-only-architecture-why) — this is the load-bearing design decision, not a deferred feature.
- **No multi-tenant accounts/RBAC.** Single operator, single machine, matches how the CLI is used today.
- **No scheduled/recurring scans, no scan queue persisted across restarts.** If that need shows up later it's a SQLite-backed job table, not a v1 concern (doc02 already lists SQLite as "Optional" future storage).
- **No new detection logic.** The UI calls the same detectors; it adds no new vulnerability classes.

## Local-only architecture (why)

**Recommendation: an embedded local web server (`hackerfive serve`), not a separately hosted web app.**

The reasoning is a direct consequence of this project's existing rules, not a new constraint invented for the UI:
- CLAUDE.md: *"Never add code that exfiltrates data... this tool only reads/enumerates"* and *"Load credentials/tokens from environment variables only."* A hosted UI means a user's target URLs and auth tokens leave their machine and land on infrastructure this project would then have to secure, audit, and be trusted with — a fundamentally different threat model than a CLI binary that never phones home.
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) and [22-authorized-targets.md](22-authorized-targets.md) both assume the operator is personally accountable for scope/authorization on each scan. A shared hosted service blurs who's actually running (and responsible for) a given scan.
- doc02's core "why Go" argument is single-binary distribution with no external dependencies. An embedded server preserves that: `hackerfive serve` opens a browser tab to `localhost:PORT`, same binary, same release artifact, no separate deploy pipeline, no hosting cost, nothing new for the release process (doc10) to package.

### Server design (v1 sketch)
- **New subcommand:** `hackerfive serve [--port 8877] [--host 127.0.0.1]`. Default bind is **loopback-only** — binding beyond `127.0.0.1` is opt-in and, per [Attack surface](#attack-surface--hardening) below, should require an explicit acknowledgment the same way `--insecure` (skip TLS verify) already does for scan targets.
- **Stack:** Go stdlib `net/http` + `html/template`, static assets (CSS/minimal JS) embedded via `go:embed` — no separate frontend build/toolchain, keeping with the "Minimal Dependencies" stance in doc02 §7. If interactivity needs grow (live progress bars, filtering without full page reloads) reach for htmx before reaching for a full SPA framework — same "smallest thing that solves the actual problem" bar as the rest of the stack.
- **Reuses, doesn't duplicate:** the HTTP handlers call into `pkg/scanner`, `pkg/template`, and `pkg/reporter` exactly as `cmd/hackerfive/scan.go` does today. The server is a new frontend on an unchanged core, per doc02's Scanner Engine module boundary.

### Async job model
A scan can run for minutes; the HTTP request that starts it can't just block:
- `POST /scans` validates the form, starts the scan in a goroutine, returns a job ID immediately.
- `GET /scans/{id}` (or `/scans/{id}/events` via Server-Sent Events) reports status: queued → running (with progress: requests sent / templates matched) → done/failed.
- Job state lives **in-memory** for v1 (a map keyed by job ID) — acceptable because the server is a local, single-operator process; state loss on restart is a non-issue the same way `hackerfive scan` output today is a non-issue (you just re-run it). Durable history is a deferred concern (see Non-Goals).

### Attack surface & hardening
Binding a port, even on loopback, is new attack surface a pure CLI tool doesn't have:
- **CSRF protection** on the `POST /scans` (and any other state-changing) endpoint even though it's loopback-only — other local processes/browser tabs can still reach `localhost`.
- **No auth token required for the default loopback bind** (matches the trust model of "it's your own machine"), but **require a token** (printed to stdout at startup, Jupyter-notebook-style: `http://127.0.0.1:8877/?token=...`) the moment `--host` is set to anything other than `127.0.0.1`/`::1`.
- **Rate/target guardrails carry over unchanged** — the UI form still goes through the same `--rate-limit`/`--concurrency` defaults and host-error-cache circuit breaker (doc02 §3) as the CLI; the UI doesn't get to bypass them.

## Template sync command

`scripts/sync-nuclei-templates.sh` already does the core of this (sparse-checkout of `http/exposed-panels`, `http/misconfiguration`, `http/technologies` from a **pinned commit** of upstream `nuclei-templates`, cached in `.nuclei-templates-cache/`, re-run only explicitly via `make templates-sync` — never auto-updated to HEAD, so a compromised upstream commit between pins can't silently reach a scan). Two gaps to close, independent of the UI:

1. **Bash-only today, and this checkout is Windows-first.** The script needs WSL to run (see CLAUDE.md's verification section) — Windows users following the README's native `.exe` path can't run it directly. Promoting it to a Go subcommand (`hackerfive templates sync`) fixes that for free: same `git`-based sparse-checkout logic, cross-compiled into the existing release binary, no bash/WSL dependency. The shell script can stay as-is for CI/dev-container use, or become a thin wrapper.
2. **No listing/enable-disable surface.** Today "which templates are active" is implicit (whatever's under `--templates ./templates/`). Add `hackerfive templates list [--tags ...]` to enumerate what's synced, with category/tag/severity metadata pulled from each template's `info:` block.

**Preserve the explicit-pin security posture exactly** — this is the one non-negotiable carried over from the existing script's comments: sync must target a pinned commit SHA (bumped deliberately, logged in the command's output), never an implicit `HEAD`/`latest`. The web UI's "Sync now" button calls this same subcommand; it does not add an "auto-update" toggle.

The web UI's **Templates page** is then a thin view over these two subcommands: a table of synced templates (name, category, tags, severity) with checkboxes feeding into the next scan's `--tags` filter, and a "Sync now" button showing the pinned commit and category counts (same output the shell script already prints today).

## Effort & sequencing

Rough shape, not a committed schedule (doc03 owns actual week numbers if/when this gets scheduled):
- `hackerfive templates sync`/`list` subcommands — small, mostly porting existing bash logic to Go; useful standalone even without the UI (unblocks Windows users today).
- `hackerfive serve` + start-scan/results pages — the bulk of the effort: async job model, SSE/polling, HTML templates for the finding view.
- Templates page — small once `templates list` exists, since it's just a table over that data.

Suggest doing the CLI template-sync subcommand first regardless of UI timing — it's useful on its own and de-risks the "Templates page" piece of the UI later.

## Authorization guardrail (UI-specific risk)

Worth calling out because it doesn't exist the same way on the CLI: typing `hackerfive scan -t <url>` is already a deliberate, typed action by someone who (presumably) chose that target. A web form with a text box and a "Scan" button lowers that friction — which is good for UX but means the UI should not lower the *authorization* bar along with it. Concretely: the "I am authorized to scan this target" checkbox in the start-scan form (mentioned above) is not decoration — treat it as a required field the same way `--insecure` requires an explicit flag today, and log the acknowledgment alongside the scan's audit trail.

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — Scanner Engine, Exporter interface, and the "Future Considerations" section this proposal graduates out of once scheduled
- [03-development-roadmap.md](03-development-roadmap.md) — where this would get an actual week/milestone number
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) / [22-authorized-targets.md](22-authorized-targets.md) — the authorization rules the UI's guardrail is enforcing
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — `scripts/sync-nuclei-templates.sh` and the pinned-commit rationale this doc builds on
