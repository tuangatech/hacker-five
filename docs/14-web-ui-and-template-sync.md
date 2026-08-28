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

### Server design (v1)
- **New subcommand:** `hackerfive serve [--port 8877] [--host 127.0.0.1]`. Default bind is **loopback-only** — binding beyond `127.0.0.1` is opt-in and, per [Attack surface](#attack-surface--hardening) below, should require an explicit acknowledgment the same way `--insecure` (skip TLS verify) already does for scan targets.
- **Stack:** Go stdlib `net/http` + `html/template`, static assets (CSS + **htmx**) embedded via `go:embed` — no separate frontend build/toolchain, keeping with the "Minimal Dependencies" stance in doc02 §7. htmx (not a hand-rolled fetch/JS layer, and not a full SPA framework) is the deliberate middle point: server-rendered HTML stays the source of truth, but form submits and live updates swap DOM fragments instead of full page reloads — see [Pages & htmx interaction patterns](#pages--htmx-interaction-patterns) below.
- **Reuses, doesn't duplicate:** the HTTP handlers call into `pkg/scanner`, `pkg/template`, and `pkg/reporter` exactly as `cmd/hackerfive/scan.go` does today. The server is a new frontend on an unchanged core, per doc02's Scanner Engine module boundary.

### Pages & htmx interaction patterns

| Page | Route | Purpose |
|---|---|---|
| Dashboard | `/` | Recent scans (in-memory list), quick links to New Scan / Templates |
| New Scan | `/scans/new` | Form: target(s), `--detector`, `--tags`, auth tokens, rate-limit/concurrency/proxy, the required authorization checkbox |
| Scan Status/Results | `/scans/{id}` | Same page transitions from live progress → **findings streaming in** → final finding list as the job completes — no navigation away |
| Scan History | `/scans` | List of past scans this server process has run |
| Templates | `/templates` | Two panels: active-template table and the sync panel — see [Templates page: what to show](#templates-page-what-to-show) |

Five pages; "Sync now" is a fragment/action on the Templates page, not a separate route.

htmx does the interactivity without a JS build step:
- **Scan submission:** the New Scan form uses `hx-post="/scans" hx-target="#scan-panel"` — the response swaps in the progress panel in place, and `hx-push-url` updates the address bar to `/scans/{id}` so it's bookmarkable.
- **Live progress:** the **SSE extension** (`hx-ext="sse"`, `sse-connect="/scans/{id}/events"`, `sse-swap="progress"`) rather than polling — Go's `net/http` + `http.Flusher` support SSE with no new backend dependency, and it avoids a poll-every-N-seconds loop. The final SSE event swaps the progress panel for the finding table.
- **Live findings:** a second SSE event type (`sse-swap="finding"`) appends one row per finding as it's detected, via `hx-swap="beforeend"` — not a single swap-at-the-end. See [Live findings and logs](#live-findings-and-logs-a-real-engine-gap) below; this needs a small engine change, not just a UI wire-up.
- **Live logs:** a third event type (`sse-swap="log"`) appends into a separate scrolling panel — warnings and errors as they happen (host-error-cache trips, template load rejects, per-target failures), not just a final error count.
- **Templates page:** the tag filter does `hx-get="/templates?tags=..." hx-target="#template-table"`; "Sync now" is `hx-post="/templates/sync" hx-target="#sync-status"` with `hx-indicator` for a spinner during the (multi-second) git sparse-checkout.
- **Why this matters beyond v1:** once these `hx-*` attributes and the SSE event stream exist, adding e.g. a cancel-scan button or per-request log tailing is a new SSE event type plus a `hx-target` div — not a framework migration. This is the "prepare for future interactivity" property htmx buys over a plain-form/full-reload design.

### Live findings and logs: a real engine gap

Both "will errors/warnings show in New Scan?" and "are findings shown in real time?" are **yes, by design** — but neither is free with the engine as it stands today. `Engine.Run(ctx)` (`pkg/scanner/engine.go`) currently returns one batch, `([]detectors.Finding, error)`, only after every target and template finishes. Warnings go straight to `os.Stderr` via plain `fmt.Fprintf` (`loadScope`'s missing-`--scope` warning, `loadTemplates`' load-summary line, per-target skip messages) — never returned to the caller — and `pool.Wait()` only surfaces the *first* pooled error in its final message, silently dropping the rest. This is exactly the trigger condition doc02's "Future Considerations → Callback-based streaming results" already named as deferred until something needs it — the web UI is that something.

**Required engine change (small, additive, CLI-safe):** add an optional hook to `scanner.Engine`, e.g. `WithFindingCallback(func(detectors.Finding))` and `WithLogCallback(func(level, msg string))` (or one `WithEventSink(func(Event))`), invoked at the exact points that today just append to the slice or print to stderr — the finding-append in `Run`'s pooled closure, the `fmt.Fprintf` calls in `loadScope`/`loadTemplates`, and the per-target error path. The CLI (`cmd/hackerfive/scan.go`) keeps calling `Run` with no callback and gets today's batch behavior unchanged; only `pkg/webui` wires the callback, so `pkg/scanner` gains no dependency on the web layer.

### New components / code

**CLI (`cmd/hackerfive/`):**
- `serve.go` — new `serve` subcommand (`--port`, `--host`)
- `templates.go` — new `templates sync` / `templates list` subcommands

**New package `pkg/webui/`:**
- `server.go` — `http.Server`, routing, CSRF middleware (hand-rolled double-submit-cookie token — stdlib has no CSRF helper, and this stays consistent with the minimal-deps stance rather than pulling in a framework)
- `handlers_scan.go` — `POST /scans`, `GET /scans/{id}`, `GET /scans/{id}/events` (SSE) — calls straight into existing `pkg/scanner`, no scan logic duplicated here
- `handlers_templates.go` — `GET /templates`, `POST /templates/sync` — calls the new `pkg/templatesync` package
- `jobs.go` — in-memory job store (`map[string]*ScanJob`, mutex-guarded), one goroutine per running scan
- `templates/*.html` — `html/template` layout + per-page files + the SSE-swapped fragments
- `static/` — CSS, `htmx.min.js`, `htmx-ext-sse.js` (vendored, not CDN-loaded — the binary must work fully offline)
- `embed.go` — `//go:embed templates static`, the line that makes [Running it](#running-it-release-to-release) below simple

**New package `pkg/templatesync/`:** the Go port of `scripts/sync-nuclei-templates.sh` — see [Template sync command](#template-sync-command).

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

### Running it, release-to-release

The key design choice: **web assets (`html/template` files, CSS, `htmx.js`) are `go:embed`-ed into the binary, not shipped as loose files in the release archive.** Only the bundled, project-authored `templates/` (`templates/idor/*.yaml`, `templates/nuclei-samples/*` — already loose today since they're meant to be user-editable and versioned with each release) stays external in the zip.

That choice is what keeps the "download a new release" story identical to today's:
```powershell
# same as today — download & extract, no separate UI install step
.\hackerfive.exe --version

# from inside that same extracted folder, so ./templates/ default still resolves
.\hackerfive.exe serve
# → opens the default browser to http://127.0.0.1:8877 and prints the URL
#   (in case the auto-open is blocked/skipped, e.g. over SSH or a sandboxed shell)
```
No separate "install the web UI" step, no static-asset folder to keep in sync with the binary version, no risk of stale HTML being served against a newer binary. Because the UI is baked into the same artifact `goreleaser` already cross-compiles (doc10), **"update the web UI" and "update the CLI" are the same action: download the new release zip, extract, run.** This is doc02's original "why Go / single static binary" argument extended one layer up, not a new distribution mechanism.

**Synced (upstream) templates need the same property, and get it from a different mechanism** — see [Template sync command's default location](#template-sync-command) below: they live in a persistent OS user directory outside the extracted release folder entirely, so a new release never requires copying anything forward.

## Template sync command

`scripts/sync-nuclei-templates.sh` already does the core of this (sparse-checkout of `http/exposed-panels`, `http/misconfiguration`, `http/technologies` from a **pinned commit** of upstream `nuclei-templates`, cached in `.nuclei-templates-cache/`, re-run only explicitly via `make templates-sync` — never auto-updated to HEAD, so a compromised upstream commit between pins can't silently reach a scan). Two gaps to close, independent of the UI:

1. **Bash-only today, and this checkout is Windows-first.** The script needs WSL to run (see CLAUDE.md's verification section) — Windows users following the README's native `.exe` path can't run it directly. Promoting it to a Go subcommand (`hackerfive templates sync`, in the new `pkg/templatesync` package — see [New components / code](#new-components--code)) fixes that for free: same `git`-based sparse-checkout logic, cross-compiled into the existing release binary, no bash/WSL dependency. The shell script can stay as-is for CI/dev-container use, or become a thin wrapper.
2. **No listing/enable-disable surface.** Today "which templates are active" is implicit (whatever's under `--templates ./templates/`). Add `hackerfive templates list [--tags ...]` to enumerate what's synced, with category/tag/severity metadata pulled from each template's `info:` block.
3. **No default sync location that survives a binary upgrade.** In the dev repo, sync output lands in gitignored `.nuclei-templates-cache/`. Writing synced templates inside the extracted release folder (e.g. `./templates/nuclei-synced/`) would recreate exactly the "copy the folder forward on every upgrade" problem this is meant to solve. **Upstream Nuclei's own convention avoids it:** it downloads templates to `~/.config/nuclei-templates` (XDG config home) — a persistent user directory that lives outside wherever the `nuclei` binary itself is, so replacing the binary never touches it. HackerFive should do the same, via Go's stdlib `os.UserConfigDir()` (already XDG-aware on Linux, `~/Library/Application Support` on macOS, `%AppData%` on Windows — no new dependency): default `hackerfive templates sync` to write into `<UserConfigDir>/hackerfive/nuclei-templates/`.
   - `--templates` (currently a single `StringVar` flag in `cmd/hackerfive/scan.go`, even though the engine's `Config.TemplatePaths` is already `[]string`) needs to become repeatable, defaulting to **both** `./templates/` (bundled, project-authored) and `<UserConfigDir>/hackerfive/nuclei-templates/` (synced) — loaded together automatically, so a freshly downloaded binary picks up previously-synced templates with zero manual steps.
   - **No pre-sync category filter for end users.** The sparse-checkout stays limited to the same maintainer-curated categories (`http/exposed-panels`, `http/misconfiguration`, `http/technologies`) the script already pins — not a picker over arbitrary upstream categories. Opening that up would pull in matcher content nobody's vetted against this project's <5% false-positive target (CLAUDE.md: "flag doubtful matchers instead of guessing"), and it's the same trust boundary as the pinned-commit rule one level up — a category is a maintainer decision (bump the list, re-pin, re-review), not a runtime toggle. The only filter exposed in the UI is the existing **post-sync tag filter** over whatever's already in the curated set.

**Preserve the explicit-pin security posture exactly** — this is the one non-negotiable carried over from the existing script's comments: sync must target a pinned commit SHA (bumped deliberately, logged in the command's output), never an implicit `HEAD`/`latest`. The web UI's "Sync now" button calls this same subcommand; it does not add an "auto-update" toggle, and it does not add a category picker (see above).

### Templates page: what to show

Two panels, not one:
- **Active templates table** — everything currently loaded from `--templates` paths (both the bundled and synced directories): name, format (nuclei-compatible/native), category, tags, severity, and **source** (bundled vs. synced) so it's visible which templates ship with the release vs. came from an upstream sync. Checkboxes feed the next scan's `--tags` selection.
- **Sync panel** — pinned commit SHA, last-synced timestamp, per-category counts (same numbers the shell script already prints), and the "Sync now" button. No category picker here, per the filter discussion above — sync is one button, not a form.

## Effort & sequencing

Rough shape, not a committed schedule (doc03 owns actual week numbers if/when this gets scheduled):
- `pkg/templatesync` + `hackerfive templates sync`/`list` subcommands — small, mostly porting existing bash logic to Go; useful standalone even without the UI (unblocks Windows users today).
- `scanner.Engine` callback hooks (`WithFindingCallback`/`WithLogCallback`) — small, additive, but a real prerequisite for live findings/logs; see [Live findings and logs](#live-findings-and-logs-a-real-engine-gap). Worth landing before or alongside `pkg/webui`'s scan handlers, not after — the SSE handlers have nothing to stream without it.
- `pkg/webui` core (`server.go`, CSRF, `embed.go`, layout) + New Scan / Scan Status pages with the SSE job model — the bulk of the effort.
- Templates page — small once `templates list` exists and `pkg/webui` core is in place, since it's mostly a table + one `hx-post` over data the CLI subcommand already produces.
- Dashboard / Scan History pages — thin, once the job store and at least one other page exist.

Suggest doing the CLI template-sync subcommand first regardless of UI timing — it's useful on its own and de-risks the "Templates page" piece of the UI later.

## Authorization guardrail (UI-specific risk)

Worth calling out because it doesn't exist the same way on the CLI: typing `hackerfive scan -t <url>` is already a deliberate, typed action by someone who (presumably) chose that target. A web form with a text box and a "Scan" button lowers that friction — which is good for UX but means the UI should not lower the *authorization* bar along with it. Concretely: the "I am authorized to scan this target" checkbox in the start-scan form (mentioned above) is not decoration — treat it as a required field the same way `--insecure` requires an explicit flag today, and log the acknowledgment alongside the scan's audit trail.

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — Scanner Engine, Exporter interface, and the "Future Considerations" section this proposal graduates out of once scheduled
- [03-development-roadmap.md](03-development-roadmap.md) — where this would get an actual week/milestone number
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) / [22-authorized-targets.md](22-authorized-targets.md) — the authorization rules the UI's guardrail is enforcing
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — `scripts/sync-nuclei-templates.sh` and the pinned-commit rationale this doc builds on
