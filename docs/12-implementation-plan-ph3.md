# Phase 3 Implementation Plan — Weeks 19-24 (Web UI & Template Sync)

> Part of the [HackerFive documentation set](../README.md).

**Status:** Scheduled as Phase 3 in [03-development-roadmap.md](03-development-roadmap.md), weeks 19-24, shipping as `v0.3.0`. Phase 1a/1b (`v0.1.0`) and Phase 2 (`v0.2.0` — API auth bypass, XSS, SQLi, 2026-08-28) are both done. This doc was originally drafted as an unscheduled proposal before Phase 2 shipped; the user then chose to run it as **Phase 3**, ahead of the Prompt Injection/SSRF/Business Logic Flaws specialization work (now Phase 4, see [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md)) — a Web UI makes `v0.2.0`'s existing detectors easier to exercise day-to-day, and neither phase depends on the other (this one wraps the existing `pkg/scanner` engine and needs none of Phase 4's new detectors). The design below is unchanged from the original proposal; only the scheduling/status framing and week numbers are updated to reflect it now being committed work, not a maybe.

## Why

The CLI (`hackerfive scan -t ... --detector ...`) works but has real friction for anyone who isn't comfortable in a terminal: remembering flags, reading raw JSON findings, and manually running `scripts/sync-nuclei-templates.sh` to refresh the Nuclei template corpus. A web UI removes that friction for the "run a scan, read the results" workflow. It should **not** replace the CLI — CI/scripted use, and power users who want full flag control, keep using `hackerfive scan` exactly as today.

## Scope

### In scope (v1)
- **Start a scan from a form:** target URL(s) and the real, current CLI surface (verified against `cmd/hackerfive/scan.go`, not the pre-Phase-2 flag list an earlier draft of this doc assumed) — `--detector` (required: `idor` | `misconfig` | `authbypass` — `misconfig` needs no token, the natural default), `--tags`, `--rate-limit`, `--concurrency`, `--proxy`, `--timeout`, `--insecure`, `--scope`, `--auth-token`/`--other-auth-token`, `--auth-header-name`/`--auth-header-format`, `--header` (repeatable), plus the detector-specific fields that only apply when their detector is selected: `--endpoint` (idor) and `--protected-paths`/`--login-paths`/`--logout-paths` (authbypass). The UI is a frontend over the existing `pkg/scanner` engine, not a second implementation of it.
- **View results:** findings rendered directly from `[]detectors.Finding` (`pkg/detectors/types.go` — a flat, `html/template`-friendly struct; no `Exporter` needed for this) via a new webui-specific HTML view (filter by severity/detector, expand request/response evidence). The download link reuses the existing `reporter.WriteJSON` for a JSON export. **Not available yet, deliberately not pulled forward from Phase 4:** the `Exporter` interface and Markdown/HTML-file/HackerOne-JSON-schema exports (doc02 §5) are design-only today — nothing in `pkg/reporter` beyond `WriteJSON` exists — and stay scheduled as Phase 4 Step 4 ([13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Week 31). An earlier draft of this doc assumed that work already existed to reuse; it doesn't, and Phase 3 now runs *before* Phase 4 post-swap, so this doc no longer assumes it.
- **Template management:** browse synced Nuclei templates by category/tag, see which are enabled for the next scan, and trigger a sync — see [Template Sync](#template-sync-command) below.
- **Scan history (v1, minimal):** a list of past scans in this session/process, so results aren't lost when you start a second scan. Not a durable multi-user history store (see Non-Goals).

### Answering directly: target URL + results on the same page?
**Yes.** A "start scan" form (target + options) and a "results" view are the two things this UI exists to provide — without them it's not a scanning UI, just a template browser. Concretely:
- One page: target input (single URL or paste a list, mirroring `-t`), detector/template/tag selection, an explicit **"I am authorized to scan this target"** acknowledgment checkbox (see [Authorization guardrail](#authorization-guardrail-ui-specific-risk) — this risk doesn't exist the same way on the CLI), then "Start Scan."
- On submit, the scan runs as a background job (see [Async job model](#async-job-model)); the same page (or a `/scans/{id}` route) shows live progress and then the finding list once complete, with a link to download the JSON export (`reporter.WriteJSON` — the only format that exists today; see the Scope note above on why HTML/Markdown/HackerOne-JSON *file* exports stay a Phase 4 item, not this page's live HTML view).
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
| New Scan | `/scans/new` | Form: target(s), `--detector` (idor/misconfig/authbypass, required), `--tags`, auth tokens/header scheme, rate-limit/concurrency/proxy/timeout/insecure/scope, detector-specific fields shown conditionally (`--endpoint` for idor; `--protected-paths`/`--login-paths`/`--logout-paths` for authbypass), the required authorization checkbox |
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

### Backpressure and reconnect: one job store, not two buffers

Two follow-on gaps the design above doesn't answer by itself:

- **Backpressure.** The callbacks above fire *synchronously*, inside the same pooled goroutine `runDetector` runs in (`engine.go:104`'s closures). If `pkg/webui` wires a callback straight into a blocking channel send, a slow or disconnected browser tab holds that worker-pool slot open — a UI hiccup becomes a **stalled scan**, not just a stale page, and with the default concurrency of 25, enough stuck subscribers measurably hurts real throughput for everyone, not just the one tab.
- **Reconnect/replay.** `hx-ext="sse"` reconnects automatically on a dropped connection or a page refresh mid-scan. Without a defined replay story, refreshing 90% through a scan shows an *empty* findings table until the next new finding arrives — reading as "the scan reset," not "the scan resumed."

**Resolution: one `Job` struct is the durable source of truth for both — not a separate ring buffer for backpressure and a separate replay log for reconnect.**
```go
type Job struct {
    ID       string
    Status   string // "queued" | "running" | "done" | "failed"
    Findings []detectors.Finding
    Logs     []LogEntry
    mu       sync.Mutex
    subs     []chan Event // live SSE subscribers on the *current* connection only
}
```
- `WithFindingCallback`/`WithLogCallback` append to `Job.Findings`/`Job.Logs` under `mu` **first** — that's what makes the job queryable at all, independent of any SSE connection's state — then publish to every current subscriber in `subs` with a **non-blocking send** (`select { case sub <- event: default: }`). A dropped live push is harmless by construction: it never touches the accumulated `Findings`/`Logs`, so nothing is lost, only a live-UI update is skipped — which the next step immediately fixes.
- **Initial render, not event replay, is what actually fixes reconnect.** `GET /scans/{id}` — whether it's the first page load or a post-refresh reload — renders the job's current `Findings`/`Logs` directly from the `Job` struct before attaching SSE, then SSE only needs to stream what happens *after* that point. This reuses the exact same accumulation Scan History and the final finding list already need; it doesn't require a second, sequence-numbered event-log-replay mechanism just for reconnect.
- **`subs` needs an unsubscribe path, not just append-on-subscribe.** htmx's SSE extension auto-reconnects on any hiccup — a dropped wifi packet, a backgrounded tab — meaning `GET /scans/{id}/events` fires repeatedly over one scan's lifetime, and without removal `subs` only ever grows: real, unbounded per-job memory growth the longer a scan (or a flaky connection) runs. Fix: `Job` exposes `func (j *Job) Subscribe() (ch chan Event, unsubscribe func())` — the handler registers `ch` in `subs` under `mu`, defers `unsubscribe()` (which removes `ch` from `subs` under `mu`), and triggers that defer via `r.Context().Done()`, which `net/http` already closes on client disconnect. No new mechanism beyond the request context stdlib already provides.
- Net effect: backpressure and reconnect resolve to the same underlying fix — durable accumulation plus best-effort live push, with subscribers cleaned up as they come and go — not two separate features that need to be kept in sync with each other.

### New components / code

**CLI (`cmd/hackerfive/`):**
- `serve.go` — new `serve` subcommand (`--port`, `--host`)
- `templates.go` — new `templates sync` / `templates list` subcommands

**New package `pkg/webui/`:**
- `server.go` — `http.Server`, routing, CSRF middleware (hand-rolled double-submit-cookie token — stdlib has no CSRF helper, and this stays consistent with the minimal-deps stance rather than pulling in a framework)
- `handlers_scan.go` — `POST /scans`, `GET /scans/{id}`, `GET /scans/{id}/events` (SSE) — calls straight into existing `pkg/scanner`, no scan logic duplicated here
- `handlers_templates.go` — `GET /templates`, `POST /templates/sync` — calls the new `pkg/templatesync` package. **Must translate `templatesync.ErrGitNotFound` into the `#sync-status` fragment**, not let it bubble as an unhandled 500 — see the "git not found" note in [Template sync command](#template-sync-command) below, which is written CLI-first and needs the same friendly-message treatment here for a browser user
- `jobs.go` — in-memory job store (`map[string]*Job`), one goroutine per running scan; `Job` shape and its non-blocking-publish/reconnect design are in [Backpressure and reconnect](#backpressure-and-reconnect-one-job-store-not-two-buffers) above
- `templates/*.html` — `html/template` layout + per-page files + the SSE-swapped fragments
- `static/` — CSS, `htmx.min.js`, `htmx-ext-sse.js` (vendored, not CDN-loaded — the binary must work fully offline)
- `embed.go` — `//go:embed templates static`, the line that makes [Running it](#running-it-release-to-release) below simple

**New package `pkg/templatesync/`:** the Go port of `scripts/sync-nuclei-templates.sh` — see [Template sync command](#template-sync-command).

### Async job model
A scan can run for minutes; the HTTP request that starts it can't just block:
- `POST /scans` validates the form, starts the scan in a goroutine, returns a job ID immediately.
- `GET /scans/{id}` renders the job's current status **and** its accumulated `Findings`/`Logs` so far (not just a status string) — see [Backpressure and reconnect](#backpressure-and-reconnect-one-job-store-not-two-buffers) for why this is what makes a page refresh mid-scan safe. `/scans/{id}/events` (SSE) streams anything after that snapshot.
- Job state lives **in-memory** for v1 (a map keyed by job ID) — acceptable because the server is a local, single-operator process; state loss on restart is a non-issue the same way `hackerfive scan` output today is a non-issue (you just re-run it). Durable history is a deferred concern (see Non-Goals).
- **Eviction policy, stated explicitly rather than left unbounded.** The project's own performance target (doc03: scan 1000 targets in <5 min) means a single job's `Findings`/`Logs` can already be large; run several such scans back-to-back in one `serve` session with no cap and the job store grows for as long as the process lives. v1 policy: cap the store to the most recent **50 jobs**, evicting the oldest on insert past the cap — a fixed, documented starting number, not a guess left unstated, adjustable once real usage shows whether 50 is too tight or too loose.

### Attack surface & hardening
Binding a port, even on loopback, is new attack surface a pure CLI tool doesn't have:
- **CSRF protection** on the `POST /scans` (and any other state-changing) endpoint even though it's loopback-only — other local processes/browser tabs can still reach `localhost`.
- **No auth token required for the default loopback bind** (matches the trust model of "it's your own machine"), but **require a token** (printed to stdout at startup, Jupyter-notebook-style: `http://127.0.0.1:8877/?token=...`) the moment `--host` is set to anything other than `127.0.0.1`/`::1`. **Known tradeoff, stated rather than silently accepted:** a query-string token lands in shell history, proxy/access logs, and browser history — the same real, documented criticism Jupyter's own `?token=` scheme has drawn. Mitigation path for v1: treat the URL token as a one-time bootstrap only — on the first successful `?token=` request, set an `HttpOnly` session cookie and require *that* cookie (not the URL param) on every request after, so exposure is limited to one initial URL rather than every subsequent request/log line.
- **Rate/target guardrails carry over unchanged** — the UI form still goes through the same `--rate-limit`/`--concurrency` defaults and host-error-cache circuit breaker (doc02 §3) as the CLI; the UI doesn't get to bypass them.
- **Browser per-origin connection limits are a stated v1 limitation, not addressed.** Go's stdlib `net/http` serves plain HTTP/1.1 by default, and browsers cap concurrent HTTP/1.1 connections per origin (~6 in Chrome). Each open `/scans/{id}/events` SSE stream holds one of those connections for the scan's duration, so a few scan-status tabs left open simultaneously against the same `hackerfive serve` origin can silently exhaust the budget, blocking further requests to that origin (including new page loads) until one closes. Acceptable for v1's "one scan at a time" mental model; HTTP/2 (available over TLS, or via `h2c` for plaintext) is the future mitigation if this becomes real friction — not committed to for v1.

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

1. **Bash-only today, and this checkout is Windows-first — but the real fix still needs `git`, stated explicitly.** The script needs WSL to run (see CLAUDE.md's verification section) — Windows users following the README's native `.exe` path can't run it directly. Promoting it to a Go subcommand (`hackerfive templates sync`, in the new `pkg/templatesync` package — see [New components / code](#new-components--code)) fixes the bash/WSL dependency — but is **not** dependency-free, and an earlier draft of this doc implied otherwise. The script's actual mechanism (`git clone --filter=blob:none --no-checkout` + `sparse-checkout set` + `checkout <sha>`) is a partial-clone + cone-mode sparse-checkout — cross-compiling the *logic* into Go still means shelling out to system `git` via `os/exec`, and Windows doesn't ship `git` by default. **v1 plan:** keep shelling out to system `git`; document `git` on `PATH` as a stated prerequisite for `templates sync` specifically (the rest of the binary stays dependency-free); the package exports a distinguishable `templatesync.ErrGitNotFound` (not a raw `exec: "git": executable file not found` stack trace) so **every caller renders its own friendly message from the same signal** — `hackerfive templates sync`'s CLI stderr text today, and the `POST /templates/sync` htmx handler's `#sync-status` fragment once Week 23 builds it (see the `handlers_templates.go` note under [New components / code](#new-components--code) — a browser user without `git` on PATH must not just see an unhandled 500). A pure-Go client (`go-git`) would close this gap for real, but its partial-clone/cone-mode sparse-checkout support is materially less mature than CLI `git` — that's a spike-first item, not something to commit to here, per the same "measure before committing" discipline doc10/11 already apply throughout (e.g. the `raw:`/`payloads:` scope corrections). The shell script can stay as-is for CI/dev-container use, or become a thin wrapper.
2. **No listing/enable-disable surface.** Today "which templates are active" is implicit (whatever's under `--templates ./templates/`). Add `hackerfive templates list [--tags ...]` to enumerate what's synced, with tag/severity metadata pulled from each template's `info:` block — **not category**: neither `nuclei.Info` nor `native.Info` has a `Category` field (confirmed against `pkg/template/{nuclei,native}/schema.go`), so "category" in the Templates page (below) is derived from which source directory a template loaded from, not template content.
3. **No default sync location that survives a binary upgrade.** In the dev repo, sync output lands in gitignored `.nuclei-templates-cache/`. Writing synced templates inside the extracted release folder (e.g. `./templates/nuclei-synced/`) would recreate exactly the "copy the folder forward on every upgrade" problem this is meant to solve. **Upstream Nuclei's own convention avoids it:** it downloads templates to `~/.config/nuclei-templates` (XDG config home) — a persistent user directory that lives outside wherever the `nuclei` binary itself is, so replacing the binary never touches it. HackerFive should do the same, via Go's stdlib `os.UserConfigDir()` (already XDG-aware on Linux, `~/Library/Application Support` on macOS, `%AppData%` on Windows — no new dependency): default `hackerfive templates sync` to write into `<UserConfigDir>/hackerfive/nuclei-templates/`.
   - `--templates` (currently a single `StringVar` flag in `cmd/hackerfive/scan.go`, even though the engine's `Config.TemplatePaths` is already `[]string`) needs to become repeatable, defaulting to **both** `./templates/` (bundled, project-authored) and `<UserConfigDir>/hackerfive/nuclei-templates/` (synced) — loaded together automatically, so a freshly downloaded binary picks up previously-synced templates with zero manual steps.
   - **No pre-sync category filter for end users.** The sparse-checkout stays limited to the same maintainer-curated categories (`http/exposed-panels`, `http/misconfiguration`, `http/technologies`) the script already pins — not a picker over arbitrary upstream categories. Opening that up would pull in matcher content nobody's vetted against this project's <5% false-positive target (CLAUDE.md: "flag doubtful matchers instead of guessing"), and it's the same trust boundary as the pinned-commit rule one level up — a category is a maintainer decision (bump the list, re-pin, re-review), not a runtime toggle. The only filter exposed in the UI is the existing **post-sync tag filter** over whatever's already in the curated set.

**Preserve the explicit-pin security posture exactly** — this is the one non-negotiable carried over from the existing script's comments: sync must target a pinned commit SHA (bumped deliberately, logged in the command's output), never an implicit `HEAD`/`latest`. The web UI's "Sync now" button calls this same subcommand; it does not add an "auto-update" toggle, and it does not add a category picker (see above).

### Templates page: what to show

Two panels, not one:
- **Active templates table** — everything currently loaded from `--templates` paths (both the bundled and synced directories): name, format (nuclei-compatible/native), tags, severity, category (derived from the loaded source directory, not an `info:` field — see the Template sync command note above), and **source** (bundled vs. synced) so it's visible which templates ship with the release vs. came from an upstream sync. Checkboxes feed the next scan's `--tags` selection.
- **Sync panel** — pinned commit SHA, last-synced timestamp, per-category counts (same numbers the shell script already prints), and the "Sync now" button. No category picker here, per the filter discussion above — sync is one button, not a form.

## Effort & sequencing — mapped to doc03's Weeks 19-24

Per [03-development-roadmap.md](03-development-roadmap.md)'s Phase 3 schedule:
- **Week 19 — Template Sync CLI + Engine Streaming Hooks — ✅ implemented, live-verified (2026-08-28)**: `pkg/templatesync` (`sync.go`/`location.go`/`list.go`) + `hackerfive templates sync`/`list` subcommands (`cmd/hackerfive/templates.go`), plus `scanner.Engine.WithFindingCallback`/`WithLogCallback` (`pkg/scanner/engine.go`) wired into all four named sites (`loadScope`'s warning, the per-target scope-skip message, `loadTemplates`' summary, and the previously-silent per-target detector-error path). `--templates` (`cmd/hackerfive/scan.go`) is now repeatable and auto-appends the synced directory when left at its default. 17 new unit tests (6 engine, 6 templatesync, 4 CLI — plus `TestList_MismatchedLengths`), all passing; `go build`/`vet`/`test -race`/`golangci-lint` clean. **Live-verified**: `hackerfive templates sync`'s per-category counts (1560/980/910/19) match `make templates-sync`'s shell script byte-for-byte at the same pinned commit; `hackerfive templates list` correctly enumerates bundled templates pre-sync and labels bundled vs. synced correctly post-sync; a real `hackerfive scan` with `--templates` omitted picked up the full ~3469-template synced corpus (confirmed via the `filtered by tag` count when narrowed with `--tags`), while an explicit `--templates` value correctly did not. Both land before `pkg/webui`'s scan handlers, not after — the SSE handlers have nothing to stream without the hooks, and template sync is useful on its own and de-risks the Templates page below.
- **Week 20-22 — Local Web Server (`pkg/webui`) — ✅ implemented, live-verified (2026-08-28)**: `pkg/webui` core (`server.go`, `csrf.go`, `auth.go`, `jobs.go`, `render.go`, `browser.go`, `embed.go`) + New Scan (`/scans/new`) / Scan Status (`/scans/{id}`) pages with the SSE job model, plus `hackerfive serve` (`cmd/hackerfive/serve.go`). Dashboard (`/`) is a minimal placeholder for this slice, per this section's own scoping — Week 23 replaces it with real Scan History content. htmx 2.0.10 / htmx-ext-sse 2.2.4 vendored and pinned (verified against the npm registry, not assumed — see `pkg/webui/VENDORED.md`). 26 new unit tests (job store/SSE subscriber lifecycle, CSRF, non-loopback token/session handoff, and a full end-to-end `POST /scans` → `GET /scans/{id}` → `GET /scans/{id}/events` flow against a real `httptest.Server` target), all passing; `go build`/`vet`/`test -race`/`golangci-lint` clean. **Live-verified** against the real binary and a live DVWA target: a scan submitted through the actual web form produced 17 real findings and real log lines (including the authorization-checkbox acknowledgment) streamed via SSE and visible mid-scan before completion; `export.json` produced real `reporter.WriteJSON` output; a forged `POST /scans` without the CSRF cookie was rejected (403); binding to a non-loopback host (`--host 0.0.0.0`) correctly required the printed bootstrap token (401 without it), and presenting it once redirected with the token stripped from the URL and set an `HttpOnly` session cookie that alone granted access to every request after; `SIGTERM` triggered a clean graceful shutdown (exit code 0).
- **Week 23 — Templates Page + Dashboard/History**: Templates page (small once `templates list` exists and `pkg/webui` core is in place — mostly a table + one `hx-post` over data the CLI subcommand already produces) + Dashboard/Scan History pages (thin, once the job store and at least one other page exist).
- **Week 24 — Hardening & Release**: CSRF/loopback-bind verification, cross-platform manual verification, docs, `v0.3.0` release. See each section above (`Attack surface & hardening`, `Running it, release-to-release`) for the specifics this week verifies.

## Authorization guardrail (UI-specific risk)

Worth calling out because it doesn't exist the same way on the CLI: typing `hackerfive scan -t <url>` is already a deliberate, typed action by someone who (presumably) chose that target. A web form with a text box and a "Scan" button lowers that friction — which is good for UX but means the UI should not lower the *authorization* bar along with it. Concretely: the "I am authorized to scan this target" checkbox in the start-scan form (mentioned above) is not decoration — treat it as a required field the same way `--insecure` requires an explicit flag today, and log the acknowledgment alongside the scan's audit trail.

**Forward-looking: the same elevated treatment applies to any future flag that breaks the read/enumerate-only invariant, not just the authorization checkbox.** `--allow-writes` doesn't exist in the CLI yet (doc13/Phase 4 Step 3 adds it), but [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) already calls it "the one deliberate, bounded, explicitly-opted-into exception" to CLAUDE.md's read/enumerate-only rule — a stronger claim on the user than the authorization checkbox itself gets non-decorative treatment for. When it lands, it must not become just another checkbox in the New Scan options blob alongside rate-limit/proxy settings: it needs its own separate confirmation step (its own explicit acknowledgment text, not bundled into the general "I am authorized" checkbox) and its own audit-log entry, mirroring this section's treatment exactly. Noted here now, ahead of the flag existing, so the New Scan form's eventual Phase 4 update doesn't quietly downgrade it to a checkbox for convenience.

## See also
- [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — Scanner Engine, Exporter interface, and the "Future Considerations" section this plan graduates out of
- [03-development-roadmap.md](03-development-roadmap.md) — full Phase 1-4 roadmap; this plan is its Phase 3 slice (Weeks 19-24)
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) / [22-authorized-targets.md](22-authorized-targets.md) — the authorization rules the UI's guardrail is enforcing
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) / [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) — the foundation this plan builds directly on top of; `scripts/sync-nuclei-templates.sh` and the pinned-commit rationale doc10 established
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the Prompt Injection/SSRF/Business Logic Flaws specialization work that follows this phase, unblocked independently of it
