# Nuclei sample templates

Four real, unmodified templates from [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) (MIT licensed — see that repo's `LICENSE.md`), committed here so Step 2's loader/executor can be exercised locally without first pinning a commit and running `scripts/sync-nuclei-templates.sh`.

**This is not "the curated set"** the roadmap targets (see [docs/10-implementation-plan-ph1b.md](../../docs/10-implementation-plan-ph1b.md) Step 2) — that's still the full `http/exposed-panels`/`http/misconfiguration`/`http/technologies` tree, synced from a pinned commit via the sync script, gitignored, and only used by the opt-in integration test. These four are a small, hand-picked, permanently-available sample for quick manual verification and as realistic loader test input — one from each of the three curated categories, plus one (`cors-misconfig.yaml`) specifically kept as a real example of the `raw:`/`payloads:` style.

Fetched 2026-08-24 from the `main` branch (no specific commit pinned for these four — they're samples, not the reproducible curated set that pinning exists for).

| File | Category | What it's here to demonstrate |
|---|---|---|
| `angular-detect.yaml` | `http/technologies` | A simple, single-request template — expected to genuinely fire against Juice Shop's Angular frontend |
| `adminer-panel.yaml` | `http/exposed-panels` | Multi-path (9 candidate paths) + `stop-at-first-match` + a regex extractor with a capture group |
| `django-debug-config-enabled.yaml` | `http/misconfiguration` | Two-matcher `and` condition (word + status) |
| `cors-misconfig.yaml` | `http/vulnerabilities/generic` | Uses `raw:`/`payloads:` (single-key inline payload) — loads and runs cleanly (fixed 2026-08-26, see doc10's `raw:`/`payloads:` note), but won't produce a correct finding yet: its payload values use unimplemented Nuclei helper functions (`rand_base`, `RDN`, `FQDN`) and its matcher's `dsl:` string references `{{cors_origin}}` directly — payload-variable substitution *inside a matcher*, which this project doesn't render (only `raw:`/`path:`/`headers:`/`body:` go through `{{}}` substitution) |

See [docs/10-implementation-plan-ph1b.md](../../docs/10-implementation-plan-ph1b.md) Step 2's "Verify against the sample templates" section for the exact commands.

**[dvwa-php/](dvwa-php/)** is a second, separate batch — five templates picked *after* reconning a live DVWA instance, specifically to have a real chance of matching (not guaranteed-empty like the four above). At the original 2026-08-24 run: two produced genuine findings, one loaded but correctly found nothing, and two were rejected at load time (real gaps: unary `!` DSL negation, and `raw:`/`payloads:`) — both since fixed, so all five now load cleanly. See that folder's own README for the full breakdown, including what's confirmed live vs. only confirmed to load.

**[crapi/](crapi/)** is a third batch — five templates picked for an API/Spring-Boot target (crAPI) instead of a plain PHP one, to exercise DSL paths the first two batches never hit. One produced a genuine, target-specific finding (MailHog panel detection), two loaded but found nothing due to crAPI's real routing (service-prefixed paths, not root), and two were correctly rejected at load time for DSL gaps distinct from the ones dvwa-php found (`mmh3`/`base64_py` functions, a `content_type` identifier). See that folder's own README for the full breakdown.
