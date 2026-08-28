# XSS sample templates

Two real, unmodified upstream templates from `http/vulnerabilities/generic/` — added 2026-08-28 as part of Phase 2 Step 2 ([docs/11-implementation-plan-ph2.md](../../../docs/11-implementation-plan-ph2.md)). This category isn't in `scripts/sync-nuclei-templates.sh`'s original three (`http/exposed-panels`/`http/misconfiguration`/`http/technologies`) — confirmed via direct fetch against the already-pinned commit (`0aa256a344d5b53648575163c61517ac67f57961`) that real, generic (non-product-specific) reflected-XSS templates live here instead, the same category [../README.md](../README.md)'s `cors-misconfig.yaml` sample already came from.

Both are passive/reflected-XSS checks: inject a payload into the URL (a fixed path suffix or common query parameters), check whether it reflects back unescaped in the response body. Neither uses `raw:`/`payloads:`/`flow:` — plain `path:` + `matchers`, well inside this project's supported schema subset.

| File | What it checks | Notes |
|---|---|---|
| `xss-uri-reflected.yaml` | A single injected path segment (`"><injectable>` / `'><injectable>`) reflected unescaped in an HTML (`content_type: text/html`) `200` response | `stop-at-first-match` across 2 candidate paths |
| `top-xss-params.yaml` | 38 common query parameter names (`q`, `search`, `id`, `token`, `email`, ...), each given a `<svg/onload=confirm(...)>` payload, checked for unescaped reflection | 3 requests (`max-request: 3`), parameters batched to stay under a reasonable URL length |

**Not live-verified against a real target in this session** — this checkout has no Docker/live DVWA or Juice Shop access. Confirmed only that both templates load cleanly via `nuclei.LoadDir` (see `tests/unit/nuclei_xss_samples_test.go`) and that every field they use (`part: content_type`, `part: header`, `negative: true`, multi-word `condition: or`) is already supported by this project's matcher engine. Live finding counts against DVWA/Juice Shop still need confirming in the user's native clone.

**DOM-based XSS** (via headless browser validation) is explicitly out of scope here — see doc11's Scope section for why it's deferred, not silently dropped.
