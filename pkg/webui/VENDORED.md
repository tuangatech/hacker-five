# Vendored static assets

Pinned, not auto-updated — same posture as `scripts/sync-nuclei-templates.sh`'s pinned commit. Bump deliberately, re-verify the source before replacing.

| File | Package | Version | Verified via | Verified |
|---|---|---|---|---|
| `htmx.min.js` | `htmx.org` | 2.0.10 | `registry.npmjs.org/htmx.org/latest`, fetched from `unpkg.com/htmx.org@2.0.10/dist/htmx.min.js` | 2026-08-28 |
| `htmx-ext-sse.js` | `htmx-ext-sse` | 2.2.4 | `registry.npmjs.org/htmx-ext-sse/latest`, fetched from `unpkg.com/htmx-ext-sse@2.2.4/sse.js` | 2026-08-28 |

Both files are byte-identical to their published npm package contents — not hand-edited. The binary must work fully offline, so these are embedded via `pkg/webui/embed.go`'s `go:embed`, never loaded from a CDN at runtime.
