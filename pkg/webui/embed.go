package webui

import "embed"

// assets embeds the whole web UI — templates and vendored static JS/CSS —
// into the binary, per docs/12-implementation-plan-ph3.md's "Running it,
// release-to-release" design: no separate install step, no static-asset
// folder to keep in sync with the binary version. See static/VENDORED.md
// (not embedded — documentation only) for the pinned htmx/htmx-ext-sse
// versions.
//
//go:embed templates static
var assets embed.FS
