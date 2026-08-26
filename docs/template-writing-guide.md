# Template Writing Guide

> Part of the [HackerFive documentation set](../README.md).

HackerFive runs two independent template formats side by side whenever `--templates` is set (default `./templates/`) — both loaded once per scan, both additive to whichever `--detector` is selected:

- **Nuclei-compatible** (`pkg/template/nuclei`) — a defined, fail-loudly *subset* of the real upstream [`nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) schema. Point `--templates` at a synced copy (`make templates-sync`) or a hand-picked directory and existing upstream templates just work, as long as they stay inside the supported subset below.
- **Native YAML** (`pkg/template/native`) — HackerFive's own format, for the one thing Nuclei's format has no equivalent for: stateful, two-account IDOR checks. Shares the exact same matcher/extractor/DSL engine as the Nuclei-compatible path, so everything in "Matchers" and "Extractors" below applies to both formats identically.

Both are proper templates, not full documentation of every field — for real, working examples, read [templates/idor/](../templates/idor/) (native) and [templates/nuclei-samples/](../templates/nuclei-samples/) (Nuclei-compatible, real unmodified upstream files) rather than hand-copying anything from this doc.

---

## Nuclei-compatible format

### Supported

```yaml
id: example-template
info:
  name: Example check
  severity: info      # info | low | medium | high | critical
  tags: tech,example   # comma-separated

http:
  - method: GET
    path:
      - "{{BaseURL}}/some/path"   # every entry is tried, in order — not just path[0]
    stop-at-first-match: true     # stop trying further path entries once one matches
    headers:
      X-Custom: value
    matchers-condition: or        # "and" | "or" — default "or" (Nuclei's own default)
    matchers:
      - type: word                # word | regex | status | size | dsl
        part: body                 # body | header | all — default "body"
        words: ["admin panel"]
        condition: or               # and | or, within this matcher's own list — default "or"
        negative: false
    extractors:
      - type: regex                # regex | kval | json | dsl
        name: token
        part: body
        regex: ['"token":"([a-f0-9]+)"']
        group: 1                    # capture group; 0 = whole match
```

- **Matchers:** `word`, `regex`, `status`, `size`, `dsl`. No `binary` — not needed by any sampled template across the curated categories; added when a real template needs it, not speculatively.
- **Extractors:** `regex`, `kval` (response header key), `json` (dot-path, e.g. `data.user.id` — no array wildcards), `dsl`.
- **`part`** on both matchers and extractors: `body` (default), `header`, or `all`.
- Every `path`/`headers`/`body` string is rendered through the same `{{BaseURL}}`/`{{chainVar}}` substitution the native format uses (`pkg/scanner/vars`).

### Rejected at load time, not silently ignored

A template using any of these fails to load with a named error, rather than running incompletely or wrong:

| Block/field | Why |
|---|---|
| `raw:`, `payloads:` | A templated-request-plus-payload-substitution engine in its own right — genuinely unsupported, not a matcher-subset gap. See doc10 Future Enhancement #1. |
| `flow:` | Conditional/sequenced multi-request control flow. This project's executor runs every `http:` entry unconditionally and independently — for a `flow:` template that's not just incomplete, it's **actively wrong** (a live false positive against `apache-server-status-localhost.yaml` is what found this — see doc10 Step 2). |
| `matchers: [{internal: true}]` | Flow-control-only matcher — meaningless without `flow:` support, rejected for the same reason. |
| `code:`, `javascript:`, `headless:`, `file:` | Arbitrary code execution / local file access — out of scope for a template source this project doesn't hand-review (see [CLAUDE.md](../CLAUDE.md)). |
| `dns:`, `tcp:`, `ssl:`, `network:`, `websocket:`, `whois:` | Non-HTTP protocols — out of scope for v0.1.0 (see doc03's Week 6-7 note). |

**Not rejected, but not implemented either:** `req-condition` (cross-request field references like `request_1.status_code` in a later request's DSL matcher) has no matching field in this project's schema, so a template using it loads without error but won't behave as the upstream author intended — the DSL evaluator has no `request_N`-prefixed identifiers to resolve. If you hit this, treat the template as unsupported even though it loaded.

### Getting real templates

```bash
make templates-sync   # scripts/sync-nuclei-templates.sh — pinned commit, never HEAD (supply-chain safety, see doc10 Step 2)
```
Populates `.nuclei-templates-cache/http/{exposed-panels,misconfiguration,technologies}/` (gitignored). Use `--tags` to scope a scan to what's actually relevant to a target's tech stack instead of firing the whole synced corpus — see [21-scanning-real-targets.md](21-scanning-real-targets.md) §3 for the full workflow.

---

## Native format

For the one thing Nuclei's format doesn't do: baseline-mode, two-account IDOR checks, plus general request chaining.

```yaml
id: example-chain
info:
  name: Example chained check
  severity: medium
tags:
  - custom          # a template's first tag becomes its Finding.Type — "custom" if untagged
variables:
  username: testuser   # global scope, visible to every request in the chain
requests:
  - method: POST
    path: "{{BaseURL}}/login"
    body: '{"user":"{{username}}"}'
    extractors:
      - type: json
        name: auth_token
        json: "token"
    # no matchers on this request — that's deliberate, see "Chaining" below

  - method: GET
    path: "{{BaseURL}}/profile"
    condition: 'auth_token != ""'   # DSL expression against already-bound vars; false/unresolvable = skip this request, not scan-fatal
    headers:
      Authorization: "Bearer {{auth_token}}"
    matchers-condition: and         # default "and" here — opposite of Nuclei's "or" default, see below
    matchers:
      - type: status
        status: [200]
```

### Schema

`id`, `info` (`name`/`author`/`severity`/`description`), `tags` (`[]string`, unlike Nuclei's comma-separated string), `variables` (global scope), `requests` (`method`/`path`/`headers`/`body`/`extractors`/`matchers`/`matchers-condition`/`condition`).

### `matchers-condition` default differs from Nuclei's

Native format defaults to **`"and"`** when omitted — the opposite of the Nuclei-compatible parser's `"or"` default. This isn't arbitrary: the format's own canonical worked example (a login-then-probe chain) relies on AND semantics with no field saying so explicitly, so the default has to match that shape rather than Nuclei's convention.

### Chaining and the extraction/match decoupling

Extractors always run after a request fires, **regardless of whether its matchers evaluate true** — deliberately different from the Nuclei-compatible executor, which only extracts on a match. A request with zero `matchers` (like the login step above) never produces a `Finding` on its own, but its extractors still bind `{{auth_token}}` for the next request. Gating extraction on match status here would silently break the login-then-probe pattern this format exists for — a matchers-less request that only exists to extract a token would never get the chance to.

### `condition:` — the DSL, exactly

Both `condition:` (native) and `dsl:` matchers/extractors (both formats) share one small, hand-rolled evaluator (`pkg/template/dsl`) — deliberately not a general expression language:

- **Identifiers:** `status_code` (int), `body` (string), `header` (string — raw `"Name: value\n"`-per-line dump), plus any already-bound chain/global variable by name.
- **Functions:** `len(x)`, `contains(haystack, needle)`, `regex(pattern, subject)` — RE2 only, no catastrophic-backtracking risk.
- **Operators:** `==`, `!=`, `<`, `>` (comparisons), `&&`, `\|\|`, unary `!` (logical), parentheses for grouping. `!a && b` parses as `(!a) && b`, same as most C-family languages — confirmed against a real upstream template (`http-missing-security-headers.yaml`) that relies on exactly this precedence.

Anything outside this grammar is a parse/eval error, not a silent `false`.

### `idor`-tagged templates

A template tagged exactly `idor` routes through the real `idor.Detector` (the same baseline-mode, two-account engine `--detector idor` uses) instead of the generic chaining path — see [templates/idor/](../templates/idor/) for real examples. Constraints, deliberately narrow rather than general:

- Exactly **one** request.
- Its `path` must contain exactly one `{{RangeInt(min|max)}}` marker, e.g. `path: "{{BaseURL}}/api/report/{{RangeInt(1|50)}}"` — distinct from the plain `{{name}}` substitution used everywhere else (`RangeInt(...)`'s parentheses aren't parseable by that simpler substitution).
- No `matchers`/`extractors` on that request — `idor.Detector` supplies its own baseline-comparison logic; the template just supplies where to enumerate.
- Needs both `--auth-token`/`HACKERFIVE_AUTH_TOKEN` and `--other-auth-token`/`HACKERFIVE_OTHER_AUTH_TOKEN` to actually run (skips cleanly, no findings, if both are empty — it won't silently fall back to unauthenticated heuristic mode just because a template happened to load).

## See also
- [templates/idor/](../templates/idor/) — real native-format `idor`-tagged templates, live-verified against crAPI
- [templates/nuclei-samples/](../templates/nuclei-samples/) — real, unmodified upstream Nuclei templates, one per curated category
- [21-scanning-real-targets.md](21-scanning-real-targets.md) — `--tags` filtering workflow for scoping a real scan's template set
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — the design decisions and live findings behind everything in this doc (Steps 2-3)
- [CONTRIBUTING.md](../CONTRIBUTING.md) — the false-positive-rate bar template contributions are held to
