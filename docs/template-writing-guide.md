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
        part: body                 # body | header | all | content_type | response — default "body"
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
- **`part`** on both matchers and extractors: `body` (default), `header`, `all`, `content_type` (the `Content-Type` header value alone), or `response` (alias for `all` — header+body; real Nuclei's is the full raw response including the status line, but no sampled template checks that literal line, so this project doesn't synthesize one).
- Every `path`/`headers`/`body` string is rendered through the same `{{BaseURL}}`/`{{chainVar}}` substitution the native format uses (`pkg/scanner/vars`).

### `raw:`/`payloads:` (v1 scope)

```yaml
http:
  - raw:
      - |
        GET {{path}} HTTP/1.1
        Host: {{Hostname}}
        Accept: */*
    payloads:
      path:
        - /admin
        - /login
    matchers:
      - type: word
        words: ["Available variants"]
```

- **One payload key, an inline list only.** `payloads: {key: [v1, v2, ...]}` fires the request once per value, substituting `{{key}}` everywhere it appears (`raw:`, or a plain `path:`/`headers:`/`body:` request — both shapes are real; upstream's `phpmyadmin-panel.yaml` is the `path:` shape, `apache-mod-negotiation-listing.yaml` the `raw:` one). `stop-at-first-match: true` stops the payload loop early, same meaning as it already has for a multi-entry `path:` list.
- **Multiple payload keys are rejected at load time** — real Nuclei's `attack: sniper|pitchfork|clusterbomb` modes, which only matter with more than one key. Rare in practice and adds real combinatorial-request-count risk against a live target; not built in v1.
- **A payload value that's a bare string (a wordlist file path, e.g. `payloads: {path: helpers/wordlists/x.txt}`) is rejected at load time** — not synced, and reading a template-specified file path at scan time is its own security surface not taken on lightly. Real size, measured: 240 templates use this, 237 of them one uniform WordPress-plugin-version category (`technologies/wordpress/plugins/*.yaml`) that also needs `compare_versions()`/`concat()` DSL functions and same-request extractor-into-matcher binding — gaps beyond just this one, so it wouldn't actually unlock that category even if built. See doc10's `raw:`/`payloads:` note.
- **Multiple `raw:` entries in one block all fire, every time** — not a `path:`-style "try each until one matches" list. A shared matcher can reference each entry's result via indexed identifiers: `body_N`, `header_N` (string), `status_code_N` (int, real int — `status_code_1 != 404` type-checks), for `N = 1..len(raw)`. Real example: upstream's `open-proxy-internal.yaml` fires ~24 probes and checks `body_1`..`body_24` in one DSL expression. Non-DSL matcher types (`word`/`regex`/`status`/`size`) and extractors apply to the **last** fired entry only.
- **An absolute-URI request line (`GET http://192.168.0.1/ HTTP/1.1`) is rejected at load time** — real templates use this to test whether the target relays proxied requests to an arbitrary URI (open-proxy/SSRF-via-proxy checks, e.g. `open-proxy-internal.yaml`, the cloud-metadata-via-proxy templates). This project has no execution path that can honor it safely: `net/http`'s client dials whatever URL it's given, so sending it naively would connect the scanner directly to whatever host the (downloaded, template-authored) text names — a real out-of-scope-host risk per [CLAUDE.md](../CLAUDE.md), not just an unsupported feature.
- **A payload variable used *inside a matcher's `dsl:` string* isn't substituted** — only `raw:`/`path:`/`headers:`/`body:` are rendered through `{{}}` substitution. Real upstream's `cors-misconfig.yaml` does this (`contains(tolower(header), 'access-control-allow-origin: {{cors_origin}}')`) — it loads and runs without erroring, but that specific check will never fire (the literal, unsubstituted `{{cors_origin}}` text never appears in a real response) — a known, safe-direction (false-negative) gap, not a crash.

### `flow:` (v1 scope)

```yaml
flow: http(1) && http(2)   # or: http(1) || http(2), parens for grouping, e.g. http(1) && (http(2) || http(3))

http:
  - method: GET
    path: ["{{BaseURL}}/server-status"]
    matchers:
      - type: status
        status: [403, 404, 401]
        internal: true       # gates flow only — never itself produces a Finding
  - method: GET
    path: ["{{BaseURL}}/server-status"]
    headers:
      X-Forwarded-For: 127.0.0.1
    matchers:
      - type: word
        words: ["Apache Server Status"]
```

- **Supported: a `flow:` script that's a pure boolean composition of `http(N)` calls** — `&&`, `||`, and parens, standard precedence, N = 1-indexed position in the template's `http:` list. Covers 36 of 38 real sampled `flow:` templates (94.7%). Evaluation short-circuits exactly like `&&`/`||` in any C-like language: a request gated behind an earlier false `&&` or true `||` never fires — no request, no `Finding`, no extractor side effects from it.
- **`matchers: [{internal: true}]` is allowed only inside a `flow:` template** — an internal matcher's own result never produces a `Finding` (even when it evaluates true), it only decides whether the `http(N)` call it belongs to counts as true for the flow script. Outside a `flow:` template it's still rejected — nothing gates without `flow:`.
- **A request block with no `matchers:` at all is treated as trivially true** for flow purposes — its extractors still run, but (having nothing to match) it can never itself produce a `Finding`. This is what makes a pure "detect, then extract a version from a second request" template (e.g. upstream's `umami-panel.yaml`) work.
- **Not supported: `javascript()` flow scripts, loops, or variable assignment** — rejected at load time. In practice a `javascript()`-based `flow:` script pairs with a real top-level `javascript:` protocol block (arbitrary code execution), which this project has never supported (see the disallowed-blocks table below) — the two sampled real templates using it are rejected there, not by the `flow:` parser itself.
- **A named extractor's result IS usable as a DSL identifier in a later request's matcher/extractor** — see "Extractor -> DSL binding" below; this is what unlocks a `flow:` template like `google-iap-detect.yaml` whose second request references the first request's `email`. What's still unsupported is a handful of *other*, unrelated missing built-in identifiers a few real `flow:` templates happen to also reference (`server`, `all_headers`, `Input`) — see doc10's `flow:` note for the exact list; these stay rejected until those identifiers are implemented, unrelated to extractor binding.

### Extractor -> DSL binding (v1 scope)

```yaml
http:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: dsl
        dsl:
          - compare_versions(version, '<=2.2.34')
    extractors:
      - type: regex
        part: header
        name: version
        group: 1
        regex:
          - 'Server: Apache/([0-9.]+)'
```

- **A named extractor's result is a DSL identifier, resolvable in a matcher/extractor from the same request or any later one** — distinct from `{{}}` string substitution (already worked everywhere via `vars.Render`/chain variables); this is specifically about referencing an extracted value as a bare identifier inside a `dsl:` expression, as in the example above (`version`, extracted by that same request, referenced by that same request's matcher). One mechanism covers both the same-request case above and the cross-request case (an earlier request's extractor referenced by a later request's `dsl:`, e.g. via `flow:`).
- **Two DSL functions exist mainly to make this useful:** `compare_versions(version, constraint...)` (see the `condition:`/DSL reference below) and `base64_decode(s)`.
- **Not supported:** a *forward* reference (a matcher in an earlier request referencing an extractor `Name` that's only declared in a *later* request) — extraction only ever flows forward, matching real Nuclei and every real sampled template. Payload-bound variables (`payloads:`'s per-iteration value) aren't merged into this DSL context either — a separate, unmeasured gap, not needed by any real template found so far.

### Rejected at load time, not silently ignored

A template using any of these fails to load with a named error, rather than running incompletely or wrong:

| Block/field | Why |
|---|---|
| `code:`, `javascript:`, `headless:`, `file:` | Arbitrary code execution / local file access — out of scope for a template source this project doesn't hand-review (see [CLAUDE.md](../CLAUDE.md)). |
| `dns:`, `tcp:`, `ssl:`, `network:`, `websocket:`, `whois:` | Non-HTTP protocols — out of scope for v0.1.0 (see doc03's Week 6-7 note). |

**`req-condition`-style cross-request field references** (real Nuclei's `request_1.status_code`-style dotted identifiers in a later request's DSL matcher) have no matching identifiers in this project's DSL evaluator — a template using that exact dotted syntax fails to load ("unknown identifier"), it doesn't silently misbehave. What *is* supported is the more common real shape: a *named extractor's* result referenced as a bare identifier (not the dotted `request_N.field` form) — see "Extractor -> DSL binding" above.

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

- **Identifiers:** `status_code` (int), `body` (string), `header` (string — raw `"Name: value\n"`-per-line dump), `content_type` (string — the `Content-Type` header value alone), `response` (string — alias for `header+body`, see the `part:` note above), plus any already-bound chain/global variable by name, plus (Nuclei-compatible format) any named extractor's result — see "Extractor -> DSL binding" above.
- **Functions:**
  - `len(x)`, `contains(haystack, needle)`, `contains_any(haystack, needle1, needle2, ...)`, `contains_all(haystack, needle1, needle2, ...)`, `regex(pattern, subject)` — RE2 only, no catastrophic-backtracking risk.
  - `to_lower(s)` / `tolower(s)` (both spellings, same function — both appear in real upstream templates), `trim(s, cutset)` (like Go's `strings.Trim`, not whitespace-only).
  - `md5(s)`, `sha1(s)` — hex-encoded digest, for templates that fingerprint by a known content hash.
  - `base64_py(s)`, `mmh3(s)` — Shodan/ZoomEye-style favicon-hash fingerprinting, almost always used together as `mmh3(base64_py(body))` compared against a quoted (possibly negative) decimal string. `base64_py` reproduces Python's `base64.encodebytes` line-wrapping (a newline every 76 characters), not Go's unbroken `base64.StdEncoding` output — the wrapping changes the hashed bytes, not just formatting. `mmh3` is a hand-rolled MurmurHash3 x86-32 (seed 0) returning its signed-int32 result as a decimal string (so it compares directly against a quoted literal like `"-633108100"`), verified against MurmurHash3's own canonical published test vectors, not reimplemented from memory.
  - `compare_versions(version, constraint, ...)` — dot-separated numeric version comparison, e.g. `compare_versions(version, "<=2.2.34")` or a range via two constraints (`">= 12.0.0"`, `"< 14.0.0"`, ANDed). Operators: `<`, `<=`, `>`, `>=`, `==`/`=`, `!=`. A missing trailing segment is treated as `0` (`"2.2"` vs `"2.2.34"` compares as `"2.2.0"` vs `"2.2.34"`); a non-numeric segment is a DSL error, not a silent `false`.
  - `base64_decode(s)` — standard base64 decode; malformed input is a DSL error.
- **Operators:** `==`, `!=`, `<`, `>` (comparisons), `&&`, `\|\|`, unary `!` (logical), parentheses for grouping. `!a && b` parses as `(!a) && b`, same as most C-family languages — confirmed against a real upstream template (`http-missing-security-headers.yaml`) that relies on exactly this precedence.
- **String literals** support backslash-escaped quotes (`"name=\"value\""`) and `\\`, matching how real templates embed a quote inside a DSL string argument.

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
