# DVWA/PHP-targeted sample templates

Five real, unmodified upstream templates picked specifically because they had a real chance of matching or misparsing against a live DVWA instance — unlike [templates/nuclei-samples/](../)'s original four, which were guaranteed zero-finding against DVWA by construction (Angular/Django/Adminer detection against a plain PHP app). Picked after reconning DVWA directly (`curl -I http://localhost/`, checked `robots.txt`/`/docs/`/`config/config.inc.php`/`server-status`) rather than guessed blind.

Fetched 2026-08-24. Four of five are from the curated `http/technologies`/`http/misconfiguration` categories; `dir-listing.yaml` is from `http/miscellaneous`, outside the three categories the roadmap's sync script targets — kept anyway because it was the closest real match to the directory-listing behavior actually observed at `/docs/`.

**Live run against DVWA (`http://localhost`, 2026-08-24), via `pkg/template/nuclei.LoadDir` + `nuclei.New(client).Run`:**

| Template | Result | Why |
|---|---|---|
| `apache-detect.yaml` | ✅ 1 finding | DVWA's `Server: Apache/2.4.25 (Debian)` header matches |
| `php-detect.yaml` | ✅ 1 finding | Matches on the literal substring `PHP` inside the `PHPSESSID` cookie name — a real, if slightly incidental, match (Nuclei's own word matcher is a plain substring check, so real Nuclei would do the same) |
| `dir-listing.yaml` | ○ 0 findings, loaded fine | Only checks `{{BaseURL}}` (root); DVWA's actual directory listing is at `/docs/`, not root, so this specific unmodified template has nothing to match there |
| `apache-mod-negotiation-listing.yaml` | ✗ rejected at load | Uses `raw:`/`payloads:` — exactly the request style Step 2 deliberately doesn't support (see docs/10-implementation-plan-ph1b.md Step 2's "Unsupported request styles") |
| `http-missing-security-headers.yaml` | ✅ 1 finding, now named | Originally rejected — used unary `!expr` DSL negation and the `header` built-in variable, neither supported yet. Both were fixed (see docs/10-implementation-plan-ph1b.md Step 2). Re-run result: `"HTTP Missing Security Headers (strict-transport-security, content-security-policy, permissions-policy, x-frame-options, x-content-type-options, x-permitted-cross-domain-policies, referrer-policy, cross-origin-embedder-policy, cross-origin-opener-policy, cross-origin-resource-policy)"` — DVWA is missing 10 of the 11 headers this template checks |

This run is real evidence the parser, matcher/extractor engine, and executor all work correctly end-to-end against a live target — three genuine, specific findings, one correctly-empty result, and one load-time rejection for a request style this project deliberately doesn't support yet.
