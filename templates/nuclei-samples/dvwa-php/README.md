# DVWA/PHP-targeted sample templates

Six real, unmodified upstream templates picked specifically because they had a real chance of matching or misparsing against a live DVWA instance — unlike [templates/nuclei-samples/](../)'s original four, which were guaranteed zero-finding against DVWA by construction (Angular/Django/Adminer detection against a plain PHP app). Picked after reconning DVWA directly (`curl -I http://localhost/`, checked `robots.txt`/`/docs/`/`config/config.inc.php`/`server-status`) rather than guessed blind.

Fetched 2026-08-24. Four of five are from the curated `http/technologies`/`http/misconfiguration` categories; `dir-listing.yaml` is from `http/miscellaneous`, outside the three categories the roadmap's sync script targets — kept anyway because it was the closest real match to the directory-listing behavior actually observed at `/docs/`.

**Live run against DVWA (`http://localhost`, 2026-08-24), via `pkg/template/nuclei.LoadDir` + `nuclei.New(client).Run`:**

| Template | Result | Why |
|---|---|---|
| `apache-detect.yaml` | ✅ 1 finding | DVWA's `Server: Apache/2.4.25 (Debian)` header matches |
| `php-detect.yaml` | ✅ 1 finding | Matches on the literal substring `PHP` inside the `PHPSESSID` cookie name — a real, if slightly incidental, match (Nuclei's own word matcher is a plain substring check, so real Nuclei would do the same) |
| `dir-listing.yaml` | ○ 0 findings, loaded fine | Only checks `{{BaseURL}}` (root); DVWA's actual directory listing is at `/docs/`, not root, so this specific unmodified template has nothing to match there |
| `apache-mod-negotiation-listing.yaml` | ✅ loaded fine (fixed 2026-08-26) | Uses `raw:`/`payloads:` (single inline-list payload key, plain `word`/`status` matchers) — now supported, see docs/10-implementation-plan-ph1b.md's `raw:`/`payloads:` note. **Not re-verified live against DVWA in this session** — this dev environment has no live Docker DVWA target (needs the user's separate native-Linux clone); confirmed only that it loads cleanly and that this exact request shape (raw: + single payload key) works end-to-end against a local test server (`tests/unit/nuclei_executor_test.go`'s `TestExecutorRun_RawSinglePayload`) |
| `http-missing-security-headers.yaml` | ✅ 1 finding, now named | Originally rejected — used unary `!expr` DSL negation and the `header` built-in variable, neither supported yet. Both were fixed (see docs/10-implementation-plan-ph1b.md Step 2). Re-run result: `"HTTP Missing Security Headers (strict-transport-security, content-security-policy, permissions-policy, x-frame-options, x-content-type-options, x-permitted-cross-domain-policies, referrer-policy, cross-origin-embedder-policy, cross-origin-opener-policy, cross-origin-resource-policy)"` — DVWA is missing 10 of the 11 headers this template checks |
| `missing-cookie-samesite-strict.yaml` | ✅ 1 finding | Added 2026-08-27 (Future Enhancement #3) — was already one of the "4 findings, all genuine" from Step 2's full synced-corpus run against DVWA (see docs/10-implementation-plan-ph1b.md), but hadn't been copied into this curated set until now. DVWA's session cookie lacks `SameSite=Strict` |

This run is real evidence the parser, matcher/extractor engine, and executor all work correctly end-to-end against a live target — four genuine, specific findings and one correctly-empty result from the original run. All six of this batch's templates now load cleanly — see `tests/unit/nuclei_dvwa_php_samples_test.go`.
