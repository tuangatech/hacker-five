# SQL injection sample templates

One real, unmodified upstream template from `http/vulnerabilities/generic/` — added 2026-08-28 as part of Phase 2 Step 3 ([docs/11-implementation-plan-ph2.md](../../../docs/11-implementation-plan-ph2.md)), same source category as [../xss/](../xss/)'s templates.

| File | What it checks | Notes |
|---|---|---|
| `error-based-sql-injection.yaml` | Appends a single `'` to the target path, checks the response for known DB error-message signatures across ~30 engines (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and many more) | Real gate is just 2 matchers (`matchers-condition: and`): NOT an Adminer-panel false-positive marker, AND at least one giant OR'd regex list matching a real DB error. The ~30 named per-engine regex entries later in the file are `extractors:`, not additional matchers — they identify *which* engine, they don't gate the finding (verified by reading the file's actual structure before including it — a naive read of "and across every named entry" would have wrongly assumed this template could never fire) |

**Boolean-based SQLi** (time-based blind confirmation) is deliberately not included — doc03's own "if time allows" wording, deferred per doc11's Step 3 scope.

Confirmed that the template loads cleanly via `nuclei.LoadDir` (see `tests/unit/nuclei_sqli_samples_test.go`).

**Live-verified against DVWA and Juice Shop (2026-08-28): 0 findings on both** — same root cause as [../xss/](../xss/)'s templates: this template probes a path-appended `'`, not DVWA's real `?id=` SQLi param. Separately proven the matcher itself is correct: a throwaway, uncommitted template pointed at the real param caught DVWA's live MariaDB error, and this template's own regex (`check the manual that (corresponds to|fits) your MariaDB server version`) matches that exact text. See [11-implementation-plan-ph2.md](../../../docs/11-implementation-plan-ph2.md) Step 5 and [20-setup-testing-targets.md](../../../docs/20-setup-testing-targets.md)'s DVWA section. **To test live yourself**: see [CLAUDE.md](../../../CLAUDE.md)'s "Verification (this environment)" section for how to reach the native WSL2 clone's already-running lab targets via `wsl.exe`, and doc20 for per-target bring-up steps.
