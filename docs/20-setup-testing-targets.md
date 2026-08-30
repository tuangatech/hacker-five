# Setting Up Test Targets

> Part of the [HackerFive documentation set](../README.md).

HackerFive is validated against local, deliberately vulnerable targets — never live/external hosts (see [05-hackerone-and-legal.md](05-hackerone-and-legal.md)). Each detector needs a different kind of target, so this doc is split by target rather than by detector, and is meant to grow as more targets are added.

Every command below is identical on macOS and Windows (WSL2) — Docker Desktop abstracts the difference, and these targets publish multi-arch images. No platform split needed here; see [04-environment-and-testing.md](04-environment-and-testing.md) for the underlying Mac/Windows dev-environment setup itself (Docker Desktop, WSL2, etc.).

**On Windows, run every command on this page — `docker`/`docker compose` included — inside your WSL2 Ubuntu shell, not PowerShell/cmd.** Docker Desktop's WSL2 integration technically exposes `docker` to both, but this doc's later steps (`crapi_setup.sh`'s `curl`/`jq`, the `./hackerfive` binary itself) only work in WSL2, so keeping Docker commands in the same shell avoids switching terminals mid-setup. Published ports (`localhost:8888`, `localhost:80`, etc.) are reachable from a browser on the Windows side either way — Docker Desktop forwards them regardless of which shell started the container.

| Target | Detector it supports | Why |
|---|---|---|
| **crAPI** | `idor` | Stateful, two-account check — needs a target with a scriptable signup/login flow and a known cross-account-access bug |
| **DVWA** | `misconfig` | Stateless, single-target check — no accounts needed, just a target with exposed paths/headers/methods to probe |
| **Juice Shop** | `misconfig`; Nuclei-compatible templates | Stateless, single-target — no accounts needed. Also the only target here with a real *target-specific* upstream Nuclei template (`owasp-juice-shop-detect`), confirmed live; XSS/auth-bypass-specific detectors are still Phase 2, not yet implemented |
| **vAPI** | `idor`, `misconfig`; Nuclei-compatible templates | Has a real BOLA (see its own section below), reachable via `idor.Detector`'s configurable auth-header scheme (`--auth-header-name`/`--auth-header-format`) |
| WebGoat | *(none yet)* | Reserved for Phase 2 — per [03-development-roadmap.md](03-development-roadmap.md), its Week 13-14 (XSS) and Week 15-16 (SQL injection) deliverables don't name a specific test target the way Week 11-12's API-auth work names vAPI/crAPI; WebGoat's general multi-vulnerability lesson set (unlike the API-specific targets above) is the natural fit for those. Not referenced by any implemented detector yet |
| **AIGoat** | prompt-injection templates | Deliberately-vulnerable LLM chat app (OWASP LLM Top 10) with real, self-hosted "System Prompt Leakage" and "Data Leakage" labs — see [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 1 |

Prerequisites for any target: Docker + Docker Compose (`docker compose`, no hyphen), per [04-environment-and-testing.md](04-environment-and-testing.md).

**Where to clone target repos:** targets like crAPI are separate, unrelated git repos — never clone them *inside* the `hacker-five` checkout (their own `.git` would end up nested in yours). Use a sibling directory instead, e.g. `~/targets/`, next to wherever `hacker-five` itself lives (`~/projects/hacker-five` per [04-environment-and-testing.md](04-environment-and-testing.md)):
```bash
mkdir -p ~/targets && cd ~/targets
```
Every `git clone`/`docker pull` below assumes you're inside that directory, not inside `hacker-five`.

---

## crAPI (for `--detector idor`)

[OWASP crAPI](https://github.com/OWASP/crAPI) ("completely ridiculous API") ships a deliberately vulnerable "vehicle location" / user-dashboard endpoint with a real cross-account IDOR, and a real signup/login flow — exactly what baseline-mode IDOR needs two account tokens for.

### Bring it up

```bash
wsl                     # Windows only — drops into the Ubuntu shell; skip on macOS
cd ~/targets
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy/docker && docker compose down -v   # wipe any stale data from a prior run
docker compose up -d
```
- **App:** `http://localhost:8888`
- **MailHog** (catches all outbound email, incl. any OTP/verification mail): `http://localhost:8025` — optional; plain signup/login doesn't require checking it.
- Requires `docker compose` v1.27.0+ (per [OWASP's official setup guide](https://owasp.org/crAPI/docs/setup.html)).

An equivalent official alternative (no git history, current release archive) if you'd rather not clone the full repo:
```bash
curl -L -o crapi.zip https://github.com/OWASP/crAPI/archive/refs/heads/main.zip
unzip crapi.zip && cd crAPI-main/deploy/docker
docker compose pull
docker compose -f docker-compose.yml --compatibility up -d
```

### Prepare: two accounts, one submitted report

crAPI has **no pre-seeded accounts** — they only exist via its signup flow (`POST /identity/api/auth/signup` → `POST /identity/api/auth/login`). HackerFive's baseline-mode IDOR needs **two unrelated accounts**, so [tests/integration/scripts/crapi_setup.sh](../tests/integration/scripts/crapi_setup.sh) automates both signups and exports the resulting tokens.

**Run this in your WSL2 terminal, from inside the `hacker-five` checkout** (`~/projects/hacker-five`, not `~/targets/crAPI/...`). Requires `curl` and `jq` — `curl` is preinstalled on Ubuntu, but `jq` usually isn't — the script's path below is relative to `hacker-five`, not to crAPI:
```bash
cd ~/projects/hacker-five
export CRAPI_BASE_URL=http://localhost:8888   # optional, this is the default
sudo apt update && sudo apt install -y jq
source tests/integration/scripts/crapi_setup.sh
# → exports CRAPI_OWNER_TOKEN, CRAPI_OTHER_TOKEN, CRAPI_OWNER_EMAIL, CRAPI_OTHER_EMAIL, CRAPI_PASSWORD
```

Must be `source`d (not executed, and from bash — not a Windows PowerShell/cmd window) so the exports land in your current shell. If it prints an error about a failed signup/login instead of the success message, crAPI's `identity` service is most likely still starting up (its DB migrations can take a minute or two after `docker compose up -d` returns) — check `docker compose ps` shows `crapi-identity` healthy, then re-run.

The tokens themselves are session JWTs, so re-run the script whenever you need fresh ones (e.g. after your shell closes, or after a `docker compose down -v` wipes account data) — safe to run repeatedly against the same crAPI instance, since it logs into the same two fixed accounts (`hackerfive-owner@example.com` / `hackerfive-other@example.com`, same password of `Passw0rd!`) rather than erroring if they already exist. Nothing confidential about these — throwaway accounts on your own local container — so they're fixed and safe to hardcode/reuse rather than regenerated per run. Also exported as `$CRAPI_OWNER_EMAIL`/`$CRAPI_OTHER_EMAIL`/`$CRAPI_PASSWORD` and printed by the script itself, in case you don't want to re-type them below.

**Now create one mechanic report** — the scan needs at least one to exist (`report_id` is a real numeric primary key in crAPI's `workshop` service, and a freshly-provisioned instance has zero of them, so a scan run before this step correctly finds nothing). There's no API shortcut for this step — it goes through crAPI's own app flow, same as how a real attacker would first find something worth targeting:
1. Open `http://localhost:8888` in a browser and log in as the owner account: `hackerfive-owner@example.com` / `Passw0rd!`.
2. Open [MailHog](http://localhost:8025) — crAPI already emailed this account a real, server-generated VIN + pincode (crAPI won't accept one you make up yourself; every vehicle row is pre-created server-side). Find that email and note its VIN and Pincode.
3. Back in `http://localhost:8888`, click **"Add a vehicle"** on the homepage and enter the VIN and Pincode exactly as emailed.
4. This lands on the Vehicle Details page for that vehicle, which has **"Vehicle Service History"** and **"Contact Mechanic"** buttons — use **"Contact Mechanic"** once to submit a report.

After submitting, the browser lands on a URL like `http://localhost:8888/service-report?id=6` — that number is the report's numeric `id`, and it's what the scan below will find `CRAPI_OTHER_TOKEN` can also read — the actual BOLA in [GetReportView](https://github.com/OWASP/crAPI/blob/develop/services/workshop/crapi/mechanic/views.py) (`services/workshop/crapi/mechanic/views.py`): it only requires *any* valid JWT, never checking that the report belongs to the requesting account.

### What HackerFive needs

Same shell as above (so `$CRAPI_OWNER_TOKEN`/`$CRAPI_OTHER_TOKEN` are still set), still inside `~/projects/hacker-five` (`./hackerfive` is the binary built there, e.g. via `go build -o hackerfive ./cmd/hackerfive` — see [README.md](../README.md)'s Quick Start):
```bash
export HACKERFIVE_AUTH_TOKEN="$CRAPI_OWNER_TOKEN"
export HACKERFIVE_OTHER_AUTH_TOKEN="$CRAPI_OTHER_TOKEN"

./hackerfive scan -t http://localhost:8888 \
  --detector idor \
  --endpoint '/workshop/api/mechanic/mechanic_report?report_id={{id}}'
```
Omitting `--other-auth-token`/`HACKERFIVE_OTHER_AUTH_TOKEN` falls back to heuristic mode (low confidence, single account) instead of failing. Requires the mechanic report from the previous step to already exist — without one, this correctly finds nothing.

### Auth bypass exists too — now testable via `--detector authbypass`

Same shell as above ($CRAPI_OWNER_TOKEN/$CRAPI_OTHER_TOKEN still set):
```bash
cd ~/projects/hacker-five
./hackerfive scan -t http://localhost:8888 --detector authbypass \
  --protected-paths '/identity/api/v2/user/dashboard,/identity/api/v2/vehicle/vehicles'
```
Real, live-verified result (2026-08-28): **2 critical findings**, both `alg: none` JWT bypass — `/identity/api/v2/user/dashboard` and `/identity/api/v2/vehicle/vehicles` both accept a token whose header was rewritten to `{"alg":"none"}` with the signature segment dropped, returning the real, personalized response (name/email/vehicle list) rather than rejecting it. Independently confirmed outside the tool with a hand-built tampered token via `curl` — not just the detector's own claim — and cross-checked that a genuinely garbage/malformed token is correctly rejected (`404`), so this isn't "the endpoint accepts anything." The signature-*stripped* variant (header left alone, signature bytes just removed) is correctly rejected — only the `alg: none` header rewrite bypasses verification, a common gap in JWT libraries that don't pin the accepted algorithm.

**Caveat, working as designed — not a bug:** `checkJWTWeakSecret` found nothing (crAPI's real secret isn't in the fixed dictionary — expected, this check is intentionally dictionary-only, not brute force, see [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) Step 1). `checkRateLimitSignal`/`checkBrokenSession` also found nothing against crAPI with the command above, but not because crAPI is well-behaved — `authbypass.LoginPaths`/`LogoutPaths` (`/login`, `/api/login`, `/auth/login`, `/logout`, `/api/logout`, `/auth/logout`) don't match crAPI's real path (`/identity/api/auth/login`; crAPI has no server-side logout at all, being stateless-JWT), confirmed via a direct `curl` sweep of all six candidate paths (`404` on every one).

**Fixed and live-verified**: `--login-paths`/`--logout-paths` override these fixed defaults —
```bash
./hackerfive scan -t http://localhost:8888 --detector authbypass \
  --protected-paths '/identity/api/v2/user/dashboard' \
  --login-paths '/identity/api/auth/login'
```
Real result (2026-08-28): `checkRateLimitSignal` now correctly reaches `/identity/api/auth/login` (`authbypass-no-rate-limit-identity-api-auth-login`) instead of a nonexistent `/login`. **Also fixed**: the check now tries both a form-encoded and a JSON body per candidate path (crAPI's real login is JSON-only and returned `415 Unsupported Media Type` for the old fixed form-encoded probe) — the real response is now a genuine `400` from crAPI's own schema validation, not a content-type rejection. Residual, accepted gap: the probe's field name is the generic `username`, not crAPI's real `email`, so it's testing throttle-by-request-volume against a validation-error path rather than a literal wrong-password rejection — matching every target's exact JSON schema is out of scope for a generic bounded probe (see [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) Step 5).

**Breadth recon beyond the two originally-tried paths (2026-08-28)**: crAPI ships a real OpenAPI spec (`~/targets/crAPI/openapi-spec/crapi-openapi-spec.json`) listing every route across its `identity`/`community`/`workshop` microservices — a much better source than guessing paths. Pointing `--protected-paths` at 8 more bearer-protected GET endpoints from that spec:
```bash
./hackerfive scan -t http://localhost:8888 --detector authbypass \
  --auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN" \
  --protected-paths '/identity/api/v2/user/videos/convert_video,/community/api/v2/community/posts/recent,/workshop/api/shop/products,/workshop/api/shop/orders/all,/workshop/api/management/users/all,/workshop/api/mechanic/,/workshop/api/mechanic/service_requests,/workshop/api/shop/return_qr_code'
```
Real, live-verified result (2026-08-28): **16 findings**, and the `alg:none` bypass turns out to be systemic, not isolated to `identity` — **7 of the 8 new paths** (all but `videos/convert_video`, which correctly rejected the tampered token — a real negative control, not every endpoint is vulnerable) accept the same `alg:none`-rewritten token across all three separate microservices (`identity`, `community`, `workshop`), meaning whatever JWT library each service uses shares the same unpinned-algorithm gap. Independently re-confirmed outside the tool on two of the seven (`/community/api/v2/community/posts/recent`, `/workshop/api/shop/products`) via hand-built `curl` requests: no-header → `401`, valid token → `200`, hand-forged `alg:none` token → `200` on both — not just the detector's own claim. `/workshop/api/shop/return_qr_code` additionally has no auth requirement at all (`checkMissingAuth`, high) and accepts the signature-*stripped* variant too, not just `alg:none`.

The run also flagged 7 `token-reuse` findings (medium, "needs manual triage" — the check's own hedge for a plausibly-shared/non-personalized endpoint). Manually triaged two: `/workshop/api/shop/orders/all` returned `{"orders":[]}` for both accounts — inconclusive, both throwaway accounts simply have no orders, not proof either way. `/workshop/api/management/users/all` is the real one: a plain `hackerfive-owner` account (never granted any admin role) gets a full user-table dump — every account's email, phone number, and credit balance, `admin@example.com` included — from an endpoint whose path implies it should be admin-only. That's a standalone broken-function-level-authorization finding in its own right, not just "two tokens match."

### Teardown / reset

```bash
cd ~/targets/crAPI/deploy/docker && docker compose down -v   # -v also drops the account data crapi_setup.sh created
```

---

## DVWA (for `--detector misconfig`)

[Damn Vulnerable Web Application](https://github.com/digininja/DVWA) is a stateless PHP/MySQL app — no account tokens needed, since misconfig's checks (exposed paths, directory listing, missing headers, disallowed methods, CORS, verbose errors, default creds) don't require an authenticated session to probe.

### Bring it up

```bash
wsl                     # Windows only — drops into the Ubuntu shell; skip on macOS
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa
```
- **Run from anywhere** — unlike crAPI, DVWA isn't cloned from a repo; it's a single public image with no compose file and no local state, so these two commands don't depend on a working directory.
- **App:** `http://localhost`
- `-d` runs it detached (no attached terminal needed for scanning); the [Docker Hub image page](https://hub.docker.com/r/vulnerables/web-dvwa) documents an equivalent `-it` foreground form if you want to watch container logs directly.

### Required one-time step: initialize the database

DVWA serves a **setup/login page only** until its database is created — open `http://localhost/setup.php` in a browser once and click **"Create / Reset Database."** Skipping this step means most misconfig checks (and everything else) will see an empty setup shell, not the actual app, so do this before running a scan.

- **Default web UI login:** `admin` / `password` — only needed for a human to browse DVWA and confirm setup; HackerFive's `misconfig` detector doesn't need it (no `--auth-token` required).
- **Security/difficulty level** (DVWA Security tab): controls how many intentional weaknesses are exposed. Set it to **Low** for the broadest signal — image defaults have been reported inconsistently across tags/rebuilds, so don't assume it's already Low; check after first login.

### Caveat: HackerFive's built-in default-creds check won't fire against DVWA

Phase 1b Step 1's fixed `DefaultCreds` rule table (see [pkg/detectors/misconfig/rules.go](../pkg/detectors/misconfig/rules.go)) POSTs `username`/`password` form fields to a plain `/login` path. DVWA's real login lives at `/login.php` and requires a CSRF `user_token` hidden field submitted alongside the credentials — a request without it is rejected regardless of whether `admin`/`password` is correct. So expect **zero** default-creds findings against DVWA; that's the fixed-path/fixed-form checker working as designed, not a bug. The other five rule categories (exposed paths, missing headers, disallowed methods, CORS, verbose errors) apply normally and don't depend on DVWA's login form.

### What HackerFive needs

From your WSL2 terminal, inside `~/projects/hacker-five` (where `./hackerfive` was built):
```bash
cd ~/projects/hacker-five
./hackerfive scan -t http://localhost --detector misconfig
```
No tokens, no `--endpoint` — misconfig runs its full built-in rule table against the target root and its fixed path list directly. As of Future Enhancement #4 ([10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md)), this now includes a directory-listing check at `/docs/` (and other common subpaths) — DVWA's own `dir-listing.yaml` sample template only ever checked root, missing DVWA's real directory listing there. Live-verified (2026-08-28): **12 findings** — the same 11 as Step 4 plus 1 new `misconfig-dir-listing-docs`. `misconfig-comment-leak` (Phase 2 Step 4) did **not** fire — DVWA's root page has HTML comments (`<!--<div id="header">-->`, a commented-out `<img>`), but none match `CommentLeakPatterns`' TODO/FIXME/DEBUG/`<script`/credential-word anchors, correctly not flagged.

### XSS/SQLi templates (`--tags xss,sqli`) — real bugs exist, but unreachable by the shipped generic templates

```bash
./hackerfive scan -t http://localhost --detector misconfig --tags xss,sqli
```
Live-verified (2026-08-28): **0 findings**, but not because DVWA lacks these bugs — its `/vulnerabilities/xss_r/?name=` and `/vulnerabilities/sqli/?id=` pages are real, confirmed live via direct `curl` with a manually-obtained session cookie (`security=low`): the SQLi page returns a genuine MariaDB syntax error for a `'` payload, and the XSS page reflects `"><injectable>` completely unescaped. Manually confirmed HackerFive's own matcher/DSL engine correctly flags both (via a throwaway, uncommitted template using the same session cookie) — **the detection logic is proven sound**. Two structural gaps block automated coverage of DVWA specifically, both true of Juice Shop too (see below) and tracked as follow-up work in [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) Step 5:
1. ~~`xss-uri-reflected.yaml`/`error-based-sql-injection.yaml` (the curated upstream generic templates) probe path-appended payloads (`{{BaseURL}}/'`), not named query params (`?id=`, `?name=`) — a different technique than DVWA's actual bug shape.~~ **Fixed (2026-08-28)**: `templates/nuclei-samples/dvwa-php/{xss-reflected-dvwa,sqli-error-dvwa}.yaml` target the real params directly — see below.
2. ~~Even a template written against the right params can't reach DVWA's vulnerable pages at all: they're gated behind a `PHPSESSID` login session, and nuclei-format templates have no mechanism to carry any CLI-supplied credential/cookie into a request.~~ **Fixed (2026-08-28)**: `--header 'Name: Value'` (repeatable) now applies a static header to every template-driven request.

**Both gaps closed — real DVWA-specific templates, live-verified:**
```bash
./hackerfive scan -t http://localhost --detector misconfig --tags xss,sqli \
  --header "Cookie: PHPSESSID=<real session id>; security=low"
```
Real result (2026-08-28): **1 XSS finding + 1 SQLi finding**, via the two first-party templates in `templates/nuclei-samples/dvwa-php/` (see that directory's README for detail). Neither doc03's ≥20 XSS nor ≥10 SQLi target is met yet — what's proven now is the technique works end-to-end against a real target; reaching the full metric would mean covering more of DVWA's pages/params, not a new mechanism.

### Teardown / reset

```bash
docker ps --filter ancestor=vulnerables/web-dvwa -q | xargs -r docker stop
```
(the container was started with `--rm`-equivalent cleanup only if you added `--rm`; otherwise `docker rm` it explicitly if you want the image's stopped container gone too.)

---

## Juice Shop (for `--detector misconfig`, and Nuclei-compatible templates)

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) is a single-container Angular/Express app — like DVWA, no accounts or setup step needed, so both `misconfig` and Step 2's Nuclei-compatible template engine can point at it directly. Two things actually run against it today, verified live (2026-08-25):

1. **`misconfig` detector** (CLI-wired) — real findings, but read the caveat below before trusting all of them.
2. **Nuclei-compatible template engine** (Step 2, `pkg/template/nuclei`) — not yet reachable from `hackerfive scan` (`--templates` CLI wiring is [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) Step 3), so this only runs via the Go integration test below for now.

### Bring it up

```bash
wsl                     # Windows only — drops into the Ubuntu shell; skip on macOS
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```
- **App:** `http://localhost:3000`
- No database-init step needed (unlike DVWA) — ready to scan as soon as the container responds.

### Caveat: one of `misconfig`'s findings needs a grain of salt against SPA-style targets like this one

A live run (`./hackerfive scan -t http://localhost:3000 --detector misconfig`) returned 6 findings: 2 missing-header, 3 disallowed-method, 1 exposed-path. Confirmed by direct `curl` that not all of them mean what they look like:
- **`/well-known/security.txt` is real but not a misconfiguration.** Juice Shop intentionally serves one (a standard, deliberate disclosure file, not a leak) — correctly identified content, but "found a `security.txt`" isn't itself a finding worth acting on; its `low` severity already reflects that, but don't read it as a bug.
- **PUT/DELETE/PATCH-accepted findings are real signal, same root cause.** The server does return 200 for all three at root — but that's the same SPA catch-all responding to any verb, not a state-changing endpoint that actually accepts those methods.

**Previously also false-positived on `/.htpasswd`, now fixed:** its rule's keyword used to be a bare `":"` — Juice Shop's Angular frontend returns its `index.html` shell (HTTP 200) for any unmatched path, Express's SPA catch-all rather than a real per-route handler, and that shell's own markup trivially contains a colon somewhere. Fixed in `pkg/detectors/misconfig/rules.go` by keying on real htpasswd hash-format markers (`$apr1$`, `{SHA}`, `$2y$`/`$2a$`/`$2b$`) instead — confirmed live, `.htpasswd` no longer appears in the 6 findings above.

### What HackerFive needs

```bash
cd ~/projects/hacker-five
./hackerfive scan -t http://localhost:3000 --detector misconfig
```
No tokens, no `--endpoint`. `misconfig-comment-leak` (Phase 2 Step 4) live-verified (2026-08-28): **0 findings** — Juice Shop's root page has no HTML comments matching `CommentLeakPatterns` (the check only fetches root, no principled path list for "where a leftover comment might be").

### XSS/SQLi templates (`--tags xss,sqli`)

```bash
./hackerfive scan -t http://localhost:3000 --detector misconfig --tags xss,sqli
```
Live-verified (2026-08-28): **0 findings**, for different reasons than DVWA's 0 (see DVWA section above for the full explanation of the shared root cause — path-appended vs. param-based payloads). Juice Shop specifically: its most XSS-relevant surface (`/rest/products/search?q=`) returns `Content-Type: application/json`, confirmed via direct `curl` — `xss-uri-reflected.yaml`'s `part: content_type: text/html` matcher deliberately excludes JSON responses (to avoid false-positiving on API payload echoes), so this is the matcher working as designed, not a miss. Juice Shop's actual XSS challenges are predominantly DOM-based (client-side), explicitly deferred pending Chromedp per [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md)'s Scope section.

For the Nuclei-compatible engine (not CLI-wired yet, so via the Go integration test instead):
```bash
export JUICESHOP_BASE_URL=http://localhost:3000   # optional if already synced
make templates-sync   # if .nuclei-templates-cache/ isn't already populated — see 10-implementation-plan-ph1b.md Step 2
go test -tags=integration ./tests/integration/... -run TestNucleiTemplates -v
```
Real result (2026-08-25, 2,473 templates loaded): 2 genuine findings — `http-missing-security-headers` (8 of 11 checked headers missing) and `owasp-juice-shop-detect`, a real upstream template that fingerprints Juice Shop specifically by its page title. Notably, `angular-detect.yaml` (one of the permanent samples in `templates/nuclei-samples/`) does **not** fire here despite Juice Shop being an Angular app — confirmed via direct `curl` that its raw HTML has no `ng-version="..."` attribute at all (this build hydrates entirely client-side, no server-rendered marker), so a plain-HTTP template genuinely has nothing to match — not an engine bug.

### Teardown / reset

```bash
docker ps --filter ancestor=bkimminich/juice-shop -q | xargs -r docker stop
```

---

## vAPI (for `--detector misconfig`, and Nuclei-compatible templates)

[vAPI](https://github.com/roottusk/vapi) ("Vulnerable Adversely Programmed Interface") is a PHP/Laravel + MySQL app mimicking OWASP API Top 10 scenarios. Its `docker-compose.yml` already bakes in DB credentials — no manual `.env` editing needed for basic bring-up, despite what the project's general docs suggest for a non-Docker install.

### Bring it up

```bash
wsl                     # Windows only — drops into the Ubuntu shell; skip on macOS
mkdir -p ~/targets && cd ~/targets
git clone https://github.com/roottusk/vapi.git
cd vapi && docker-compose up -d
```
- **App:** `http://localhost:8000`
- **phpMyAdmin** (exposed by vAPI's own compose file — a real, separate misconfiguration if scanned on its own): `http://localhost:8001`
- No database-init step needed — the `db` container's init scripts run automatically on first start.

### Real BOLA exists here too — now testable via `--detector idor`

Reading vAPI's source confirms a real bug structurally identical to crAPI's: `API1UsersController::show($id)` (`routes/api.php`: `GET api1/user/{id}`) calls `API1Users::find($id)` with no check that `$id` belongs to the authenticated user (`API5UsersController::show` is the *fixed* counterpart — it adds `->where('id', $id)`, worth comparing). Every vAPI endpoint authenticates via a custom `Authorization-Token: base64(username:password)` header, not `Authorization: Bearer <token>` — `idor.Detector` now supports this via a configurable auth-header scheme (Future Enhancement #6, see [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md)).

**Getting two account tokens:** unlike crAPI's `crapi_setup.sh`, there's no scripted signup for vAPI — sign up two real, unrelated accounts via vAPI's web UI (`http://localhost:8000`), then base64-encode each `username:password` pair yourself:
```bash
export VAPI_OWNER_TOKEN=$(printf '%s' 'owner@example.com:password1' | base64)
export VAPI_OTHER_TOKEN=$(printf '%s' 'other@example.com:password2' | base64)
```

```bash
cd ~/projects/hacker-five
./hackerfive scan -t http://localhost:8000/vapi --detector idor \
  --endpoint '/api1/user/{{id}}' \
  --auth-header-name 'Authorization-Token' --auth-header-format '{token}' \
  --auth-token "$VAPI_OWNER_TOKEN" --other-auth-token "$VAPI_OTHER_TOKEN"
```
**Target must include the `/vapi` prefix** — vAPI's real routes all live under `/vapi/...` (confirmed from its own Postman collection, `postman/vAPI.postman_collection.json`), not at bare `http://localhost:8000/...`. An earlier version of this doc omitted it, which would have made every request 404/500 rather than reach the real endpoint — corrected here after live-verifying (2026-08-28), not caught until an actual run was attempted.

Real, live-verified result (2026-08-28): **6 findings** (`idor-1` through `idor-6`) — `hf_other`'s token retrieved real, personalized user data (`username`/`name`/`course`) for every account ID 1-6, including `hf_owner`'s own account, confirming the real BOLA read directly from source (`API1UsersController::show`, no ownership check).

**Registering accounts via the API directly** (faster than the web UI doc03 originally suggested, and what was actually used for the run above) — `POST /vapi/api1/user` requires all four fields (`username`, `name`, `course`, `password`) even though only `username`/`password` matter for login; omitting `name`/`course` hits a `NOT NULL` DB constraint and returns a bare `500` with no detail (a real vAPI robustness gap, not a HackerFive bug):
```bash
curl -s -X POST http://localhost:8000/vapi/api1/user -H 'Content-Type: application/json' \
  -d '{"username":"hf_owner","name":"HackerFive Owner","course":"n/a","password":"Passw0rd123!"}'
export VAPI_OWNER_TOKEN=$(printf '%s' 'hf_owner:Passw0rd123!' | base64)
export VAPI_OTHER_TOKEN=$(printf '%s' 'hf_other:Passw0rd456!' | base64)   # register hf_other the same way first
```

### What HackerFive needs (misconfig + templates)

```bash
cd ~/projects/hacker-five
./hackerfive scan -t http://localhost:8000 --detector misconfig
```
No tokens, no `--endpoint`. Real, live-verified result (2026-08-25): **9 findings** — 4 missing security headers, 3 disallowed methods (`PUT`/`DELETE`/`PATCH` all return `500` rather than `405`/`403` — Laravel's `APP_DEBUG: "true"` in its `docker-compose.yml` means this and any other unhandled path likely also produces a real, verbose stack trace, a live signal for `misconfig`'s verbose-error check), plus 2 from the synced Nuclei-compatible template set (`http-missing-security-headers`, `php-detect`).

### Auth bypass (`--detector authbypass`)

```bash
cd ~/projects/hacker-five
./hackerfive scan -t http://localhost:8000/vapi --detector authbypass \
  --auth-token "$VAPI_OWNER_TOKEN" --other-auth-token "$VAPI_OTHER_TOKEN" \
  --protected-paths '/api1/user/5,/api1/user/6'
```
Real, live-verified result (2026-08-28): **1 low-confidence finding**, `authbypass-no-rate-limit-login` — fired against `/login`, one of `authbypass.LoginPaths`' three fixed candidates, which doesn't exist on vAPI (real routes are `/vapi/api2/user/login`, `/vapi/api4/login`, etc. — none at bare `/login`) and returns a bare `500` for every request. The check correctly reports this at `"confidence": "low"` with its own description flagging "needs manual triage," so it isn't lying, but it also isn't real signal about vAPI's actual login endpoints — one of which (`api9/v2/user/login`) genuinely does have `throttle:5,1` rate-limiting in vAPI's own `routes/api.php`, and others (`api2`, `api4`, `api8`) don't. **This is the same `LoginPaths`/`LogoutPaths` mismatch noted in crAPI's section above** — see [11-implementation-plan-ph2.md](11-implementation-plan-ph2.md) Step 5.

The other checks correctly found nothing with the command above: `checkMissingAuth` (a request with no `Authorization` header at all gets a real `403`, not a false `200`), the two JWT checks (vAPI's `api1` scheme is `base64(username:password)` via a custom `Authorization-Token` header, not a JWT — `looksLikeJWT` correctly identifies this and no-ops), and token-reuse/broken-session (also scheme-mismatched — `authbypass.Detector` only sends `Authorization: Bearer <token>` by default).

**Fixed and live-verified**: `authbypass.Detector` now supports the same `--auth-header-name`/`--auth-header-format` override `idor.Detector` already had —
```bash
./hackerfive scan -t http://localhost:8000/vapi --detector authbypass \
  --auth-token "$VAPI_OWNER_TOKEN" --other-auth-token "$VAPI_OTHER_TOKEN" \
  --protected-paths '/api1/user/5,/api1/user/6' \
  --auth-header-name 'Authorization-Token' --auth-header-format '{token}'
```
Real result (2026-08-28): **2 new real findings**, `authbypass-token-reuse-api1-user-5`/`-6` — `/vapi/api1/user/{id}` returns identical content regardless of which account's token is used (the same underlying BOLA the IDOR run above already found, now also caught through auth-bypass's own token-reuse lens, since the request finally carries a header vAPI's real auth middleware recognizes at all).

**vAPI also ships its own intentional weak-JWT-secret challenge** (`POST /vapi/jwt/user` to register, `GET /vapi/jwt/user` with an `Authorization-Token` header to redeem, `App\Http\Controllers\JustWeakTokenController`) — a *different* auth module from `api1`'s header scheme. The earlier session's unexplained `500` on registration was chased down and resolved (2026-08-28): it's not a vAPI bug or a HackerFive gap, just a reused `username` colliding with `justweaktokens`' `UNIQUE` DB constraint — a fresh username registers cleanly and returns `200` with a real JWT.

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/vapi/jwt/user -H 'Content-Type: application/json' \
  -d '{"username":"<unique-name>","password":"<any>"}' | jq -r .token)
./hackerfive scan -t http://localhost:8000 --detector authbypass \
  --auth-token "$TOKEN" --protected-paths /vapi/jwt/user \
  --auth-header-name 'Authorization-Token' --auth-header-format '{token}'
```
Real, live-verified result (2026-08-28): **4 real findings** — `authbypass-jwt-alg-none-vapi-jwt-user` and `authbypass-jwt-signature-stripped-vapi-jwt-user` (both **critical**: the server's `JWT::decode($token, $key, array('HS256','none'))` call really does accept `alg: none`, confirmed independently by hand-forging a `role:admin` token and retrieving the module's flag directly — see doc11 Step 5), `authbypass-broken-session-vapi-jwt-user` (**high**: the token still works after hitting the generic `/logout` guess — this module has no server-side logout at all, so any logout attempt trivially "fails" to invalidate it), and `authbypass-no-rate-limit-login` (**info/needs-triage**, same `/login`-guess mismatch as above — not new signal). One transient run produced only the broken-session finding with no error; a same-second re-run and an isolated direct-`Run()` call both reproduced all 4 findings cleanly, so this was a one-off flake (most likely the local container's own warm-up), not a detector bug — logged as a note, not chased further given it hasn't recurred.

### SSRF (`--detector ssrf`) — real vulnerability, via `/vapi/serversurfer`

vAPI's "ServerSurfer" exercise (`GET /vapi/serversurfer?url=<url>`) fetches whatever URL it's given server-side and returns `{"success":..., "data":"<base64 of the fetched response>"}` — real, no login required. Point HackerFive directly at that endpoint (not just `/vapi`):
```bash
./hackerfive scan -t http://localhost:8000/vapi/serversurfer --detector ssrf --ssrf-param url
```
Real, live-verified result (2026-08-29): **`ssrf-scheme-based-url-file` fires** — `file:///etc/passwd` returns a real `200` with the actual file's base64-encoded content. Other payloads' real behavior, useful context if results look different on a re-run:
- Plain `127.0.0.1` is blocklisted (`403 "Whoa!!! Not Allowed!!"`) — correctly produces no finding.
- Decimal (`2130706433`)/octal (`0177.0.0.1`) bypass that blocklist (no 403) but the fetch itself returns `500`, not `200` — real evidence the filter is naive, but not independently provable as a working fetch on this specific deployment.
- Hex (`0x7f000001`) and both IPv6 forms hang vAPI's own backend indefinitely rather than completing — HackerFive's own `--timeout` correctly bounds this and treats it as no finding, not a hang or crash on our side.
- `gopher://`/`dict://` are blocklisted the same as plain `127.0.0.1`.

**A real gotcha this surfaced**: firing every encoded-bypass variant in one run can leave vAPI's small worker pool tied up for several minutes afterward (each hang gets retried 3× by HackerFive's own shared retry middleware) — if you see fewer findings than expected, wait a minute and re-run rather than assuming a detector bug; `pkg/detectors/ssrf` no longer shares the other detectors' host-error circuit breaker for exactly this reason (see [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 2).

**Blind OOB check** (`--oob-server`) needs a self-hosted Interactsh-protocol server (e.g. `interactsh-server`'s Docker image) — not yet brought up/live-verified as of 2026-08-29; the protocol/crypto correctness is proven by `tests/unit/detector_ssrf_test.go`'s real encrypted round trip against a fake server.

### Teardown / reset

```bash
cd ~/targets/vapi && docker-compose down -v
```

---

## AIGoat (for prompt-injection templates)

[AIGoat](https://github.com/AISecurityConsortium/AIGoat) (Apache 2.0 app code) is a deliberately-vulnerable LLM shopping-assistant chatbot covering the full OWASP LLM Top 10, self-hosted via Docker + Ollama — no external API, no cost. Used to build and live-verify `templates/nuclei-samples/promptinjection/` (see that directory's README and [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) Step 1).

### Bring it up

```bash
wsl                     # Windows only — drops into the Ubuntu shell; skip on macOS
mkdir -p ~/targets && cd ~/targets
git clone https://github.com/AISecurityConsortium/AIGoat.git
cd AIGoat
```

**Model substitution — use Gemma 3 4B instead of the default Mistral 7B** (smaller/faster; AIGoat's own docs confirm `ollama.model` is meant to be user-swappable, no challenge design is documented as Mistral-specific). `docker-compose` actually mounts `docker/config.yml` into the backend container, not the top-level `config/config.yml` — edit **both** for consistency, but only `docker/config.yml` matters for the running container:
```bash
sed -i 's/model: "mistral"/model: "gemma3:4b"/' config/config.yml docker/config.yml
```

**Raise the Ollama request timeout** — AIGoat's default (`ollama.timeout: 60` seconds) is tuned for a GPU. A real chat completion on CPU-only Gemma 3 4B genuinely takes 60-90s, so the default timeout cuts it off mid-generation (`Ollama generate failed: ` in the backend log, an empty-string error — confirmed live, 2026-08-29):
```bash
sed -i 's/timeout: 60/timeout: 240/' docker/config.yml
```

**Port conflicts with HackerFive's other lab targets**: AIGoat's backend defaults to host port 8000 (collides with vAPI's `www` container) and its frontend to 3000 (collides with Juice Shop). HackerFive only needs the backend's chat API for template testing, so remap the backend's host port and skip starting the frontend entirely rather than tear down your other running targets:
```bash
sed -i 's/"8000:8000"/"18000:8000"/' docker/docker-compose.yml
docker volume create ollama_models   # external volume — survives "down -v", so the model is only pulled once
cd docker && docker compose up -d --build ollama backend
```
- **API:** `http://localhost:18000` (real container-internal port is still 8000; only the host-side mapping changed)
- **API docs (Swagger):** `http://localhost:18000/docs`
- First startup pulls the `gemma3:4b` model automatically (several GB — the same one-time-download tradeoff DVWA/crAPI's image pulls don't have) and seeds demo data (`docker compose logs -f backend` to watch progress).
- **Demo accounts:** `alice`/`bob`/`charlie`/`frank`, all password `password123`; admin: `admin`/`admin123`.

### What HackerFive needs

```bash
cd ~/projects/hacker-five
TOKEN=$(curl -s -X POST http://localhost:18000/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

./hackerfive scan -t http://localhost:18000 \
  --templates templates/nuclei-samples/promptinjection \
  --header "Authorization: Bearer $TOKEN"
```
Same "static token via `--header`" pattern already used for DVWA's session cookie — nuclei-format templates have no chaining mechanism to log in themselves.

**Real, live-verified result (2026-08-29)**: 9 findings — 7 from `misconfig` (missing security headers, disallowed methods accepted) and 2 real prompt-injection leaks from `templates/nuclei-samples/promptinjection/` — both templates genuinely leaked AIGoat's system prompt (admin credentials, database path, internal config) via its Gemma-3-backed `Cracky AI` assistant. See that directory's README for the full result, including a real matcher bug (JSON-escaping vs. `\b` word boundaries) live-testing caught and fixed. The concurrency guardrail correctly warned at the default `--concurrency 25`.

Note on latency: each chat completion takes ~60-90s on CPU-only Gemma 3 4B — raise `--timeout` well above this project's other targets' defaults (`--timeout 200s` used above) or requests will time out before the model finishes generating.

### Teardown / reset

```bash
cd ~/targets/AIGoat/docker && docker compose down -v   # -v also drops seeded demo data; add `docker volume rm ollama_models` to also force a re-pull of the model
```

---

## Other targets (no detector targets these yet)

No setup steps here on purpose — these are Docker-available but nothing in HackerFive targets them yet (see table above), so there's no real live-verified result to document, unlike the sections above. Pull the image ahead of time if you want it ready for when Phase 2's XSS/SQLi work lands (see [03-development-roadmap.md](03-development-roadmap.md) Week 13-16) and this graduates to its own section:
```bash
docker pull --platform linux/amd64 webgoat/goatandwolf   # amd64-only image; needs Rosetta on Apple Silicon Macs, native on Windows/WSL2 and Intel Macs
```

---

## Summary: what to prepare, per target

| Target | Credentials/tokens HackerFive needs | Where they come from | One-time setup step |
|---|---|---|---|
| crAPI | `HACKERFIVE_AUTH_TOKEN`, `HACKERFIVE_OTHER_AUTH_TOKEN` (or `--auth-token`/`--other-auth-token`) — same tokens also drive `--detector authbypass` | `tests/integration/scripts/crapi_setup.sh` (signs up two real throwaway accounts) | Log in as the owner account in the browser, add a vehicle, submit one "Contact Mechanic" report |
| DVWA | None for `misconfig`; a manually-obtained `PHPSESSID` session cookie for XSS/SQLi (not yet CLI-supportable, see its section above) | — | Click "Create / Reset Database" once at `/setup.php`; set Security level to Low |
| Juice Shop | None | — | None — ready as soon as the container responds |
| vAPI | `VAPI_OWNER_TOKEN`, `VAPI_OTHER_TOKEN` for `--detector idor`/`authbypass` (each `base64(username:password)`; target must include the `/vapi` prefix) — none for `--detector misconfig` | `POST /vapi/api1/user` with `username`/`name`/`course`/`password` (faster than the web UI), then base64-encode `username:password` yourself | None — `docker-compose.yml`'s DB init runs automatically |
| AIGoat | A JWT via `--header "Authorization: Bearer $TOKEN"` for the promptinjection templates | `POST /api/auth/login/` with a demo account (`alice`/`password123`) | `sed` the Ollama model to `gemma3:4b` in both config files and remap the backend's host port before `docker compose up` — see its section above |

## See also
- [04-environment-and-testing.md](04-environment-and-testing.md) — Docker/WSL2/Mac dev environment these targets run under
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — read-only/authorized-target-only constraints these local targets satisfy
- [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md) — the prompt-injection detector work this AIGoat setup validates
- [21-scanning-real-targets.md](21-scanning-real-targets.md) — the equivalent workflow once you're past these lab targets and scanning a real, authorized one
- [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) — IDOR detector this crAPI setup validates
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — misconfiguration detector this DVWA/Juice Shop setup validates, and the Nuclei-compatible template engine this Juice Shop setup also validates
- [README.md](../README.md) — Quick Start commands that assume the setup steps on this page are done
