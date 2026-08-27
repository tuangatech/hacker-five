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

### Teardown / reset

```bash
cd ~/targets/crAPI/deploy/docker && docker compose down -v   # -v also drops the account data crapi_setup.sh created
```

---

## DVWA (for `--detector misconfig`)

[Damn Vulnerable Web Application](https://github.com/digininja/DVWA) is a stateless PHP/MySQL app — no account tokens needed, since misconfig's checks (exposed paths, missing headers, disallowed methods, CORS, verbose errors, default creds) don't require an authenticated session to probe.

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
No tokens, no `--endpoint` — misconfig runs its full built-in rule table against the target root and its fixed path list directly.

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
No tokens, no `--endpoint`.

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
./hackerfive scan -t http://localhost:8000 --detector idor \
  --endpoint '/api1/user/{{id}}' \
  --auth-header-name 'Authorization-Token' --auth-header-format '{token}' \
  --auth-token "$VAPI_OWNER_TOKEN" --other-auth-token "$VAPI_OTHER_TOKEN"
```
Not yet live-verified against a running vAPI instance from this project's Windows-side checkout (no Docker there) — run this (or `tests/integration/vapi_auth_test.go`'s `TestIDORAgainstVAPI`, gated behind `VAPI_BASE_URL`/`VAPI_OWNER_TOKEN`/`VAPI_OTHER_TOKEN`) from this native clone and update this note with the real result once confirmed.

### What HackerFive needs (misconfig + templates)

```bash
cd ~/projects/hacker-five
./hackerfive scan -t http://localhost:8000 --detector misconfig
```
No tokens, no `--endpoint`. Real, live-verified result (2026-08-25): **9 findings** — 4 missing security headers, 3 disallowed methods (`PUT`/`DELETE`/`PATCH` all return `500` rather than `405`/`403` — Laravel's `APP_DEBUG: "true"` in its `docker-compose.yml` means this and any other unhandled path likely also produces a real, verbose stack trace, a live signal for `misconfig`'s verbose-error check), plus 2 from the synced Nuclei-compatible template set (`http-missing-security-headers`, `php-detect`).

### Teardown / reset

```bash
cd ~/targets/vapi && docker-compose down -v
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
| crAPI | `HACKERFIVE_AUTH_TOKEN`, `HACKERFIVE_OTHER_AUTH_TOKEN` (or `--auth-token`/`--other-auth-token`) | `tests/integration/scripts/crapi_setup.sh` (signs up two real throwaway accounts) | Log in as the owner account in the browser, add a vehicle, submit one "Contact Mechanic" report |
| DVWA | None | — | Click "Create / Reset Database" once at `/setup.php`; set Security level to Low |
| Juice Shop | None | — | None — ready as soon as the container responds |
| vAPI | `VAPI_OWNER_TOKEN`, `VAPI_OTHER_TOKEN` for `--detector idor` (each `base64(username:password)`) — none for `--detector misconfig` | Sign up two accounts via vAPI's web UI, base64-encode each `username:password` yourself (no scripted signup like crAPI's) | None — `docker-compose.yml`'s DB init runs automatically |

## See also
- [04-environment-and-testing.md](04-environment-and-testing.md) — Docker/WSL2/Mac dev environment these targets run under
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — read-only/authorized-target-only constraints these local targets satisfy
- [21-scanning-real-targets.md](21-scanning-real-targets.md) — the equivalent workflow once you're past these lab targets and scanning a real, authorized one
- [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) — IDOR detector this crAPI setup validates
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — misconfiguration detector this DVWA/Juice Shop setup validates, and the Nuclei-compatible template engine this Juice Shop setup also validates
- [README.md](../README.md) — Quick Start commands that assume the setup steps on this page are done
