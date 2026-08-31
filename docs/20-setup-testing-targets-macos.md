# HackerFive Test Targets — macOS Setup Guide

Adapted from `docs/20-setup-testing-targets.md` for macOS specifically. The original doc is written with WSL2/Windows callouts throughout ("wsl # Windows only"); those are dropped below since Terminal on macOS runs everything natively. A few commands also needed real adjustment, not just callout removal — macOS ships **BSD** `sed`/`xargs`, not GNU, and those have different flag behavior. Flagged inline wherever it matters.

---

## 0. Prerequisites

- **Docker Desktop for Mac** — [docker.com](https://www.docker.com/products/docker-desktop/), or `brew install --cask docker`. This bundles Compose V2 (`docker compose`, no hyphen) automatically.
- **Homebrew** — for `jq` (used by crAPI's setup script and a couple of `curl | jq` one-liners below): `brew install jq`. `curl` and `base64` are already preinstalled on macOS.
- **Go 1.26+** (only if building HackerFive from source) — `brew install go`.
- **Apple Silicon (M1/M2/M3/M4) note:** most images below are multi-arch and pull a native `arm64` image automatically. If Docker ever prints a platform-mismatch warning for a given image, it'll fall back to Rosetta emulation — slower, but it works; you don't need to do anything unless you want to pin `--platform linux/amd64` explicitly.
- **Resource allocation:** if you bring up several targets at once (e.g. crAPI's multi-container stack + AIGoat's Ollama model), bump Docker Desktop's memory/CPU limits under **Settings → Resources** — the default can feel tight with 2-3 stacks running simultaneously.

**Directory layout — keep target repos *out* of your HackerFive checkout:**
```bash
mkdir -p ~/Tuan/weekend/hacker-five-targets          # crAPI, vAPI, AIGoat clone in here
cd ~/Tuan/weekend/hacker-five   # wherever you cloned/built hackerfive itself — adjust paths below if yours differs
```
Never `git clone` a target repo inside `hacker-five/` — its own `.git` would nest inside yours.

**Build the HackerFive binary itself** (pick one):
```bash
# via go install
go install github.com/tuangatech/hacker-five/cmd/hackerfive@latest

# from source
git clone https://github.com/tuangatech/hacker-five.git ~/Tuan/weekend/hacker-five
cd ~/Tuan/weekend/hacker-five
make build
./hackerfive --version
```

**One standing gotcha to know before you run anything:** `./hackerfive scan` loads and fires the *entire* template corpus (bundled + synced, up to ~3,000+ templates) **additively**, on top of whatever `--detector` you pick — it's never an either/or. If you're timing or isolating one detector's behavior, pass either an empty templates dir or a `--tags` filter that matches nothing, or an expected ~1-minute run can silently balloon to 50+ minutes:
```bash
mkdir -p /tmp/empty-templates
./hackerfive scan -t <target> --detector <x> --templates /tmp/empty-templates
```

---

## 1. crAPI — `--detector idor` / `authbypass` / `businesslogic`

Real cross-account IDOR, JWT `alg:none` bypass (systemic across its microservices), and a real coupon/business-logic bug — see the original doc for full detail; commands only below.

### Bring it up
```bash
cd ~/Tuan/weekend/hacker-five-targets
git clone https://github.com/OWASP/crAPI.git
cd crAPI/deploy/docker
docker compose down -v      # wipe any stale data from a prior run
docker compose up -d
```
- App: `http://localhost:8888`
- MailHog (catches signup/OTP email): `http://localhost:8025`

### Two accounts + one mechanic report
```bash
cd ~/Tuan/weekend/hacker-five
export CRAPI_BASE_URL=http://localhost:8888   # optional, this is the default
brew install jq                                # if not already installed
source tests/integration/scripts/crapi_setup.sh
# → exports CRAPI_OWNER_TOKEN, CRAPI_OTHER_TOKEN, CRAPI_OWNER_EMAIL, CRAPI_OTHER_EMAIL, CRAPI_PASSWORD
```
Must be `source`d (not executed) so the exports land in your shell. If it errors, crAPI's `identity` service is probably still finishing DB migrations after `docker compose up -d` — check `docker compose ps` shows it healthy, then re-run.

Then, in a browser:
1. Log into `http://localhost:8888` as `hackerfive-owner@example.com` / `Passw0rd!`.
2. Open [MailHog](http://localhost:8025), find the signup email, note the VIN + Pincode it contains.
3. Back in the app, click **"Add a vehicle"**, enter that VIN/Pincode.
4. On the resulting Vehicle Details page, click **"Contact Mechanic"** once to submit a report.

### Run the scans
```bash
export HACKERFIVE_AUTH_TOKEN="$CRAPI_OWNER_TOKEN"
export HACKERFIVE_OTHER_AUTH_TOKEN="$CRAPI_OTHER_TOKEN"

# IDOR (baseline mode)
./hackerfive scan -t http://localhost:8888 \
  --detector idor \
  --endpoint '/workshop/api/mechanic/mechanic_report?report_id={{id}}'

# Auth bypass — the fixed LoginPaths defaults don't match crAPI's real path,
# so override them:
./hackerfive scan -t http://localhost:8888 --detector authbypass \
  --protected-paths '/identity/api/v2/user/dashboard' \
  --login-paths '/identity/api/auth/login'

# Broader auth-bypass recon across 8 more endpoints (crAPI's real OpenAPI spec)
./hackerfive scan -t http://localhost:8888 --detector authbypass \
  --auth-token "$CRAPI_OWNER_TOKEN" --other-auth-token "$CRAPI_OTHER_TOKEN" \
  --protected-paths '/identity/api/v2/user/videos/convert_video,/community/api/v2/community/posts/recent,/workshop/api/shop/products,/workshop/api/shop/orders/all,/workshop/api/management/users/all,/workshop/api/mechanic/,/workshop/api/mechanic/service_requests,/workshop/api/shop/return_qr_code'

# Business logic (coupon flow) — this is the one detector that WRITES,
# hence --allow-writes
./hackerfive scan -t http://localhost:8888 --detector businesslogic --allow-writes \
  --auth-token "$CRAPI_OWNER_TOKEN" --templates /tmp/empty-templates
```

### Teardown
```bash
cd ~/Tuan/weekend/hacker-five-targets/crAPI/deploy/docker
docker compose down -v   # -v also drops the account data crapi_setup.sh created
```

---

## 2. DVWA — `--detector misconfig`

Stateless PHP/MySQL app, no accounts needed.

### Bring it up
```bash
docker pull vulnerables/web-dvwa
docker run -d -p 80:80 vulnerables/web-dvwa
```
- App: `http://localhost`
- **Required one-time step:** open `http://localhost/setup.php` and click **"Create / Reset Database."** Until you do this it only serves a setup shell, not the real app.
- Default web login `admin` / `password` (only needed if you want to browse it yourself). Under the **Security** tab, set difficulty to **Low** — don't assume it's already there.

### Run the scan
```bash
cd ~/Tuan/weekend/hacker-five
./hackerfive scan -t http://localhost --detector misconfig
```
No tokens, no `--endpoint` needed. Expect ~12 findings (missing headers, exposed paths, disallowed methods, a directory-listing hit). The built-in default-creds check won't fire here — DVWA's login needs a CSRF token the fixed checker doesn't send; that's expected, not a bug.

### XSS/SQLi (needs a session cookie — nuclei templates can't log in themselves)
Grab a `PHPSESSID` by logging into DVWA in a browser with dev tools open (Application → Cookies), then:
```bash
./hackerfive scan -t http://localhost --detector misconfig --tags xss,sqli \
  --header "Cookie: PHPSESSID=<real session id>; security=low"
```

### Teardown
```bash
docker ps --filter ancestor=vulnerables/web-dvwa -q | xargs docker stop
```
> **macOS note:** the original doc uses `xargs -r`. macOS's built-in `xargs` (BSD, not GNU) doesn't have a `-r` flag at all and will error on it — just drop it. BSD `xargs` already skips running the command when there's no input, so behavior is identical without the flag.

---

## 3. Juice Shop — `--detector misconfig` + Nuclei-compatible templates

Single-container Angular/Express app, no accounts, no setup step.

### Bring it up
```bash
docker pull bkimminich/juice-shop
docker run -d -p 3000:3000 bkimminich/juice-shop
```
App: `http://localhost:3000` — ready as soon as it responds.

### Run the scans
```bash
cd ~/Tuan/weekend/hacker-five
./hackerfive scan -t http://localhost:3000 --detector misconfig
./hackerfive scan -t http://localhost:3000 --detector misconfig --tags xss,sqli   # expect 0 — see note below
```
The `/well-known/security.txt` hit and the PUT/DELETE/PATCH-accepted hits are both artifacts of Juice Shop's SPA catch-all responding to everything with 200 — real content, but not real bugs. XSS/SQLi comes back empty because Juice Shop's search endpoint returns JSON (matcher correctly excludes it) and its real XSS bugs are DOM-based, out of scope until browser-based validation exists.

For the Nuclei-compatible engine (not yet CLI-wired, so via the Go integration test):
```bash
export JUICESHOP_BASE_URL=http://localhost:3000
make templates-sync   # only if .nuclei-templates-cache/ isn't already populated
go test -tags=integration ./tests/integration/... -run TestNucleiTemplates -v
```

### Teardown
```bash
docker ps --filter ancestor=bkimminich/juice-shop -q | xargs docker stop
```
(same `-r`-drop note as DVWA above)

---

## 4. vAPI — `--detector idor` / `misconfig` / `authbypass` / `ssrf`

PHP/Laravel + MySQL, real BOLA (`API1UsersController::show`), a custom `Authorization-Token: base64(username:password)` auth scheme, and a real SSRF endpoint (`/serversurfer`).

### Bring it up
```bash
cd ~/Tuan/weekend/hacker-five-targets
git clone https://github.com/roottusk/vapi.git
cd vapi
docker-compose up -d
```
- App: `http://localhost:8000`
- phpMyAdmin: `http://localhost:8001`

> **macOS note:** this repo's own docs assume the standalone `docker-compose` (v1, hyphenated) binary. Docker Desktop for Mac ships Compose V2 as the `docker compose` plugin instead — the classic hyphenated command may not exist on a fresh install. If `docker-compose up -d` fails with "command not found," use `docker compose up -d` (no hyphen) instead; it reads the same `docker-compose.yml`.

### Get two account tokens
No scripted signup for vAPI — register via the API directly:
```bash
curl -s -X POST http://localhost:8000/vapi/api1/user -H 'Content-Type: application/json' \
  -d '{"username":"hf_owner","name":"HackerFive Owner","course":"n/a","password":"Passw0rd123!"}'
curl -s -X POST http://localhost:8000/vapi/api1/user -H 'Content-Type: application/json' \
  -d '{"username":"hf_other","name":"HackerFive Other","course":"n/a","password":"Passw0rd456!"}'

export VAPI_OWNER_TOKEN=$(printf '%s' 'hf_owner:Passw0rd123!' | base64)
export VAPI_OTHER_TOKEN=$(printf '%s' 'hf_other:Passw0rd456!' | base64)
```
All four fields (`username`/`name`/`course`/`password`) are required or you'll hit a bare `500` from a DB constraint.

**Another real gotcha, live-verified 2026-08-30 — the default template corpus hangs against vAPI:** any of the commands below, run without a `--templates` override, sat for 2+ minutes with zero output (never even printed the JSON array). Root cause: `authbypass`'s rate-limit-signal check treats vAPI's generic `500` catch-all as "found the login endpoint" (only `404`/`415` are excluded), then the shared retry middleware retries each of those 500s 3× with backoff — turning a handful of fast no-ops into a long, silent stall. Until that's fixed, append `--templates /tmp/empty-templates` to every vAPI command below (per the standing gotcha in [§0](#0-prerequisites)) to avoid it — the detector-level findings are unaffected, only the (empty, for vAPI) nuclei-template layer is skipped.

### Run the scans
```bash
cd ~/Tuan/weekend/hacker-five

# IDOR — note the /vapi prefix is required, and the custom auth header
./hackerfive scan -t http://localhost:8000/vapi --detector idor \
  --endpoint '/api1/user/{{id}}' \
  --auth-header-name 'Authorization-Token' --auth-header-format '{token}' \
  --auth-token "$VAPI_OWNER_TOKEN" --other-auth-token "$VAPI_OTHER_TOKEN" \
  --templates /tmp/empty-templates

# Misconfig — no tokens/prefix needed
./hackerfive scan -t http://localhost:8000 --detector misconfig --templates /tmp/empty-templates

# Auth bypass — same header override, or the checks scheme-mismatch and find nothing
./hackerfive scan -t http://localhost:8000/vapi --detector authbypass \
  --auth-token "$VAPI_OWNER_TOKEN" --other-auth-token "$VAPI_OTHER_TOKEN" \
  --protected-paths '/api1/user/5,/api1/user/6' \
  --auth-header-name 'Authorization-Token' --auth-header-format '{token}' \
  --templates /tmp/empty-templates

# SSRF — real bug via ServerSurfer
./hackerfive scan -t http://localhost:8000/vapi/serversurfer --detector ssrf --ssrf-param url --templates /tmp/empty-templates

# SSRF blind/OOB, using the public Interactsh pool (see §6 for self-hosted instead)
./hackerfive scan -t http://localhost:8000/vapi/serversurfer --detector ssrf --ssrf-param url --oob-server public --templates /tmp/empty-templates
```
Optional: vAPI's separate weak-JWT module (`/vapi/jwt/user`):
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/vapi/jwt/user -H 'Content-Type: application/json' \
  -d '{"username":"<unique-name>","password":"<any>"}' | jq -r .token)
./hackerfive scan -t http://localhost:8000 --detector authbypass \
  --auth-token "$TOKEN" --protected-paths /vapi/jwt/user \
  --auth-header-name 'Authorization-Token' --auth-header-format '{token}'
```

**A real timing gotcha, worth knowing before you run the encoded-SSRF-bypass sweep:** vAPI's own worker pool can get tied up for several minutes after a hang-prone payload (e.g. hex/IPv6 forms) — if a run returns fewer findings than expected, wait a minute and re-run rather than assuming a bug.

### Teardown
```bash
cd ~/Tuan/weekend/hacker-five-targets/vapi
docker-compose down -v   # or `docker compose down -v` if you hit the same hyphen issue as above
```

---

## 5. AIGoat — prompt-injection templates

Deliberately-vulnerable LLM chatbot (OWASP LLM Top 10), self-hosted via Ollama — no external API, no cost.

### Bring it up
```bash
cd ~/Tuan/weekend/hacker-five-targets
git clone https://github.com/AISecurityConsortium/AIGoat.git
cd AIGoat
```

**Swap the model to Gemma 3 4B** (smaller/faster than the default Mistral 7B):
```bash
sed -i '' 's/model: "mistral"/model: "gemma3:4b"/' config/config.yml docker/config.yml
```
> **macOS note — this is the one command that actively breaks unmodified.** The original doc's `sed -i 's/.../.../' file` is GNU `sed` syntax. macOS ships **BSD** `sed`, which requires an explicit backup-suffix argument right after `-i` — an empty string `''` for "no backup." Every `sed -i` command below needs that extra `''`, or `sed` will error out (or, worse, silently write garbage depending on shell quoting). If you'd rather not think about this every time, `brew install gnu-sed` gives you `gsed`, which accepts the original Linux-style syntax unmodified.

**Raise the Ollama request timeout** (CPU-only generation is slow):
```bash
sed -i '' 's/timeout: 60/timeout: 240/' docker/config.yml
```

**Remap the backend's host port** (8000 collides with vAPI, 3000 collides with Juice Shop — you only need the backend, so skip the frontend):
```bash
sed -i '' 's/"8000:8000"/"18000:8000"/' docker/docker-compose.yml
docker volume create ollama_models    # external volume — survives `down -v`, model only pulled once
cd docker
docker compose up -d --build ollama backend
```
- API: `http://localhost:18000`
- Swagger docs: `http://localhost:18000/docs`
- Demo accounts: `alice`/`bob`/`charlie`/`frank`, password `password123`; admin: `admin`/`admin123`
- First run pulls the model (several GB) — watch progress with `docker compose logs -f backend`.

### Run the scan
```bash
cd ~/Tuan/weekend/hacker-five
TOKEN=$(curl -s -X POST http://localhost:18000/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}' | jq -r .token)

./hackerfive scan -t http://localhost:18000 \
  --detector misconfig \
  --templates templates/nuclei-samples/promptinjection \
  --header "Authorization: Bearer $TOKEN" \
  --timeout 200s
```
`--detector` is a required flag on this build (`idor`/`misconfig`/`authbypass`/`ssrf`/`businesslogic` — no "none"/prompt-injection value exists yet), so it can't be omitted; `misconfig` is a safe placeholder here since it needs no extra flags and its native header/method checks are harmless background noise — the `--templates` flag independently scopes in just the prompt-injection templates regardless of which detector is picked.

Each chat completion takes ~60-90s on CPU-only Gemma 3 4B — the generous `--timeout` above is deliberate, not a typo. If you leave `--concurrency` at the default (25), expect a stderr warning about hammering an LLM-backed endpoint too hard; that's the built-in guardrail, not an error.

### Teardown
```bash
cd ~/Tuan/weekend/hacker-five-targets/AIGoat/docker
docker compose down -v
# optional — also forces a re-pull of the model next time:
docker volume rm ollama_models
```

---

## 6. Interactsh Server — self-hosted OOB receiver (for `--detector ssrf --oob-server`)

Not a scan target itself — it's the callback receiver the SSRF detector's blind check polls. HackerFive never talks to the *public* Interactsh service by default; `--oob-server` only takes a URL you're self-hosting (or the explicit `public` opt-in used above).

### Bring it up
```bash
docker pull projectdiscovery/interactsh-server:latest
docker run -d --name oob-server -p 8082:8082 \
  projectdiscovery/interactsh-server:latest -domain localhost -skip-acme -http-port 8082
```
`*.localhost` auto-resolves to loopback on macOS with no `/etc/hosts` entry needed (same as Linux/Windows) — confirm with `dscacheutil -q host -a name test123.localhost` if you want to check.

**One real constraint:** this only works cleanly against a target running directly on your host's network (not inside its own Docker container) — a Dockerized target like vAPI has its *own* loopback, so `localhost:8082` from inside its container resolves nowhere useful. For a real Dockerized lab target, either use a publicly-resolvable hostname for a real self-hosted server, or use the `--oob-server public` opt-in shown in vAPI's section above.

### Teardown
```bash
docker rm -f oob-server
```

---

## Summary: what each target needs

| Target | Credentials HackerFive needs | Where they come from | One-time setup |
|---|---|---|---|
| crAPI | `HACKERFIVE_AUTH_TOKEN` / `HACKERFIVE_OTHER_AUTH_TOKEN` | `crapi_setup.sh` (scripted signup) | Add a vehicle + submit one mechanic report via browser |
| DVWA | None for misconfig; a manual `PHPSESSID` cookie for XSS/SQLi | Browser dev tools | "Create/Reset Database" once at `/setup.php`; set Security to Low |
| Juice Shop | None | — | None |
| vAPI | `VAPI_OWNER_TOKEN` / `VAPI_OTHER_TOKEN` (base64 `user:pass`) | `POST /vapi/api1/user` | None |
| AIGoat | A JWT via `--header` | `POST /api/auth/login/` with a demo account | `sed` the model/port config before `docker compose up` |

## Tear everything down at once
```bash
cd ~/Tuan/weekend/hacker-five-targets/crAPI/deploy/docker && docker compose down -v
docker ps --filter ancestor=vulnerables/web-dvwa -q | xargs docker stop
docker ps --filter ancestor=bkimminich/juice-shop -q | xargs docker stop
cd ~/Tuan/weekend/hacker-five-targets/vapi && docker compose down -v
cd ~/Tuan/weekend/hacker-five-targets/AIGoat/docker && docker compose down -v
docker rm -f oob-server 2>/dev/null
```
