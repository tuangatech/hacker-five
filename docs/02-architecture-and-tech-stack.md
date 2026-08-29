# Architecture & Technology Stack

> Part of the [HackerFive documentation set](../README.md).

## Technology Stack

### Core Components

#### 1. **Language: Go (Golang)**
- **Why?**
  - Compiles to single static binary (no dependencies, easy distribution)
  - Concurrent request handling via goroutines (150+ req/sec baseline)
  - Fast startup and low memory footprint
  - Built-in HTTP/DNS/TCP clients
  - Production-proven by Nuclei, Nmap, Docker, Kubernetes

- **Minimum Version:** Go 1.21+

#### 2. **Detection Templates: YAML**
- **Why, in plain English:** the scanner splits into two separate things — an engine (the Go code) and templates (YAML files). The engine is generic and only gets built once: it knows how to send a web request, read the response, and check it against a set of rules. It has no idea what "IDOR" or "exposed `.env` file" actually means. A template is what supplies that meaning — a short, readable recipe for one specific weakness on one kind of app: which URL to hit, what a "vulnerable" response looks like, what a "safe" response looks like. So the intuition is correct: build the tool once, then add a new template whenever we want to check for a new weakness or adapt to a new app — no rebuild, no new release, no code change.

  Why that split is worth the extra layer, rather than just hardcoding every check into the engine:
  - **New checks ship fast.** Adding a check is writing a YAML file, not writing and testing new Go code — turnaround for "can we also check for X" drops from a code change + release cycle to editing a text file.
  - **We don't have to invent detection knowledge from scratch.** The security community already maintains a large, actively updated library of these recipes (Nuclei's `nuclei-templates` project) covering thousands of known exposed panels, misconfigurations, and technology fingerprints. Because our engine speaks a compatible template format, we can pull in that existing, vetted work directly instead of re-researching and re-writing detection logic ourselves for everything that's already publicly known. Concretely, via `pkg/templatesync` and `hackerfive templates sync`/`list`: a `git`-based sparse-checkout of a maintainer-curated, deliberately **pinned commit** (never `HEAD`/latest — a compromised upstream commit landing between pins can't silently reach a scan) into a persistent per-user config directory (`os.UserConfigDir()`) that survives a binary upgrade with zero manual copying. `--templates` loads both this synced directory and the project-authored `templates/` bundled with each release, together — see [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md)'s "Template sync command" for the full design.
  - **Non-engineers can contribute checks.** A template is a readable text file, not a pull request against the scanner's internals — a security researcher who knows *what* to check for doesn't need to know Go, or how the scanner is built, to add *how* to check for it.
  - **One engine, many apps and many bug types.** The same underlying request/compare logic works for crAPI's IDOR bug, DVWA's exposed paths, or a future customer's app — what changes between them is only which template file is loaded, not the program itself.

- **Template Structure Example:**
  ```yaml
  id: idor-user-profile
  info:
    name: IDOR in User Profile Endpoint
    author: YourName
    severity: high
    description: Test if user IDs are sequentially enumerable
  tags:
    - idor
    - api

  variables:                    # global scope — set once, available to every request below
    base_path: /api/users

  requests:
    - method: POST              # request 1: log in, extract the token for request 2
      path: /api/auth/login
      body: '{"email":"{{Email}}","password":"{{Password}}"}'
      extractors:
        - type: json
          name: auth_token      # becomes {{auth_token}} in later requests — request-chain scope
          path: token           # JSON path into the response body

    - method: GET
      path: "{{base_path}}/{{RangeInt(1|100)}}"
      headers:
        Authorization: Bearer {{auth_token}}
      matchers:
        - type: status
          status: [200]
        - type: word
          words:
            - "email"
            - "name"
      condition: auth_token != ""   # skip this request if the login request above didn't produce a token
  ```
  - **Extractors** pull a value out of one request's response (regex, JSON path, header) and bind it to a name; later requests in the same template reference it as `{{name}}`. This is what makes request chaining (login → use token) work — see `pkg/template` in [09-implementation-plan-ph1a.md](09-implementation-plan-ph1a.md) for where this lands in the build order: the native YAML engine step in Phase 1b (see [03-development-roadmap.md](03-development-roadmap.md) for current week numbers), out of scope for Phase 1a's Weeks 1-4.
  - **Variable scope:** `variables:` at the template's top level is global (visible to every request); anything bound by an `extractors:` entry is chain-scoped — visible only to requests *after* the one that produced it, not before, and not across separate template files.
  - **Conditionals:** an optional `condition:` on a request is evaluated against already-bound variables before the request fires; a false condition skips that request entirely rather than sending it with an empty/broken value.
  - **Correction (Phase 1b Step 3, implemented):** the `tags: [idor, api]` on this example doesn't mean what it looks like it means once the engine actually exists. An `idor`-tagged template routes through the existing `idor.Detector` (baseline two-account comparison, tokens supplied externally via `--auth-token`/`--other-auth-token`, `{{RangeInt(min|max)}}` marking the enumerated ID) — it does **not** run its own login request or custom matchers; those are rejected at load time on an `idor`-tagged template instead of silently ignored. The login-then-probe pattern shown above is real and works, but only for a template **without** the `idor` tag (see `templates/idor/example.yaml`, and [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) Step 3 for the full reasoning) — `{{RangeInt(...)}}` enumeration specifically is `idor`-tagged-only machinery, not available to a generic template like this one.

  **In plain English, this template does the following:**
  - Step 1: log in with the credentials supplied on the command line (`{{Email}}` / `{{Password}}`) and pull the auth token out of the login response.
  - Step 2: pick a random ID between 1 and 100 (`RangeInt(1|100)`) and request that user's profile using the token from step 1 — i.e., "am I, as this logged-in user, able to view someone else's profile by guessing their ID?"
  - It only counts as a finding if the response comes back `200 OK` **and** contains fields like `email`/`name` — a redirect to a login page or an empty body doesn't match, which is what keeps false positives low.
  - The `condition` guard on request 2 means: if login failed and there's no token, skip the probe instead of sending a broken/unauthenticated request that could look like a false finding.
  - Nothing here writes or deletes target data — it's a read-only probe, consistent with the project's scan-only rule.

#### 3. **HTTP Client: Go Standard Library + Custom Middleware**
- Use Go's `net/http` for base functionality
- Add custom middleware for:
  - Request rate limiting
  - Automatic retry with backoff
  - Proxy support (for routing through Burp, MitmProxy)
  - Custom headers (User-Agent rotation, API keys)
  - Request/response logging
- **Host error cache:** track consecutive errors per host across a scan; once a host crosses an error threshold, skip further requests to it rather than continuing to hammer an unreachable or broken target for the rest of an ID-enumeration run

#### 4. **Concurrency Framework: Go Goroutines + Worker Pool**
- Implement configurable worker pool (default: 25 concurrent requests)
- Queue-based job distribution for targets and templates
- Progress tracking and cancellation support

#### 5. **Result Storage & Reporting**
- **Output Formats:**
  - JSON (for programmatic use)
  - Markdown (for GitHub issue templates)
  - HTML (for stakeholder reports)
  - HackerOne JSON schema (for platform integration)
- **Exporter interface:** one `Exporter` interface (`Export(*Finding) error`) with one implementation per format above — justified since multiple concrete formats are already planned (rule of three), not a speculative abstraction. No separate `Tracker`/issue-creation interface (GitHub, Jira, etc.) — HackerOne is the only external integration target (see [01-overview-and-strategy.md](01-overview-and-strategy.md)), and even that's report-drafting export, not live issue tracking.

- **Optional:** SQLite for local finding history

#### 6. **CLI Framework: Cobra (Go)**
- Standard command structure
- Flag parsing and validation
- Help documentation auto-generation

#### 7. **Web UI: Local-Only Embedded Server (Optional)**
- `hackerfive serve` runs a local, loopback-only-by-default web server (Go stdlib `net/http` + `html/template`, no separate frontend build/toolchain) over the same, unmodified Scanner Engine below — a second interface to the engine, not a second implementation of it. Never a substitute for the CLI: CI/scripted use and full-flag-control power users keep using `hackerfive scan` directly.
- Interactivity via **htmx** (vendored, `go:embed`-ed alongside the CLI into the same cross-compiled binary — no separate install step, no hosted/cloud mode) rather than a hand-rolled JS layer or a full SPA framework: server-rendered HTML stays the source of truth, form submits/live updates swap DOM fragments instead of full page reloads.
- Live findings/logs stream to the browser via Server-Sent Events, backed by `Engine`'s `WithFindingCallback`/`WithLogCallback` hooks (see Scanner Engine, below) — this is what "Callback-based streaming results," formerly listed under Future Considerations, actually became once something needed it.
- CSRF via a hand-rolled double-submit cookie (no third-party framework, consistent with the Minimal Dependencies stance below); a non-loopback bind requires a one-time bootstrap token, exchanged on first use for an `HttpOnly` session cookie.
- Full design in [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md).
- **Planned, not yet built: a third frontend for LLM agents.** [90-research-hackerbot.md](90-research-hackerbot.md) researched how other LLM-driven pentesting tools structure themselves and resolved the open design questions (a single coordinator, no shell/exec-shaped tool, MCP `elicitation`/`tasks` for human approval); [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md) and [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) schedule it as Phase 5-6. Like the Web UI, it's designed as a third frontend over this same unmodified Scanner Engine (an MCP server in `pkg/mcpserver/`, not a second implementation of it) — this section stays a stub rather than a full write-up until that phase actually ships, matching how this doc already treats Phase 4's still-unbuilt detectors.

#### 8. **Dependencies (Minimal)**
```
- github.com/spf13/cobra (CLI)
- gopkg.in/yaml.v3 (YAML parsing)
- github.com/json-iterator/go (fast JSON parsing)
- (Optional) github.com/chromedp/chromedp (for browser-based XSS validation)
```

Matcher/regex matching uses the standard library `regexp` (RE2) — it's arm64-native, avoids cgo, and keeps cross-compiled CI builds reproducible. (An earlier draft of this list named `github.com/valyala/fastregexp`, which does not exist as a published package — do not add it.) Only reach for a third-party engine such as `github.com/dlclark/regexp2` if a template genuinely needs PCRE-only features RE2 can't express (backreferences, lookahead).

The misconfig detector's templates are pulled from upstream `nuclei-templates`, whose own engine is Go's stdlib `regexp` — so every regex matcher that ships there is already RE2-safe by construction; no audit needed. The one place a PCRE-only pattern could actually show up is the HackerFive-native IDOR baseline-comparison format (no Nuclei equivalent, see template example above) — if a future IDOR regex matcher needs a backreference or lookahead, that's the trigger to add `regexp2` for that matcher only, not switch the whole engine.

#### 9. **Development Tools**
- **Testing:** Go's built-in `testing` package + testify for assertions; native `testing.F` fuzz targets for the HTTP client and response parsers (the scanner parses untrusted target responses, which is attack surface for the tool itself, not just the target)
- **Build:** a `Makefile` wrapping `build`/`test`/`lint`/`fuzz`/`integration` targets, so the commands used throughout this doc set have one canonical entry point instead of being copy-pasted per doc
- **Error handling:** wrap errors with context via stdlib `fmt.Errorf("...: %w", err)` and inspect with `errors.Is`/`errors.As` — no custom error-context package; that solves a debugging-at-scale problem this project doesn't have yet
- **Linting:** golangci-lint
- **Documentation:** MkDocs (similar to Nuclei docs)
- **CI/CD:** GitHub Actions
- **Docker:** Multi-stage build for production image
- **Releases:** goreleaser for cross-compiled Linux/macOS/Windows binaries, backing the installation guide in the Phase 1b packaging step. The Web UI's templates/CSS/JS are `go:embed`-ed into that same cross-compiled binary (see Web UI, above) — "update the web UI" and "update the CLI" are the same release action, no separate frontend deploy.

### Development & Testing Stack

| Component | Tool | Purpose |
|-----------|------|---------|
| **Vulnerable Targets** | crAPI, vAPI, DVWA, Juice Shop | Safe testing environment |
| **HTTP Interception** | Burp Suite Community, MitmProxy | Debug requests/responses |
| **API Testing** | Postman, Insomnia | Template development |
| **Fuzzing** | ffuf, OWASP ZAP | Discover endpoints |
| **Recon** | Subfinder, Assetfinder, Nmap | Asset discovery |
| **Version Control** | GitHub | Code, templates, issues |
| **Automation** | GitHub Actions | CI/CD, template validation |

## System Architecture

### High-Level Overview

```
┌───────────────────────────────┐   ┌──────────────────────────────────┐
│         HackerFive CLI         │   │   HackerFive Web UI (optional)    │
│  (hackerfive scan -t ...)      │   │  (hackerfive serve — htmx + SSE)  │
└────────────────┬────────────────┘   └────────────────┬───────────────┘
                 │                                      │
                 └──────────────────┬───────────────────┘
                                    │
      ┌──────────────┼──────────────┐
      │              │              │
   ┌──▼──┐       ┌───▼────┐    ┌───▼─────┐
   │Input│       │Recon   │    │Template │
   │Parse│       │Phase   │    │Parser   │
   └──┬──┘       └───┬────┘    └───┬─────┘
      │              │              │
      └──────────────┼──────────────┘
                     │
      ┌──────────────▼──────────────┐
      │   Scanner Engine (Core)     │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ IDOR Detector       │   │
      │  │ - ID enumeration    │   │
      │  │ - Response compare  │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Misconfiguration    │   │
      │  │ - Path matching     │   │
      │  │ - Header checks     │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Auth Bypass         │   │
      │  │ - JWT validation    │   │
      │  │ - Rate limiting     │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Template Runner     │   │
      │  │ - Matcher engine    │   │
      │  │ - Extractor engine  │   │
      │  └─────────────────────┘   │
      │                             │
      │  ┌─────────────────────┐   │
      │  │ Worker Pool         │   │
      │  │ - Concurrency ctrl  │   │
      │  │ - Rate limiting     │   │
      │  └─────────────────────┘   │
      └──────────────┬──────────────┘
                     │
      ┌──────────────┴──────────────┐
      │                             │
   ┌──▼──────┐            ┌────────▼──┐
   │Finding  │            │Reporter   │
   │Store    │            │(JSON/MD)  │
   └─────────┘            └───────────┘
```

### Key Modules

#### 1. **Input Parser**
- Accepts targets: `-t http://example.com` or `-l targets.txt`
- Supports templates: `-t IDOR_*.yaml` or `-t /path/to/templates`
- Options: rate limit, concurrency, proxy, headers, authentication

#### 2. **Recon Phase** (Optional, delegated to external tools)
- Subdomain enumeration (call Subfinder API or subprocess)
- Port discovery (call Nmap or Masscan)
- Tech stack detection (fingerprinting via HTTP headers)

#### 3. **Scanner Engine**
- **Detector Modules:** IDOR, Misconfiguration, Auth Bypass, etc.
- **Template Runner:** Parses YAML, executes requests, applies matchers
- **Matcher Engine:** Regex, word, status code, size, JSON extraction
- **Extractor Engine:** Pull dynamic values from responses for chaining requests
- **Streaming hooks:** optional `WithFindingCallback`/`WithLogCallback` on `Engine` — additive; the CLI's batch behavior (`Run` returning `([]Finding, error)` only once everything finishes) is unchanged when unset. The Web UI (below) is what actually consumes these, for live SSE updates mid-scan.

**Detector solutions, in plain English:**

- **IDOR Detector — "swap the ID, see what comes back."** Log in as one account, note what a normal response looks like, then request the same endpoint with a different object ID (another user's order, document, profile). If the response looks like real, authorized data (200 status, expected fields present) rather than a rejection (401/403, empty body, redirect to login), that's an access-control failure. Where possible this runs as a **two-account baseline comparison** (Account A's token accessing Account B's resource) rather than single-account ID guessing, which is what keeps the false-positive rate low — see the IDOR template example above and [01-overview-and-strategy.md](01-overview-and-strategy.md#1-idor-insecure-direct-object-reference).
- **Misconfiguration Detector — "check known-bad paths and settings."** No guessing or fuzzing: it requests a fixed list of paths/headers (`/.env`, `/.git`, missing `Content-Security-Policy`, wildcard CORS, etc.) and matches on status code + keyword/header presence. Because the checks are deterministic (a path either exposes `.env` or it doesn't), this is the lowest-effort, lowest-false-positive detector, and it runs almost entirely on templates pulled from the upstream `nuclei-templates` repo rather than custom Go code.
- **Auth Bypass Detector — "does the API enforce what it claims to enforce?"** A family of state-based checks rather than one technique: call an endpoint with no credentials at all (should reject, does it?), tamper with a JWT (strip the signature, flip `alg` to `none`), reuse one user's token against another user's session, or hammer a login endpoint to see if rate limiting actually kicks in. These require sequencing multiple requests and comparing outcomes, which is why this detector is rated medium-high automation difficulty in the roadmap.
- **Template Runner (shared by all detectors)** — the common execution engine: it reads the YAML request/matcher/extractor definitions, fires the HTTP requests through the worker pool, and hands each response to the matcher engine. Detector-specific logic (IDOR's two-account diffing, auth bypass's multi-step sequencing) sits on top of this shared runner rather than each detector reimplementing HTTP handling from scratch.

#### 4. **Concurrency Manager**
- Worker pool with configurable size
- Request queue with priority support
- Progress tracking and ETA calculation
- Graceful shutdown and signal handling

#### 5. **Result Aggregator**
- Deduplicates findings
- Severity scoring
- CVSS calculation (if applicable)
- Output formatting

## Future Considerations (Not Yet Scoped)

Deferred because the trigger condition for needing them hasn't happened yet — revisit if the trigger occurs, not on a fixed date.

- **In-memory template cache:** only pays off when the same process re-parses the same templates across multiple scan jobs — true for a long-running service, not a single-shot CLI invocation. No action unless HackerFive grows a persistent service mode, which isn't currently planned.
- **Template signing:** relevant once a community template repository actually accepts third-party submissions — no such milestone exists yet in [03-development-roadmap.md](03-development-roadmap.md). Premature while templates are either project-authored or pulled from the pinned upstream `nuclei-templates` commit.
- **Auto-generated `SYNTAX-REFERENCE.md` (docgen):** the hand-written template-writing guide (Phase 1b packaging step) covers this need for now. Auto-generation from code solves a scale-of-external-contributors problem this project doesn't have yet.

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — the detectors this architecture must support
- [03-development-roadmap.md](03-development-roadmap.md) — build order for these modules
- [12-implementation-plan-ph3.md](12-implementation-plan-ph3.md) — full Web UI and template-sync design behind the components summarized here
- [90-research-hackerbot.md](90-research-hackerbot.md), [14-implementation-plan-ph5.md](14-implementation-plan-ph5.md), [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) — planned MCP server / agent-integration design (Phase 5-6, not yet built) that will extend this architecture once that work starts
