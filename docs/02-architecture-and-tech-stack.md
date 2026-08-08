# Architecture & Technology Stack

> Part of the [VulnDetector documentation set](../README.md).

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
- **Why?**
  - Human-readable and maintainable
  - No programming knowledge required to write new checks
  - Supports community contribution model (like Nuclei)
  - Extensible matchers (regex, word, status code, JSON extraction)

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
  - **Extractors** pull a value out of one request's response (regex, JSON path, header) and bind it to a name; later requests in the same template reference it as `{{name}}`. This is what makes request chaining (login → use token) work — see `pkg/template` in [09-implementation-plan-ph1.md](09-implementation-plan-ph1.md) for where this lands in the build order: the native YAML engine step in Phase 1b (see [03-development-roadmap.md](03-development-roadmap.md) for current week numbers), out of scope for Phase 1a's Weeks 1-4.
  - **Variable scope:** `variables:` at the template's top level is global (visible to every request); anything bound by an `extractors:` entry is chain-scoped — visible only to requests *after* the one that produced it, not before, and not across separate template files.
  - **Conditionals:** an optional `condition:` on a request is evaluated against already-bound variables before the request fires; a false condition skips that request entirely rather than sending it with an empty/broken value.

#### 3. **HTTP Client: Go Standard Library + Custom Middleware**
- Use Go's `net/http` for base functionality
- Add custom middleware for:
  - Request rate limiting
  - Automatic retry with backoff
  - Proxy support (for routing through Burp, MitmProxy)
  - Custom headers (User-Agent rotation, API keys)
  - Request/response logging

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

- **Optional:** SQLite for local finding history

#### 6. **CLI Framework: Cobra (Go)**
- Standard command structure
- Flag parsing and validation
- Help documentation auto-generation

#### 7. **Dependencies (Minimal)**
```
- github.com/spf13/cobra (CLI)
- gopkg.in/yaml.v3 (YAML parsing)
- github.com/json-iterator/go (fast JSON parsing)
- (Optional) github.com/chromedp/chromedp (for browser-based XSS validation)
```

Matcher/regex matching uses the standard library `regexp` (RE2) — it's arm64-native, avoids cgo, and keeps cross-compiled CI builds reproducible. (An earlier draft of this list named `github.com/valyala/fastregexp`, which does not exist as a published package — do not add it.) Only reach for a third-party engine such as `github.com/dlclark/regexp2` if a template genuinely needs PCRE-only features RE2 can't express (backreferences, lookahead).

#### 8. **Development Tools**
- **Testing:** Go's built-in `testing` package + testify for assertions
- **Linting:** golangci-lint
- **Documentation:** MkDocs (similar to Nuclei docs)
- **CI/CD:** GitHub Actions
- **Docker:** Multi-stage build for production image

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
┌──────────────────────────────────────────────────────────────┐
│                    VulnDetector CLI                          │
│  (Command: vulndetector scan --targets urls.txt --templates) │
└────────────────────┬─────────────────────────────────────────┘
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

## See also
- [01-overview-and-strategy.md](01-overview-and-strategy.md) — the detectors this architecture must support
- [03-development-roadmap.md](03-development-roadmap.md) — build order for these modules
