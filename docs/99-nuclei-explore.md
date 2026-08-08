# Nuclei Repo Exploration — Findings

> Created: August 2026
> Source: https://github.com/projectdiscovery/nuclei

---

## 1. Project Structure

### Top-Level Layout
```
.github/              — CI/CD workflows
.run/                 — IDE run configurations
cmd/                  — CLI entry points
examples/             — Example templates
helm/                 — Kubernetes Helm chart
internal/             — Internal packages (not exported)
lib/                  — Library exports
pkg/                  — Core library (main package)
static/               — Static assets
```

### Key Files
- `DESIGN.md` — Architecture overview (documented)
- `CONTRIBUTING.md` — Contribution guidelines
- `SYNTAX-REFERENCE.md` — Template syntax reference
- `Makefile` — Build/test/lint commands
- `Dockerfile` — Multi-stage build
- `.goreleaser.yml` — Release automation
- `go.mod` — Module definition
- `nuclei-jsonschema.json` — Template JSON schema

### Package Layout (pkg/)
```
pkg/
├── catalog/          — Template path resolution
├── core/             — Engine (work pools, execution)
├── fuzz/             — Fuzzing engine
├── input/            — Input parsing
├── installer/        — Self-updater
├── keys/             — Template signing
├── model/            — Info/classification models
├── operators/        — Match/extract operators
├── output/           — Result writing
├── progress/         — Progress tracking
├── protocols/        — Protocol implementations (http, dns, tcp, etc.)
├── reporting/        — Exporters (Elasticsearch, Jira, GitHub, GitLab, Markdown, SARIF)
├── scan/             — Scanning utilities
├── templates/        — Template parsing, compilation, clustering
├── tmplexec/         — Template execution (Generic, MultiProtocol, Flow)
├── types/            — Core types (Options, etc.)
├── utils/            — Utilities
└── workflows/        — Workflow compilation
```

---

## 2. Best Practices Found

### 2.1 Build System (Makefile)

**Findings:**
- Uses `CGO_ENABLED=0` for static binaries (no CGO dependencies)
- Uses `-trimpath` for reproducible builds
- Uses `-ldflags '-s -w'` for stripped binaries (smaller, faster)
- Uses `-pgo=auto` for profile-guided optimization
- Separate targets: `build`, `test`, `integration`, `fuzz`, `lint`, `docs`
- `test` runs with `-race` flag (data race detection)
- `integration` uses build tags (`-tags=integration`)
- `fuzz` targets for fuzzing support

**Relevant to VulnDetector:**
- ✅ Your Dockerfile should use `CGO_ENABLED=0` for static binaries
- ✅ Use `-trimpath` and `-ldflags '-s -w'` for production builds
- ✅ Use `-race` in CI tests
- ✅ Use build tags for integration tests (`-tags=integration`)
- ✅ Have separate `make test`, `make lint`, `make build` targets

### 2.2 Go Module (go.mod)

**Findings:**
- Uses Go 1.21+ minimum version
- Uses `github.com/projectdislibrary/*` internal packages (monorepo)
- Uses `github.com/projectdiscovery/gologger` for logging
- Uses `github.com/projectdiscovery/utils` for shared utilities
- Uses `github.com/projectdiscovery/fastdialer` for HTTP
- Uses `github.com/projectdiscovery/retry-go` for retries
- Uses `github.com/projectdiscovery/mapcid` for CIDR utilities

**Relevant to VulnDetector:**
- ✅ Consider a monorepo with shared internal packages (internal/)
- ✅ Use Go 1.21+ minimum
- ✅ Use structured logging (not fmt.Printf)

### 2.3 CLI Structure (cmd/)

**Findings:**
- `cmd/nuclei/main.go` — Thin entrypoint
- `cmd/nuclei/root.go` — Root command (Cobra)
- Multiple subcommands (scan, docgen, etc.)
- Uses Cobra for CLI framework
- Uses flags for configuration
- Uses environment variables for sensitive data

**Relevant to VulnDetector:**
- ✅ Your CLI structure (cmd/vulndetector/main.go, root.go, scan.go) matches this pattern
- ✅ Use Cobra for CLI (already planned)
- ✅ Use flags for configuration
- ✅ Use environment variables for sensitive data (already planned)

### 2.4 Architecture (DESIGN.md)

**Key patterns found:**

**A. Interface-Based Design**
```go
// Request interface (protocol abstraction)
type Request interface {
    Compile(options *ExecuterOptions) error
    Requests() int
    GetID() string
    Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)
    Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
    ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback OutputEventCallback) error
    MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent
    MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent
    GetCompiledOperators() []*operators.Operators
}

// Executer interface (execution abstraction)
type Executer interface {
    Compile() error
    Requests() int
    Execute(input string) (bool, error)
    ExecuteWithResults(input string, callback OutputEventCallback) error
}

// Tracker interface (issue tracker abstraction)
type Tracker interface {
    CreateIssue(event *output.ResultEvent) error
}

// Exporter interface (result exporter abstraction)
type Exporter interface {
    Close() error
    Export(event *output.ResultEvent) error
}

// Writer interface (output abstraction)
type Writer interface {
    Close()
    Colorizer() aurora.Aurora
    Write(*ResultEvent) error
    Request(templateID, url, requestType string, err error)
}

// Preprocessor interface (template preprocessing)
type Preprocessor interface {
    Process(data []byte) []byte
}

// WorkflowLoader interface (workflow loading)
type WorkflowLoader interface {
    GetTemplatePathsByTags(tags []string) []string
    GetTemplatePaths(templatesList []string, noValidate bool) []string
}
```

**B. Callback-Based Results**
- Results flow through callbacks (not returned directly)
- `OutputEventCallback` receives results during execution
- Allows real-time processing and streaming

**C. Modular Exporters/Trackers**
- Each exporter (Elasticsearch, Markdown, SARIF) is a separate implementation
- Each tracker (GitHub, GitLab, Jira) is a separate implementation
- Easy to add new ones without modifying core

**D. Protocol Abstraction**
- HTTP, DNS, TCP, SSL, WebSocket, Headless, etc. all implement `Request` interface
- Protocol-specific logic is isolated
- Common logic is in `pkg/protocols/common/`

**E. Template Compilation**
- Templates are parsed and compiled at startup
- Compilation includes validation, request generation, operator compilation
- In-memory cache for templates (reuses compiled templates)

**F. Host Error Cache**
- Tracks errors per host
- Skips further requests if errors exceed threshold
- Prevents wasting resources on unreachable hosts

**G. Interactsh Integration**
- Automatic out-of-band vulnerability identification
- Uses LRU caches for interaction URLs and request URLs
- Correlates requests with OOB server interactions

**Relevant to VulnDetector:**
- ✅ Use interfaces for protocol abstraction (HTTP, WebSocket, etc.)
- ✅ Use callback-based result handling (streaming results)
- ✅ Use modular exporters (JSON, Markdown, HackerOne schema)
- ✅ Use modular trackers (GitHub, Jira, HackerOne API)
- ✅ Use template compilation at startup (parse once, execute many times)
- ✅ Use in-memory cache for templates
- ✅ Use host error cache (skip unreachable hosts)
- ✅ Use callback services for blind vulnerabilities (Interactsh for SSRF)

### 2.5 Error Handling

**Findings:**
- Uses `github.com/projectdiscovery/utils/errkit` for structured errors
- Errors carry context (file, line, message)
- Errors can be wrapped/unwrapped
- Errors are logged with file/line context

**Relevant to VulnDetector:**
- ✅ Use structured error handling with context
- ✅ Log errors with file/line information
- ✅ Wrap errors for better debugging

### 2.6 Testing

**Findings:**
- Unit tests with `go test ./...`
- Integration tests with `-tags=integration`
- Fuzzing tests with `make fuzz`
- Regression tests for HTTP engine scale
- Benchmarks for throughput
- Race detection with `-race`

**Relevant to VulnDetector:**
- ✅ Your testing plan (unit, integration, fuzzing, benchmarks) matches this
- ✅ Use `-race` flag in CI
- ✅ Use build tags for integration tests
- ✅ Add fuzzing targets for HTTP client

### 2.7 Documentation

**Findings:**
- `DESIGN.md` — Architecture overview (living document)
- `SYNTAX-REFERENCE.md` — Template syntax (auto-generated from code)
- `CONTRIBUTING.md` — Contribution guidelines
- `README.md` — Getting started
- Documentation auto-generated from code (`go generate`)

**Relevant to VulnDetector:**
- ✅ Create `DESIGN.md` for architecture overview
- ✅ Auto-generate template syntax documentation from code
- ✅ Create `CONTRIBUTING.md` for community contributions
- ✅ Keep documentation in sync with code

### 2.8 CI/CD

**Findings:**
- GitHub Actions for CI
- Separate workflows for:
  - `test` — Unit tests with race detection
  - `integration` — Integration tests
  - `lint` — Code linting
  - `build` — Release builds
  - `goreleaser` — Release automation
- Uses `goreleaser` for multi-platform releases
- Uses Docker for container builds

**Relevant to VulnDetector:**
- ✅ Your CI/CD plan (GitHub Actions) matches this
- ✅ Add separate workflows for test, integration, lint, build
- ✅ Use `goreleaser` for multi-platform releases
- ✅ Use multi-stage Docker builds

### 2.9 Security

**Findings:**
- Template signing (cryptographic verification)
- Unsigned template blocking (`-disable-unsigned-templates`)
- Host error cache (skip hosts with too many errors)
- Rate limiting (configurable QPS)
- Proxy support (SOCKS5, HTTP)
- User-Agent rotation

**Relevant to VulnDetector:**
- ✅ Consider template signing for security
- ✅ Implement host error cache (skip unreachable hosts)
- ✅ Implement rate limiting (configurable QPS)
- ✅ Implement proxy support (SOCKS5, HTTP)
- ✅ Implement User-Agent rotation

---

## 3. Gaps vs. VulnDetector (Docs 02 & 09)

### 3.1 Missing in VulnDetector Docs

| Nuclei Pattern | Status in VulnDetector | Recommendation |
|----------------|----------------------|----------------|
| **Interface-based design** | Partially (Engine, Detector) | Add interfaces for: Exporter, Tracker, Protocol, ResultHandler |
| **Callback-based results** | Not mentioned | Add callback pattern for streaming results |
| **Modular exporters** | Mentioned (JSON, Markdown) | Add interface + examples (HackerOne, Jira, GitHub) |
| **Modular trackers** | Not mentioned | Add interface + examples (GitHub, Jira, HackerOne API) |
| **Template compilation** | Partially (YAML parser) | Add compilation phase (parse once, execute many) |
| **In-memory cache** | Not mentioned | Add template cache for reuse |
| **Host error cache** | Not mentioned | Add error tracking per host |
| **Interactsh integration** | Partially (SSRF) | Add callback service integration (Interactsh) |
| **Structured errors** | Not mentioned | Use structured error handling with context |
| **Template signing** | Not mentioned | Consider for security (optional) |
| **Fuzzing tests** | Not mentioned | Add fuzzing targets |
| **Auto-generated docs** | Not mentioned | Add `go generate` for docs |
| **Multi-platform releases** | Not mentioned | Add `.goreleaser.yml` |
| **Progress/ETA tracking** | Not mentioned | Add progress tracking |

### 3.2 Docs 02 Recommendations

**Architecture doc (02-architecture-and-tech-stack.md) should add:**

1. **Interface definitions** (like Nuclei's Request, Executer, Tracker, Exporter)
2. **Callback pattern** for results (streaming, not batch)
3. **Modular exporter/tracker design** (add interfaces)
4. **Template compilation phase** (parse → compile → execute)
5. **In-memory template cache**
6. **Host error cache** (skip unreachable hosts)
7. **Interactsh integration** (for blind SSRF detection)
8. **Progress/ETA tracking**

### 3.3 Docs 09 Recommendations

**Implementation plan (09-implementation-plan-ph1.md) should add:**

1. **Interface definitions** for Phase 1b (Exporter, Tracker, ResultHandler)
2. **Callback pattern** for IDOR detector results
3. **Template compilation** (parse → compile → execute)
4. **In-memory cache** for templates
5. **Host error cache** (skip hosts with errors)
6. **Fuzzing targets** for HTTP client
7. **Auto-generated docs** (template syntax)
8. **Multi-platform release** (`.goreleaser.yml`)

---

## 4. Summary: Top 10 Best Practices to Adopt

| # | Best Practice | Priority | Docs 02 | Docs 09 |
|---|--------------|----------|---------|---------|
| 1 | **Interface-based design** (Request, Executer, Exporter, Tracker) | High | Add interfaces | Add interface definitions |
| 2 | **Callback-based results** (streaming) | High | Add callback pattern | Add callback to IDOR |
| 3 | **Modular exporters/trackers** (add interfaces) | High | Add interface + examples | Add interface definitions |
| 4 | **Template compilation phase** (parse → compile → execute) | High | Add compilation phase | Add compilation step |
| 5 | **In-memory template cache** | Medium | Add cache design | Add cache implementation |
| 6 | **Host error cache** (skip unreachable hosts) | Medium | Add cache design | Add cache implementation |
| 7 | **Structured error handling** (with context) | Medium | Add error design | Add error handling |
| 8 | **Interactsh integration** (blind SSRF) | Medium | Add integration design | Add Interactsh client |
| 9 | **Fuzzing tests** (HTTP client) | Medium | Add fuzzing plan | Add fuzzing targets |
| 10 | **Auto-generated docs** (template syntax) | Low | Add docgen plan | Add docgen step |

---

## 6. Comparison: Nuclei Best Practices vs. VulnDetector (Docs 02 & 09)

### 6.1 What VulnDetector Already Does Well

| Nuclei Practice | Status in VulnDetector | Notes |
|----------------|----------------------|-------|
| **Go 1.21+** | ✅ | Same minimum version |
| **Cobra CLI** | ✅ | Same CLI framework (cmd/vulndetector/main.go, root.go, scan.go) |
| **Thin entrypoint** | ✅ | main.go calls into root Cobra command |
| **Flags for config** | ✅ | --proxy, --timeout, --output, --auth-token, etc. |
| **Env vars for secrets** | ✅ | VULNDECTOR_AUTH_TOKEN, VULNDETECTOR_OTHER_AUTH_TOKEN |
| **Worker pool** | ✅ | Fixed-size pool for concurrent requests |
| **Rate limiting** | ✅ | Token-bucket (golang.org/x/time/rate) |
| **Proxy support** | ✅ | SOCKS5, HTTP |
| **User-Agent rotation** | ✅ | Custom headers |
| **Request templating** | ✅ | {{BaseURL}}, {{RangeInt}}, {{Var}} |
| **Extractors** | ✅ | JSON, regex — request chaining |
| **Matchers** | ✅ | Status, word, regex, size, JSON |
| **Conditionals** | ✅ | Skip requests if preconditions not met |
| **Unit tests** | ✅ | Table-driven tests, httptest.Server |
| **Integration tests** | ✅ | Build tags (-tags=integration), crAPI |
| **Race detection** | ✅ | -race flag in CI |
| **Benchmarks** | ✅ | Throughput tests (150+ req/sec) |
| **Docker** | ✅ | Multi-stage build (planned for Phase 1b) |
| **CI/CD** | ✅ | GitHub Actions (go test, go vet, golangci-lint) |
| **Static binary** | ✅ | CGO_ENABLED=0 (planned for Phase 1b) |
| **IDOR baseline mode** | ✅ | Two-account comparison (high-confidence) |
| **IDOR heuristic mode** | ✅ | Single-token fallback (low-confidence) |
| **Read-only scanner** | ✅ | GET only, no state-mutating verbs |
| **No hardcoded secrets** | ✅ | Auth from flags/env vars only |

### 6.2 Triaged Gaps (Adopt / Future / Ignore)

This section was originally a raw diff against docs 02 and 09 only, importing Nuclei's architecture wholesale. After reviewing against docs 01 and 03 as well, here is the corrected triage:

#### ADOPT NOW (cheap, concretely useful, fits already-planned work)

| # | Nuclei Practice | Status | Where | Why |
|---|----------------|--------|-------|-----|
| 6 | **Host error cache** (skip a host after N consecutive errors) | ❌ → ✅ | Phase 1a, Step 2 (Week 2-3) | During IDOR's sequential-ID enumeration, a struggling/dead target shouldn't get hammered for the rest of the ID range. Performance win + good-citizen/non-destructive-scanning (CLAUDE.md's read-only ethos). |
| 13 | **Makefile** (build/test/lint/fuzz targets) | ❌ → ✅ | Phase 1a, Step 1 (Week 1-2) | Trivial. Formalizes commands already spelled out in prose in 09-implementation-plan-ph1.md. No reason not to. |
| 3a | **Exporter interface only** (part of Gap 3) | ❌ → ✅ | Phase 1a, Step 1 (Week 1-2) | Rule of three: three concrete formats already planned (JSON, Markdown, HackerOne JSON schema). Just the interface + three implementations. Reject the accompanying Tracker interface (GitHub/Jira/HackerOne-API-as-issue-tracker) — that's multi-platform integration scope already declined. |
| 9 | **Fuzzing tests** (HTTP client/response parser) | ❌ → ✅ | Phase 1a, Step 2 (Week 2-3) | Go's stdlib testing.F fuzzing is free and directly relevant: the scanner parses untrusted responses from targets, which is real attack surface for the tool itself. |
| 15 | **CONTRIBUTING.md** | ❌ → ✅ | Phase 1b, Week 9-10 | Phase 1b already plans "issue/PR templates for GitHub"; this just names the missing companion doc for that already-budgeted work. |
| 7 | **Structured, wrapped errors** (Go stdlib) | ❌ → ✅ | Phase 1a, Step 1 (Week 1-2) | Adopt the principle (contextual, wrapped errors) using Go's stdlib (`fmt.Errorf("%w", ...)`, `errors.Is/As`). Reject the proposed custom errkit-style package with file/line tracking — that solves a debugging-at-scale problem for a project with hundreds of contributors, not a 3-person MVP. |
| 11 | **goreleaser for multi-platform builds** | ❌ → ✅ | Phase 1b, Week 9-10 | Week 9-10 already plans an installation guide for Linux/macOS/Windows; goreleaser is just the tool to produce those binaries, not new scope. |

#### FUTURE / BACKLOG (real ideas, wrong time)

| # | Nuclei Practice | Status | When to revisit | Why not now |
|---|----------------|--------|-----------------|-------------|
| 2 | **Callback/streaming results** | ❌ | Once scans run long enough that batch-at-the-end output is a UX problem | Not yet at Phase 1a's single-target-validation scale |
| 5 | **In-memory template cache** | ❌ | Only if a persistent service is ever built (explicitly declined) | VulnDetector is a single-shot CLI; there's no second scan job in the same process to cache for |
| 17 | **Template signing** | ❌ | Once the "community template repository" (Milestone 4 / Phase 3 Week 26) actually accepts third-party submissions | Premature while templates are project-authored |
| 12 | **Progress/ETA tracking** | ❌ | Phase 2+ | Nice CLI polish, not a correctness or differentiation item |
| 10 | **SYNTAX-REFERENCE.md** | ❌ | Never (write by hand) | Write it by hand as part of the already-planned "template writing guide" (Week 9-10). Skip the docgen/auto-generation tooling — that solves a scale-of-contributors problem you don't have |

#### IGNORE (over-engineered, out of scope, or already covered)

| # | Nuclei Practice | Status | Why |
|---|----------------|--------|-----|
| 1 | **Full interface zoo** (Request/Executer/Writer/Preprocessor/WorkflowLoader) | ❌ Ignore | Premature abstraction: Nuclei needs it for 28+ protocols and a workflow-orchestration feature; VulnDetector is HTTP-only through Phase 3 by explicit design, and has no multi-template workflow feature planned. Conflicts with this project's own stated principle against designing for hypothetical future requirements. |
| (Protocol abstraction) | **Protocol abstraction layer** | ❌ Ignore | Moot given decision to explicitly reject non-HTTP protocol templates (code:/javascript:/headless:/file:) for security reasons. Building an abstraction for protocols you've already decided to refuse is pure waste. |
| 4 | **Elaborate template "compilation phase"** | ❌ Ignore | Parse-once-at-load-time is already the implicit design; a formal multi-stage compiler is solving a problem that matters at Nuclei's scale (thousands of templates, repeated compilation across scan jobs), not ~50-70 templates parsed once per CLI invocation. |
| 14 | **DESIGN.md** | ❌ Ignore | Redundant. 02-architecture-and-tech-stack.md already IS the architecture doc; adding a second one is a maintenance liability (two docs to keep in sync — exactly the drift problem we just spent an entire pass fixing for week numbers). |
| 8 | **Interactsh integration** | ❌ Not a gap | Already in 03-development-roadmap.md Phase 3 Week 21-22 ("Integration with Interactsh or similar callback service"). The exploration doc missed it because it only checked docs 02/09. |

### 6.3 Detailed Gap Analysis

#### Gap 1: Interface Definitions (High Priority)

**Nuclei's approach:**
```go
// Request interface (protocol abstraction)
type Request interface {
    Compile(options *ExecuterOptions) error
    Requests() int
    GetID() string
    Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)
    Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
    ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback OutputEventCallback) error
    MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent
    MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent
    GetCompiledOperators() []*operators.Operators
}

// Executer interface (execution abstraction)
type Executer interface {
    Compile() error
    Requests() int
    Execute(input string) (bool, error)
    ExecuteWithResults(input string, callback OutputEventCallback) error
}

// Tracker interface (issue tracker abstraction)
type Tracker interface {
    CreateIssue(event *output.ResultEvent) error
}

// Exporter interface (result exporter abstraction)
type Exporter interface {
    Close() error
    Export(event *output.ResultEvent) error
}

// Writer interface (output abstraction)
type Writer interface {
    Close()
    Colorizer() aurora.Aurora
    Write(*ResultEvent) error
    Request(templateID, url, requestType string, err error)
}

// Preprocessor interface (template preprocessing)
type Preprocessor interface {
    Process(data []byte) []byte
}

// WorkflowLoader interface (workflow loading)
type WorkflowLoader interface {
    GetTemplatePathsByTags(tags []string) []string
    GetTemplatePaths(templatesList []string, noValidate bool) []string
}
```

**VulnDetector's current state:** No interfaces defined. Everything is concrete structs.

**Recommendation:** Add interfaces for:
- `Protocol` (HTTP, WebSocket — like Nuclei's Request interface)
- `Exporter` (JSON, Markdown, HackerOne schema — like Nuclei's Exporter)
- `Tracker` (GitHub, Jira, HackerOne API — like Nuclei's Tracker)
- `Writer` (stdout, file, callback — like Nuclei's Writer)
- `ResultHandler` (callback for streaming results — like Nuclei's OutputEventCallback)

**Impact on Docs 02:** Add interface definitions section after "Key Modules"
**Impact on Docs 09:** Add interface stubs in Step 1 (Phase 1a) and implementations in Step 3 (Phase 1b)

#### Gap 2: Callback-Based Results (High Priority)

**Nuclei's approach:**
- Results flow through callbacks (not returned directly)
- `OutputEventCallback` receives results during execution
- Allows real-time processing and streaming
- Results are `*output.InternalWrappedEvent` (intermediate format)
- Final results are `*output.ResultEvent` (user-facing format)

**VulnDetector's current state:** Results are returned as `[]detectors.Finding` (batch, not streaming).

**Recommendation:** Add callback pattern for streaming results:
```go
// Callback for streaming results (like Nuclei's OutputEventCallback)
type ResultCallback func(*Finding) error
```

**Impact on Docs 02:** Add callback pattern to "Result Storage & Reporting" section
**Impact on Docs 09:** Add callback to IDOR detector (Step 3) — emit findings as they're found, not at the end

#### Gap 3: Modular Exporters/Trackers (High Priority)

**Nuclei's approach:**
- Each exporter (Elasticsearch, Markdown, SARIF, JSON) is a separate implementation
- Each tracker (GitHub, GitLab, Jira) is a separate implementation
- Easy to add new ones without modifying core
- Configuration in YAML format

**VulnDetector's current state:** Exporters are mentioned (JSON, Markdown, HTML, HackerOne JSON schema) but no interfaces or modular design.

**Recommendation:** Add modular exporter/tracker design:
```go
// Exporter interface (like Nuclei's Exporter)
type Exporter interface {
    Close() error
    Export(*Finding) error
}

// Tracker interface (like Nuclei's Tracker)
type Tracker interface {
    CreateIssue(*Finding) error
}
```

**Impact on Docs 02:** Add interface definitions + examples (JSON, Markdown, HackerOne schema as Exporters; GitHub, Jira, HackerOne API as Trackers)
**Impact on Docs 09:** Add interface definitions in Step 1 (Phase 1a) and implementations in Step 3 (Phase 1b)

#### Gap 4: Template Compilation Phase (High Priority)

**Nuclei's approach:**
- Templates are parsed and compiled at startup
- Compilation includes validation, request generation, operator compilation
- In-memory cache for templates (reuses compiled templates)
- `Parse` function is the main entry point — returns a template for a `filePath` and `executorOptions`

**VulnDetector's current state:** Templates are parsed on-the-fly (no compilation phase).

**Recommendation:** Add template compilation phase:
```go
// Template compilation (like Nuclei's Parse function)
type Template struct {
    ID          string
    Info        Info
    Requests    []Request
    Matchers    []Matcher
    Extractors  []Extractor
    compiled    *compiledTemplate // internal, compiled form
}

// Parse compiles a template (like Nuclei's Parse function)
func Parse(filePath string, options *Options) (*Template, error)
```

**Impact on Docs 02:** Add template compilation phase to "System Architecture" section
**Impact on Docs 09:** Add compilation step to Phase 1b (Weeks 6-7 for Nuclei-compatible parser, Weeks 7-8 for native YAML engine)

#### Gap 5: In-Memory Template Cache (Medium Priority)

**Nuclei's approach:**
- In-memory cache for templates (reuses compiled templates)
- Avoids re-parsing/compiling the same template

**VulnDetector's current state:** No cache.

**Recommendation:** Add template cache:
```go
// Template cache (like Nuclei's cache)
type TemplateCache struct {
    templates map[string]*Template
    mu        sync.RWMutex
}

func (c *TemplateCache) Get(id string) (*Template, bool)
func (c *TemplateCache) Set(id string, t *Template)
```

**Impact on Docs 02:** Add cache design to "System Architecture" section
**Impact on Docs 09:** Add cache implementation to Phase 1b (Weeks 6-7)

#### Gap 6: Host Error Cache (Medium Priority)

**Nuclei's approach:**
- Tracks errors per host
- Skips further requests if errors exceed threshold
- Prevents wasting resources on unreachable hosts

**VulnDetector's current state:** No error cache.

**Recommendation:** Add host error cache:
```go
// Host error cache (like Nuclei's HostErrorsCache)
type HostErrorsCache struct {
    errors map[string]int
    mu     sync.RWMutex
}

func (c *HostErrorsCache) Increment(host string) int
func (c *HostErrorsCache) ShouldSkip(host string) bool
```

**Impact on Docs 02:** Add cache design to "System Architecture" section
**Impact on Docs 09:** Add cache implementation to Phase 1b (Weeks 6-7)

#### Gap 7: Structured Error Handling (Medium Priority)

**Nuclei's approach:**
- Uses `github.com/projectdiscovery/utils/errkit` for structured errors
- Errors carry context (file, line, message)
- Errors can be wrapped/unwrapped
- Errors are logged with file/line context

**VulnDetector's current state:** No structured error handling.

**Recommendation:** Add structured error handling:
```go
// Structured error (like Nuclei's errkit)
type Error struct {
    File    string
    Line    int
    Message string
    Cause   error
}

func (e *Error) Error() string
func (e *Error) Unwrap() error
```

**Impact on Docs 02:** Add error handling design to "Technology Stack" section
**Impact on Docs 09:** Add error handling to Step 1 (Phase 1a)

#### Gap 8: Interactsh Integration (Medium Priority)

**Nuclei's approach:**
- Automatic out-of-band vulnerability identification
- Uses LRU caches for interaction URLs and request URLs
- Correlates requests with OOB server interactions
- Interactsh Client package does most of the heavy lifting

**VulnDetector's current state:** Mentioned in Phase 3 (SSRF) but no design.

**Recommendation:** Add Interactsh integration design:
```go
// Interactsh client (like Nuclei's Interactsh Client)
type InteractshClient struct {
    server string
    client *interactsh.Client
}

func (c *InteractshClient) Register() (string, error)
func (c *InteractshClient) Poll() ([]*Interaction, error)
```

**Impact on Docs 02:** Add integration design to "System Architecture" section
**Impact on Docs 09:** Add Interactsh client to Phase 3 (Weeks 21-22)

#### Gap 9: Fuzzing Tests (Medium Priority)

**Nuclei's approach:**
- Fuzzing targets for HTTP client
- `make fuzz` for fuzzing
- Regression tests for HTTP engine scale

**VulnDetector's current state:** No fuzzing tests.

**Recommendation:** Add fuzzing targets:
```go
// Fuzzing target (like Nuclei's fuzzing)
func FuzzHTTPClient(f *testing.F) {
    // Add seed corpus
    f.Add("http://example.com", "GET", "/")
    f.Add("http://example.com", "POST", "/api")
    // Run fuzzer
}
```

**Impact on Docs 02:** Add fuzzing plan to "Development Tools" section
**Impact on Docs 09:** Add fuzzing targets to Phase 1b (Week 8-9)

#### Gap 10: Auto-Generated Docs (Low Priority)

**Nuclei's approach:**
- `SYNTAX-REFERENCE.md` — Template syntax (auto-generated from code)
- `go generate` for documentation
- `docgen` tool for generating docs from code

**VulnDetector's current state:** No auto-generated docs.

**Recommendation:** Add auto-generated docs:
```bash
# Generate docs from code (like Nuclei's docgen)
go generate ./pkg/templates/...
```

**Impact on Docs 02:** Add docgen plan to "Development Tools" section
**Impact on Docs 09:** Add docgen step to Phase 1b (Week 9-10)

#### Gap 11: Multi-Platform Releases (Low Priority)

**Nuclei's approach:**
- `.goreleaser.yml` for release automation
- Multi-platform releases (Linux, macOS, Windows)
- Docker images for each platform

**VulnDetector's current state:** No multi-platform releases.

**Recommendation:** Add multi-platform releases:
```yaml
# .goreleaser.yml (like Nuclei's)
builds:
  - main: ./cmd/vulndetector/main.go
    targets:
      - linux/amd64
      - linux/arm64
      - darwin/amd64
      - darwin/arm64
      - windows/amd64
```

**Impact on Docs 02:** Add build plan to "Development Tools" section
**Impact on Docs 09:** Add release step to Phase 1b (Week 9-10)

#### Gap 12: Progress/ETA Tracking (Low Priority)

**Nuclei's approach:**
- Progress tracking (requests sent, found, ETA)
- ETA calculation based on progress

**VulnDetector's current state:** No progress/ETA tracking.

**Recommendation:** Add progress tracking:
```go
// Progress tracker (like Nuclei's progress)
type Progress struct {
    Total     int
    Current   int
    Found     int
    ETA       time.Duration
}

func (p *Progress) Update(total, current, found int)
```

**Impact on Docs 02:** Add progress design to "Concurrency Manager" section
**Impact on Docs 09:** Add progress tracking to Step 2 (Phase 1a)

#### Gap 13: Makefile (Medium Priority)

**Nuclei's approach:**
- Comprehensive Makefile with build, test, lint, fuzz targets
- Uses `CGO_ENABLED=0` for static binaries
- Uses `-trimpath` for reproducible builds
- Uses `-ldflags '-s -w'` for stripped binaries
- Uses `-pgo=auto` for profile-guided optimization
- Separate targets for: `build`, `test`, `integration`, `fuzz`, `lint`, `docs`

**VulnDetector's current state:** No Makefile (just manual commands).

**Recommendation:** Add Makefile:
```makefile
# Makefile (like Nuclei's)
build:
    CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o ./bin/vulndetector ./cmd/vulndetector

test:
    go test -race -v ./...

integration:
    go test -tags=integration -v ./...

lint:
    golangci-lint run ./...

fuzz:
    go test -fuzz=FuzzHTTPClient -fuzztime=15m ./pkg/scanner/httpclient/...
```

**Impact on Docs 02:** Add Makefile design to "Development Tools" section
**Impact on Docs 09:** Add Makefile to Step 1 (Phase 1a)

#### Gap 14: DESIGN.md (Low Priority)

**Nuclei's approach:**
- `DESIGN.md` — Architecture overview (living document)
- Documents all interfaces, patterns, and design decisions

**VulnDetector's current state:** No DESIGN.md.

**Recommendation:** Create DESIGN.md:
```markdown
# VulnDetector Design Document

## Architecture Overview
- CLI (Cobra)
- Scanner Engine (Core)
- Detector Modules (IDOR, Misconfiguration, Auth Bypass, etc.)
- Template Runner (Parses YAML, executes requests, applies matchers)
- Matcher Engine (Regex, word, status code, size, JSON extraction)
- Extractor Engine (Pull dynamic values from responses for chaining requests)
- Worker Pool (Configurable size, request queue with priority support)
- Result Aggregator (Deduplicates findings, severity scoring, CVSS calculation)
```

**Impact on Docs 02:** Create DESIGN.md (new file, referenced from 02)
**Impact on Docs 09:** N/A (documentation only)

#### Gap 15: CONTRIBUTING.md (Low Priority)

**Nuclei's approach:**
- `CONTRIBUTING.md` — Contribution guidelines
- Documents how to contribute (PR process, code style, testing)

**VulnDetector's current state:** No CONTRIBUTING.md.

**Recommendation:** Create CONTRIBUTING.md:
```markdown
# Contributing to VulnDetector

## Getting Started
- Always base your work from the `dev` branch
- Before creating a PR, make sure there is a corresponding issue
- Include the problem description in the issue

## Pull Requests
- Link your PR to the corresponding issue
- Provide context in the PR description
- Include an example of running the tool with the changed code
- Include steps for functional testing or replication
- If you're adding a new feature, make sure to include unit tests

## Code Style
- Adhere to the existing coding style
- Run `make test`, `make vet`, `make build` before submitting
```

**Impact on Docs 02:** Create CONTRIBUTING.md (new file, referenced from 02)
**Impact on Docs 09:** N/A (documentation only)

#### Gap 16: SYNTAX-REFERENCE.md (Low Priority)

**Nuclei's approach:**
- `SYNTAX-REFERENCE.md` — Template syntax (auto-generated from code)
- Documents all template fields, matchers, extractors, etc.

**VulnDetector's current state:** No SYNTAX-REFERENCE.md.

**Recommendation:** Auto-generate SYNTAX-REFERENCE.md:
```bash
# Generate syntax reference from code (like Nuclei's docgen)
go generate ./pkg/templates/...
```

**Impact on Docs 02:** Add docgen plan to "Development Tools" section
**Impact on Docs 09:** Add docgen step to Phase 1b (Week 9-10)

#### Gap 17: Template Signing (Low Priority)

**Nuclei's approach:**
- Template signing (cryptographic verification)
- Unsigned template blocking (`-disable-unsigned-templates`)
- Ensures templates haven't been tampered with

**VulnDetector's current state:** No template signing.

**Recommendation:** Consider template signing (optional, low priority):
```go
// Template signing (like Nuclei's template signing)
type TemplateSigner struct {
    privateKey []byte
}

func (s *TemplateSigner) Sign(t *Template) ([]byte, error)
func (s *TemplateSigner) Verify(t *Template, signature []byte) bool
```

**Impact on Docs 02:** Add signing design to "Technology Stack" section (optional)
**Impact on Docs 09:** Add signing implementation to Phase 1b (Week 9-10, optional)

### 6.4 Priority Matrix

| Priority | Gaps | Docs 02 | Docs 09 | Effort |
|----------|------|---------|---------|--------|
| **High** | 1. Interface definitions | Add interfaces | Add interface definitions | 2-3 days |
| **High** | 2. Callback-based results | Add callback pattern | Add callback to IDOR | 1-2 days |
| **High** | 3. Modular exporters/trackers | Add interface + examples | Add interface definitions | 2-3 days |
| **High** | 4. Template compilation phase | Add compilation phase | Add compilation step | 2-3 days |
| **Medium** | 5. In-memory template cache | Add cache design | Add cache implementation | 1-2 days |
| **Medium** | 6. Host error cache | Add cache design | Add cache implementation | 1-2 days |
| **Medium** | 7. Structured error handling | Add error design | Add error handling | 1-2 days |
| **Medium** | 8. Interactsh integration | Add integration design | Add Interactsh client | 2-3 days |
| **Medium** | 9. Fuzzing tests | Add fuzzing plan | Add fuzzing targets | 1-2 days |
| **Medium** | 13. Makefile | Add Makefile design | Add Makefile | 1 day |
| **Low** | 10. Auto-generated docs | Add docgen plan | Add docgen step | 1 day |
| **Low** | 11. Multi-platform releases | Add build plan | Add release step | 1 day |
| **Low** | 12. Progress/ETA tracking | Add progress design | Add progress tracking | 1 day |
| **Low** | 14. DESIGN.md | Create DESIGN.md | N/A | 1 day |
| **Low** | 15. CONTRIBUTING.md | Create CONTRIBUTING.md | N/A | 1 day |
| **Low** | 16. SYNTAX-REFERENCE.md | Auto-generate from code | N/A | 1 day |
| **Low** | 17. Template signing | Consider for security | Consider for security | 2-3 days (optional) |

### 6.5 Recommended Implementation Order

**Phase 1a (Weeks 1-4):**
1. Add interface definitions (Gap 1) — `pkg/scanner/engine.go`, `pkg/detectors/idor/detector.go`
2. Add callback pattern (Gap 2) — IDOR detector emits findings via callback
3. Add modular exporter/tracker design (Gap 3) — `pkg/reporter/exporter.go`, `pkg/reporter/tracker.go`
4. Add progress tracking (Gap 12) — `pkg/scanner/progress.go`

**Phase 1b (Weeks 5-10):**
5. Add template compilation phase (Gap 4) — `pkg/templates/compile.go`
6. Add in-memory template cache (Gap 5) — `pkg/templates/cache.go`
7. Add host error cache (Gap 6) — `pkg/protocols/common/hosterrorscache/`
8. Add structured error handling (Gap 7) — `pkg/utils/errkit/`
9. Add fuzzing targets (Gap 9) — `pkg/scanner/httpclient/fuzz_test.go`
10. Add Makefile (Gap 13) — `Makefile`
11. Add Interactsh integration (Gap 8) — `pkg/protocols/common/interactsh/` (Phase 3)
12. Add auto-generated docs (Gap 10) — `pkg/templates/docgen/` (Phase 1b)
13. Add multi-platform releases (Gap 11) — `.goreleaser.yml` (Phase 1b)
14. Create DESIGN.md (Gap 14) — `DESIGN.md` (Phase 1b)
15. Create CONTRIBUTING.md (Gap 15) — `CONTRIBUTING.md` (Phase 1b)
16. Create SYNTAX-REFERENCE.md (Gap 16) — `SYNTAX-REFERENCE.md` (Phase 1b)
17. Consider template signing (Gap 17) — `pkg/templates/signing/` (Phase 1b, optional)

---

## 7. Next Steps

1. Update docs 02 with interface definitions (Request, Executer, Exporter, Tracker, Writer)
2. Update docs 02 with callback pattern for results
3. Update docs 02 with modular exporter/tracker design
4. Update docs 02 with template compilation phase
5. Update docs 02 with in-memory cache design
6. Update docs 02 with host error cache design
7. Update docs 02 with Interactsh integration design
8. Update docs 09 with interface definitions
9. Update docs 09 with callback pattern
10. Update docs 09 with template compilation step
11. Update docs 09 with in-memory cache implementation
12. Update docs 09 with host error cache implementation
13. Update docs 09 with structured error handling
14. Update docs 09 with Interactsh client
15. Update docs 09 with fuzzing targets
16. Update docs 09 with Makefile
17. Update docs 09 with progress tracking
18. Update docs 09 with auto-generated docs
19. Update docs 09 with multi-platform releases
20. Create DESIGN.md, CONTRIBUTING.md, SYNTAX-REFERENCE.md
