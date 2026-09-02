# Engineering Discussions

> Part of the [HackerFive documentation set](../README.md).

Short, dated, bullet-form records of architecture questions that were discussed and resolved but didn't warrant their own numbered doc or a change to an existing plan — a place to point back to later instead of re-litigating from scratch. Not an implementation plan; see the numbered docs for those.

## 2026-09-02: `--oob-server` default changed from empty to 2 public servers

**Decision, user's explicit and informed choice (confirmed via a clarifying question, not assumed):** `--oob-server` (CLI) and the Web UI's OOB servers field now default to `ssrf.DefaultOOBServers` — `https://oast.pro` (primary) + `https://oast.live` (backup) — when left untouched, instead of the prior empty/silent-skip default. Motivation: testing the user's own sites without re-typing `public` or a URL every run.

**Scope of the change, confirmed explicitly rather than assumed:** this is the tool-wide code default, not a personal-only opt-in — affects every user who doesn't override it, on both the CLI and the Web UI.

**What's unchanged:** the underlying leak tradeoff (`pkg/detectors/ssrf/rules.go`'s `PublicInteractshServers` doc comment) — Interactsh's per-client encryption keeps interaction *contents* private, but the server operator still sees the target's real IP and timing. Still "not recommended for a real, authorized third-party engagement" — only the default acceptance of the tradeoff changed, not the tradeoff itself.

**How to opt out, since a non-empty default needs a real escape hatch:**
- CLI: `--no-oob` (new flag) — `pflag`'s `StringArray` has no clean way to explicitly pass "empty" once the flag has a non-nil default, so a dedicated disable flag was added rather than relying on flag semantics.
- Web UI: clear the OOB servers text field before submitting — a plain `<input>` naturally supports "explicitly empty," no extra control needed.

**What's still available, unchanged:** `--oob-server public` still expands to the full 6-server `PublicInteractshServers` pool (broader than the 2-server default); an explicit self-hosted URL still works exactly as before.

**Files:** `pkg/detectors/ssrf/rules.go` (`DefaultOOBServers`), `cmd/hackerfive/scan.go` (`--oob-server` default, new `--no-oob`), `pkg/webui/handlers_scan.go`/`handlers_launch.go` (Web UI default), `pkg/scanner/config.go` (`OOBServers` doc comment) — plus corrections to [13-implementation-plan-ph4.md](13-implementation-plan-ph4.md)'s design tension 1 and [follow-up.md](follow-up.md) §1, both of which documented the old "empty by default" behavior as settled.

## 2026-09-02: Go-only vs. Go engine + Python (FastAPI) UI/LLM/MCP, connected via gRPC

**Proposal considered:** split into two deployables — Go for the deterministic engine (and maybe LLM/agent logic), Python/FastAPI for UI + LLM + MCP, gRPC as the connector, same monorepo.

**Verified before deciding, not assumed:**
- MCP's *official* Go SDK (`github.com/modelcontextprotocol/go-sdk`, maintained with Google) already supports `elicitation` and the `tasks` extension per the 2026-07-28 spec. This closes the one concrete reason Python might have been needed — [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md)'s own "unverified, check at Step 1 kickoff" framing for the Go MCP SDK is more cautious than current evidence supports.
- `pkg/llmfallback` (doc15 Step 2) is already scoped as plain `net/http` REST calls to OpenRouter/Ollama, not a heavy SDK — Python's richer LLM-SDK ecosystem was already a non-issue for that piece, by design.

**Evaluated on efficiency / maintenance / UX:**
- **Efficiency — against, not for.** Today's `pkg/webui` → `pkg/scanner`/`pkg/recon` calls are in-process, zero-serialization. gRPC would add a network hop + protobuf marshaling to a workload that was never latency-bound (a human watching SSE-streamed findings trickle in over minutes).
- **Maintenance — a real, ongoing tax.** Two build pipelines, two dependency-drift surfaces, a `.proto` schema to keep in sync with both a Go struct and a Pydantic model, two runtimes to patch, version-skew risk between deployables that doesn't exist today. Runs against this project's own repeated discipline (verify real transitive footprint before adding a dependency — the `interactsh-client` lesson, [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) §8; prefer a first-party Go implementation over accepting bloat).
- **UX — no visible upside, real downside.** `hackerfive serve` (one binary, zero install) is a stated advantage over Strix/PentestGPT's real Python-environment overhead (`uv sync`, a Python 3.12+ requirement, venv management). Splitting either reintroduces that friction for the end user, or hides it behind a combined Docker image — buying nothing the user would ever notice, only new failure modes (port conflicts, connection refused, version skew).

**Recommendation: stay one Go binary. No gRPC, no FastAPI.**
- UI stays `pkg/webui` (Go, htmx, `go:embed`).
- MCP server stays Go (`pkg/mcpserver`, doc15 Step 1) — lower risk than doc15 currently states, given the official-SDK finding above.
- LLM fallback stays Go (`pkg/llmfallback`, doc15 Step 2) — already REST-only by design.
- The only contingency worth keeping, and only if the Go MCP SDK genuinely proves inadequate in practice (not preemptively): a narrow, isolated Python subprocess for *just* the MCP transport layer — a much smaller hedge than a second service.

**Trigger to revisit — a condition, not a date:** if HackerFive ever becomes a genuinely hosted, multi-tenant service (the undecided "Pentest On-Demand" idea noted in [follow-up.md](follow-up.md) §3), independent scaling of a UI tier vs. an engine tier would be a legitimate reason to reach for services and maybe gRPC. Doesn't apply to a locally-run CLI/Web UI tool today.

**See also:**
- [90-research-hackerbot.md](90-research-hackerbot.md) Decision 5 — why a heavy Python agent framework isn't needed either: stateless, tiered LLM calls, never a persistent agent session.
- [15-implementation-plan-ph6.md](15-implementation-plan-ph6.md) Dependencies — the MCP SDK verification step this discussion's finding should update.
- [follow-up.md](follow-up.md) §3 — XBOW's hosted-service precedent, the actual trigger condition named above.
