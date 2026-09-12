# Live-Testing Playbook

> Part of the [HackerFive documentation set](../README.md).

An operational runbook for running HackerFive against a real, authorized target: settings
to run, what to monitor mid-run, what to verify before trusting a result, and how to log an
enhancement. Assumes authorization is already settled — see
[05-hackerone-and-legal.md](05-hackerone-and-legal.md) and
[22-authorized-targets.md](22-authorized-targets.md) first.

---

## 0. Before you start

- Check [doc22](22-authorized-targets.md) for this target's rules (rate caps, disallowed
  detectors) and `.engagements/<target>/results.md` for prior-round context.
- Rebuild against current `main`.
- Decide which mutating flags this program actually permits: `--allow-writes`
  (businesslogic), `--allow-mutating-bfla` (fires a real DELETE),
  `--auto-provision-account` (registers a real account). Opt-in only, never default-on.

## 1. What settings to run

**Recon first, always** — it feeds tag-narrowing, dead-path/WAF-wall skipping, and every
detector's required fields. Hand-typing flags with no recon behind them should be the
exception.

- `recon --scope <file/glob> --recon-depth <passive|active|full>` — escalate only once a
  shallower pass looks thin; `full`'s crawl gets expensive at host-count scale.
- `--openapi-spec <path|url>` whenever a spec exists — the single highest-leverage flag
  for detector precision (concrete IDs, auth requirements, body schemas).
- `--headless-crawl` / `--param-mining` — opt-in for a JS-heavy app that a plain crawl
  visibly under-finds, not a default toggle.
- `--wave-timeout` — raise it on a large sweep; a starved wave fails silently (a short
  host list, no error), so a thin recon result is a reason to re-run longer, not trust it.

**Plan next** (`plan --llm-assist` or the deterministic path) rather than hand-picking
detectors. **Review Plan Preview before approving** — check every leaf's target host
against scope; never "select all" blind. `--narrow-by-tech` stays on by default, but a
diverse multi-tech host can still narrow to thousands of templates — watch
`--max-target-duration` and partial-completion findings.

**Detector prerequisites:**

| Detector | Required fields | Mutating? |
| --- | --- | --- |
| `misconfig` | none — unauthenticated | No |
| `idor` | `--endpoint`/recon-derived; two accounts for high-confidence mode | No |
| `authbypass` | `--protected-paths`/recon-derived; `--auth-token` | No |
| `ssrf` | `--ssrf-param`/body-param or recon-derived; `--no-oob` for a real engagement | No |
| `sqli` | `--sqli-path`/`--sqli-param` or recon-derived | No |
| `netservice` | a `tcp://host:port` target | No |
| `businesslogic` | `--auth-token`; **`--allow-writes`** | **Yes** — real coupon mint/apply |
| `mutatebfla` | two accounts; `--mutatebfla-delete-path`/`-verify-path`/`-marker`; **`--allow-mutating-bfla`** | **Yes** — a real DELETE |

**Rate limits are a program rule, not a tool default** — some programs cap runs/day
rather than requests/sec, which HackerFive doesn't track; keep that in doc22 and set it
before the first request.

**LLM-assisted steps** (`plan`/`suggest`/`triage --llm-assist`) print spend against a
ceiling — log it in `results.md`. A stuck call is worth canceling and retrying smaller
rather than waiting indefinitely.

## 2. What to monitor mid-run

stderr is the real-time signal:

- an allow-flag "not set" warning confirms a mutating detector is safely skipping, not
  silently broken.
- a circuit-breaker warning means the host couldn't be finished — not that it's clean.
- a WAF-block/uniform-catchall finding means the corpus was skipped for that host — "no
  findings" there means "walled," not "secure."
- a partial-time-budget finding names how far the corpus got; findings at 20% likely mean
  more at 100%.
- a rate-limited/unreachable-mid-run abort means the target pushed back for real —
  correct behavior, not a bug to work around.
- silence for several minutes with no dispatch heartbeat is worth checking as a hang.
- confirm a program-mandated header is applied to every request, not just hand-added ones.

Before walking away from a long run, sanity-check template-count × target-count ÷
rate-limit against the time budget — a mismatch is expected partial coverage, not a bug.

## 3. What to verify before trusting a result

Every finding is a lead, not a report: reproduce it by hand (`curl`/Burp), confirm the
response shows what's claimed, confirm it reproduces twice.

- `Severity`/`Confidence` are detector-set, never LLM-mutated — a mismatch against the
  evidence is a detector-logic gap to file, not something to silently override.
- For any cross-account finding, confirm both accounts are genuinely your own throwaway
  accounts, never a bystander's data. If not certain, don't trust the finding.
- Watch for implausible duplication across similar hosts, especially via webui/MCP.
- Cross-check recon's out-of-scope list, not just its endpoints — a candidate that
  reached a leaf pointing at an unrecognized host is a stop-everything bug.
- A silent zero-finding host next to an identical positive one is worth a second look.

## 4. What to raise as an enhancement, and how

Raise something when: a real, hand-verified vulnerability existed and no detector reached
it; a false-positive **pattern** appears (name the mechanism, not just "saw an FP"); a
config field had to be hand-typed that recon could plausibly derive; a scope-safety issue
surfaces (fix same-session, never backlog); a performance/reliability/cost issue changed
what the run could cover; or a [doc22](22-authorized-targets.md) judgment turned out wrong.

To log it: get the next `LT-` number (`grep -oE 'LT-[0-9]+' docs/follow-up.md docs/follow-up-archive.md | sort -t- -k2 -n | tail -1`), add a dated `## Live Testing — <target> (<date>)` section to [follow-up.md](follow-up.md) with the command run, what was hand-verified, and the fix/test if applied — then route it to a phase doc if it fits planned work, or leave it open with a Value/Effort note. Save raw artifacts under `.engagements/<target>/` and update its `results.md`.

## 5. What a human researcher would likely flag

HackerFive's strength is broad, deterministic, read-only coverage fast. Probe for these
during a live round rather than waiting to be asked:

- **Chained exploits** — several low-severity findings that compose into something worse.
- **Business-logic depth** beyond the shipped coupon checks — price/workflow/quantity abuse.
- **Client-side/DOM issues** — stored/DOM XSS, `postMessage`, CSP bypass, clickjacking.
- **Newer protocol surfaces** — GraphQL, gRPC, WebSockets/SSE, the AI-agent surface.
- **Deeper auth/session semantics** — OAuth/SSO flows, token-binding, cross-service
  session confusion, beyond a fixed JWT weak-secret wordlist.
- **Report quality** — a tight reproduction and severity tied to real impact; a batch of
  low-value header findings reads as noise even when individually true.
- **WAF/filter-bypass sophistication** — a fixed mutation set generally lags a human's
  manual creativity.
- **Multi-account/workflow ergonomics** across several concurrent programs.

## See also

- [21-scanning-real-targets.md](21-scanning-real-targets.md) — first-time-against-a-target mechanics this playbook assumes are done
- [22-authorized-targets.md](22-authorized-targets.md) — per-target vetting registry to check/update every round
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — authorization/legal rules, the "lead, not a report" duty
- [follow-up.md](follow-up.md) / [follow-up-archive.md](follow-up-archive.md) — full write-ups this playbook is distilled from
