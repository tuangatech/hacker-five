# Live-Testing Playbook

> Part of the [HackerFive documentation set](../README.md).

An operational runbook for running HackerFive against a real, authorized target: what to
configure, what to watch during a run, what to verify before trusting a result, and how to
turn what you observe into a tracked enhancement. This is the accumulated procedure behind
~15 live-testing rounds recorded in [follow-up.md](follow-up.md)/[follow-up-archive.md](follow-up-archive.md)
(crAPI, nettix.com.pe, aalberts.com, meesho_bbp, shopify, ALSCO, the G1 agent eval) — read
those for the specific bugs each round found; this doc is the reusable *process*, distilled
so the next round doesn't re-derive it. Written for whoever runs the next live-testing
session (human or agent) to follow without re-reading the whole backlog first.

**Not a substitute for:**
[05-hackerone-and-legal.md](05-hackerone-and-legal.md) (authorization/legal rules),
[21-scanning-real-targets.md](21-scanning-real-targets.md) (the first-time-against-a-target
mechanics: finding scope, building a tag set), or
[22-authorized-targets.md](22-authorized-targets.md) (the per-target vetting registry — check
it before every round, update it after). This doc sits downstream of all three: it assumes
authorization is settled and covers *how to run and judge the tool itself* well.

---

## 0. Before you start

1. **Check [doc22](22-authorized-targets.md) for this target.** An existing entry saves
   re-vetting; a missing one means step 1 of [doc21](21-scanning-real-targets.md) isn't done
   yet. If a `.engagements/<target>/policy.yaml` exists, it's a D2 pre-flight hard gate
   (`automated_scanning: disallowed` refuses the run) — but it only enforces an explicit
   "no"; still read the actual policy text yourself.
2. **Read `.engagements/<target>/results.md` if this isn't the first round.** Avoid
   re-deriving what a prior round already established — demo-viability verdicts,
   wall/WAF status, which detectors are safe vs. off-limits for this specific program
   (Meesho's own doc22 entry is the model: "don't run `--allow-writes` here casually").
3. **Rebuild against current `main`.** A stale binary silently lacks whatever the latest
   `LT-`-numbered fixes shipped — check `git log -1` before a long run, not after.
4. **Decide up front which mutating flags are even on the table**, against this program's
   actual rules, not just "the flag exists": `--allow-writes` (businesslogic), 
   `--allow-mutating-bfla` (LT-132, fires a real DELETE), `--auto-provision-account`
   (registers a real account). Each is its own independently-scoped exception to the
   read/enumerate-only default (CLAUDE.md) — none is a default-on decision.

## 1. What settings to run

**Recon first, always** — even for a single `--detector misconfig` pass. `ReconResult`
feeds tag-narrowing, dead-path skip, the D6 uniform-wall skip, tech-stack correlation, and
every detector's required-field auto-fill (`EndpointTemplate`, `ProtectedPaths`,
`SQLiPath`/`Params`, `CouponEndpoint`, …). A raw `scan --detector X` with every field
hand-typed and no recon behind it should be the exception now, not the default.

- `recon --scope <file/glob> --recon-depth <passive|active|full>` — escalate depth only
  once a shallower pass looks thin, not by default on a large scope. `full`'s Wave 3 crawl
  is genuinely expensive at host-count scale (nettix's 24-host sweep, LT-111/150).
- `--openapi-spec <path|url>` whenever a spec exists, even undocumented/behind-auth
  (LT-89) — it's the highest-leverage single flag for detector precision: it's the only
  route to concrete `{{id}}` templates, `AuthRequired`, body-param schemas, and
  `CouponEndpoint` facts without hand-typing every one.
- `--headless-crawl` / `--param-mining` are opt-in on purpose (cost/scope) — turn on when
  a non-headless crawl visibly under-finds on a SPA (LT-99's crAPI 4-vs-40-endpoint gap is
  the trigger to recognize), not as a default toggle.
- `--wave-timeout` — raise from the 60s default on a large host-count sweep (LT-111); a
  starved subdomain-enum wave produces a thin/wrong host list with **no error**, so a
  suspiciously small host count after a broad-scope recon is itself a signal to re-run
  with a longer timeout before trusting it.

**Plan next** (`plan --llm-assist`, or the deterministic decision-engine path) rather than
hand-picking detectors, unless doing a narrow re-check of one already-known endpoint.

- **Review Plan Preview before approving anything.** Specifically check every leaf's
  target host against the authorized scope — LT-144's exact failure mode was a
  JS-namespace string (`xmlns="...w3.org..."`) becoming a real, dispatchable `idor` leaf
  against `www.w3.org`. Never "select all" without reading hosts first.
- `--narrow-by-tech` stays on (default) unless the full corpus is deliberately wanted —
  but don't assume it bounds wall-clock the way "scoped to this detector" implies. LT-150
  measured a narrowed set still at 5,343 templates on one diverse multi-tech host; watch
  `--max-target-duration` and `scan-partial-time-budget` findings rather than assuming
  narrowing alone solved the time problem.

**Detector prerequisites** — check before dispatch, not after zero findings come back:

| Detector | Required fields | Mutating? |
| --- | --- | --- |
| `misconfig` | none — fully unauthenticated | No — always safe as a first pass |
| `idor` | `--endpoint`/recon-derived `EndpointTemplate`; two accounts (`--auth-token` + `--other-auth-token`) for high-confidence baseline mode, else low-confidence heuristic mode | No |
| `authbypass` | `--protected-paths`/recon-derived; `--auth-token` | No |
| `ssrf` | `--ssrf-param`/body-param or recon-derived; `--oob-server` (2 public servers on by default) or `--no-oob` for a real third-party engagement | No |
| `sqli` | `--sqli-path`/`--sqli-param` or recon-derived (`SuggestSQLiTargets`) | No |
| `netservice` | a `tcp://host:port` target (naabu-discovered) | No |
| `businesslogic` | `--auth-token`; **`--allow-writes`** | **Yes** — real coupon mint/apply |
| `mutatebfla` | `--auth-token` + `--other-auth-token`; `--mutatebfla-delete-path`/`-verify-path`/`-marker` (CLI-only — no recon derivation yet); **`--allow-mutating-bfla`** | **Yes** — a real DELETE (LT-132) |

**Rate limits are a program rule, not a tool default.** `--rate-limit`'s 10 req/s default
is conservative but several real programs go lower still — Meesho explicitly disallows
rate-limit testing on its order flow; aalberts.com caps *runs per day* (5), which
`--rate-limit`/`--concurrency` don't track at all — that's a manual count kept in doc22's
entry, not something the tool enforces. Set this before the first request, not after a
complaint.

**LLM-assisted steps** (`plan --llm-assist`, `suggest --llm-assist`, `triage --llm-assist`)
each print spend against a ceiling — note actual spend vs. ceiling in `results.md` every
time (a $0.10 ceiling costing $0.006 is normal and worth recording as a data point, not
just when something goes wrong). Expect an occasional per-call timeout even after LT-146's
reliability work on a slow model; a heartbeat line every 30s means "still working," a truly
stuck call for minutes is worth canceling and re-running with fewer leaves.

## 2. What to monitor during a run

stderr is the real-time signal — watch it, don't just wait for the final JSON. Lines worth
recognizing (as of 2026-09-12; grep the relevant `e.warnf`/`Fprintln` call sites if a
future line isn't listed here):

- `--allow-writes not set` / `--allow-mutating-bfla not set` — confirms a mutating
  detector is running in its documented safe-skip mode, not silently failing for an
  unrelated reason.
- `too many consecutive request errors` (a `hosterrors` circuit-breaker trip) — the host
  may be down or actively blocking; read "0 findings" here as "couldn't finish," not
  "clean."
- `misconfig-waf-blocked` / `misconfig-uniform-catchall` (D6) — the template corpus was
  skipped entirely for that host. "No misconfig findings" on a walled host means "walled,"
  not "secure."
- `scan-partial-time-budget` — the corpus didn't finish; the finding itself names how far
  it got (`n/m templates`). A host with real findings at 22% completion likely has more
  at 100% — a candidate for a longer `--max-target-duration` re-run, not a closed case.
- `scan-target-rate-limited` / `scan-target-unreachable-mid-run` (the adaptive-throttle
  abort, LT-74/88) — the target pushed back for real; this is the tool behaving correctly,
  not a bug to work around mid-run.
- the dispatch heartbeat (`N/M templates completed so far`, LT-149) — total silence for
  several minutes with none of these lines is itself worth investigating as a possible
  hang, not just "a slow but progressing scan."
- `applying policy-mandated request header` — confirms a program-required header (e.g.
  Meesho's `X-Hackerone`) went out on *every* request, not just the ones added by hand via
  `--header`.

**Request-volume sanity, checked before walking away from a long run, not after:**
cross-multiply loaded-template count × target count ÷ rate-limit against wall-clock
expectations. LT-150's own number — a 5,343-template narrowed set across 6 hosts at
8-50 req/s ran for hours, one host finishing at 22% inside a 15-minute cap — is the scale
to calibrate against. A mismatch here is expected partial coverage to plan around, not a
bug to chase.

## 3. What to verify before trusting a result

**Every finding is a lead, not a report** ([doc21](21-scanning-real-targets.md) already
says this — repeated here because it's the rule most likely skipped under time pressure).
Manually reproduce: `curl`/Burp re-check, confirm the response really shows what the
finding claims, confirm it reproduces a second time.

- **`Severity`/`Confidence` are detector-set, never LLM-mutated** — an enforced invariant
  (`triage --llm-assist`'s annotations, and any future triage-assist step, are advisory
  fields alongside a `Finding`, never edits to it). If a finding's confidence looks
  mismatched against its own evidence, that's a detector-logic gap worth filing (§4), not
  something to silently second-guess and move past.
- **For any cross-account finding** (idor baseline mode, authbypass token-reuse/BFLA,
  `mutatebfla`) — confirm both accounts really are your own/the operator's own throwaway
  accounts, never a bystander's real data. This is the entire reason for `mutatebfla`'s
  baseline-marker design (LT-132): if a marker match feels coincidental rather than
  certain, don't trust the finding — fix the marker, don't relax the check.
- **Dedup/aggregation sanity** — an implausible number of near-identical findings across
  similar hosts, specifically through a webui/MCP-driven run, is a known failure shape
  (LT-6/LT-148's tail: N copies of one D6 finding from N leaves dispatched separately on
  one walled host). A CLI `scan --recon-file` run already dedupes; a Plan-Preview/MCP run
  should show the same shape of output, not more.
- **Cross-check recon's `OutOfScope` list, not only its `Endpoints` table** — especially
  after a JS-heavy crawl (LT-144). A candidate that reached a leaf's `Target` field
  pointing at an unrecognized host is a stop-everything bug, not a minor note — fix and
  re-verify before continuing that engagement.
- **For a native product-fingerprint check** (Dolibarr/Nextcloud/phpMyAdmin/Webmin-style)
  — a silent zero-finding host sitting next to an identical positive one is a known,
  previously-real failure shape (LT-113/151). Check the log for a priority-check
  `warn:` line before concluding "this host is actually different."

## 4. What to raise as an enhancement, and how

**Raise something when:**

- a real, hand-verified vulnerability existed on the target and no detector reached it —
  a structural gap, not a tuning nit. Hand-verify the miss first (crAPI's 2026-09-08 round
  — LT-92/95/96/132/133/134 — is the model), then file it with the concrete request/response
  that proves it.
- a false-positive **pattern** appeared, not a one-off — reproduce it and name the
  *mechanism* the detector was fooled by (a specific response shape, an auth-wall status
  code, a templated-catch-all page), not just "saw an FP."
- a config field had to be hand-typed that a smarter recon pass could plausibly derive —
  name the missing correlation concretely (the `EndpointTemplate`/`SQLiPath`
  auto-derivation precedent), not just "wish this were automatic."
- a **scope-safety issue** surfaced — anything that could dispatch a real request outside
  the authorized target. Treat as same-session, top-priority, never backlog (LT-144 was
  fixed in the same session it was found).
- a performance/reliability/cost issue changed what the run could actually cover — a
  timeout, a corpus-size/time-budget mismatch, a starved wave (LT-111/146/149/150 are this
  shape).
- a [doc22](22-authorized-targets.md) registry judgment turned out wrong, or a new hard
  program requirement surfaced (a rate cap, a forbidden detector) — update that doc
  directly, in the same sitting, not only `follow-up.md`.

**How to log it:**

1. Get the next number: `grep -oE 'LT-[0-9]+' docs/follow-up.md docs/follow-up-archive.md | sort -t- -k2 -n | tail -1`.
2. Add (or append to) a `## Live Testing — <target(s)> (<date>)` section in
   [follow-up.md](follow-up.md) — full detail: the exact command/flags run, what was
   hand-verified, root cause if found, the fix if applied, and the regression test that
   pins it. This doc's own precedent sections (search that file for `## Live Testing`) are
   the template to match, in both depth and honesty about what's still open.
3. Route it to a phase doc's Scope table ([18-implementation-plan-ph9.md](18-implementation-plan-ph9.md)
   is current) if it fits already-planned work; otherwise leave it `(open)` with a stated
   Value/Effort estimate (see LT-132/133/134's own entries for the exact format) so it's
   pickable later without re-deriving why it matters.
4. Save raw artifacts under `.engagements/<target>/` (scope/recon/plan/scan JSON, dated
   filenames) and update `.engagements/<target>/results.md` — that file is the first thing
   the *next* round of this playbook reads (§0.2 above).
5. Once fixed: move the full write-up to [follow-up-archive.md](follow-up-archive.md) and
   compress the `follow-up.md` entry to 1-3 lines (symptom → fix, test pointer) — the
   standing convention this doc set already follows (see `follow-up.md`'s own header note).

## 5. What a human security researcher would likely flag — probe for these unprompted

HackerFive's strength is broad, deterministic, read-only-by-default coverage across many
hosts fast. The gaps a human reviewer tends to name are exactly where deterministic
pattern-matching runs out — actively look for these during a live round rather than
waiting to be asked:

- **Multi-step/chained exploits.** Two or three individually low-severity findings that
  compose into something worse (a missing-CSRF-token endpoint + an IDOR + no rate limit).
  HackerFive reports each finding independently — a human researcher's distinguishing
  value is often the chain, not any single link. Look at correlated findings
  (`suggest --llm-assist`'s `correlate_hosts` action is the tool's own attempt at this) and
  ask whether any compose into something reportable on their own.
- **Business-logic depth beyond the shipped coupon mint/apply pair.** Real programs have
  their own bespoke logic flaws — price manipulation, workflow-state bypass, quantity/
  negative-value abuse — that need a human reading the actual application, not a generic
  detector. `businesslogic`'s own doc comment is explicit that it's crAPI-shaped, not
  general-purpose yet.
- **Client-side/DOM-based issues.** Stored/DOM XSS needing real script execution,
  `postMessage` handling, CSP bypass, clickjacking. HackerFive's model is almost entirely
  server-response-based; a human with a browser (or Burp) covers a different half of the
  OWASP Top 10 than this tool does today.
- **Newer/less-common protocol surfaces.** GraphQL introspection depth (LT-40's open
  tail), gRPC, WebSockets/SSE, the AI-agent surface (`llms.txt`/MCP, doc18 Step 3, not yet
  built). A researcher checking a modern API-heavy target looks here before HackerFive can.
- **Session/auth semantics beyond `alg:none` and a fixed weak-secret wordlist.** Real
  OAuth/SSO flows, token-binding edge cases, cross-service session confusion between
  microservices. `authbypass`'s JWT checks are intentionally narrow — see its own doc
  comment on why a real credential-guessing sequence isn't built.
- **Evidence/report quality for a human audience.** A tighter, copy-pasteable `curl`
  reproduction; a severity justification tied to actual business impact rather than a
  template's static label; noise discipline (a batch of low-value missing-header findings
  reads as report-quality noise to a reviewer even when each one is individually true).
- **WAF/filter-bypass sophistication.** HackerFive's signature-based approach is a poor
  fit for a program whose whole premise is bypassing an edge filter (doc22's ALSCO note)
  — even once Phase 9 Step 4's WAF-aware retry ships with its bounded mutation set, a
  human's manual encoding/mutation creativity will likely still outpace it.
- **Multi-account/workflow ergonomics at scale.** A researcher juggling several programs
  wants smoother scope/policy/account management than today's per-engagement,
  hand-curated `.engagements/` folder plus CLI flags. Friction here is itself worth naming
  even without a specific bug behind it.

## See also

- [21-scanning-real-targets.md](21-scanning-real-targets.md) — first-time-against-a-target mechanics this playbook assumes are already done
- [22-authorized-targets.md](22-authorized-targets.md) — the per-target vetting registry to check before, and update after, every round
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — authorization/legal rules, the "finding is a lead, not a report" verification duty
- [18-implementation-plan-ph9.md](18-implementation-plan-ph9.md) — current phase scope, for routing a new enhancement into planned work
- [follow-up.md](follow-up.md) / [follow-up-archive.md](follow-up-archive.md) — every prior round's full write-up this playbook is distilled from
- [90-research-hackerbot.md](90-research-hackerbot.md) — the G1 agent-driven eval methodology, for a full-pipeline agent-mediated round specifically
- [20-setup-testing-targets.md](20-setup-testing-targets.md) — local lab targets for rehearsing a new flag/detector before it ever touches a real program
