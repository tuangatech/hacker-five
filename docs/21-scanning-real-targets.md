# Scanning a Real, Authorized Target

> Part of the [HackerFive documentation set](../README.md).

[05-hackerone-and-legal.md](05-hackerone-and-legal.md) covers *why* and *whether* (authorization, legal/ethical rules, the HackerOne workflow). [20-setup-testing-targets.md](20-setup-testing-targets.md) covers local lab targets (crAPI, DVWA, Juice Shop, vAPI) — safe to scan freely, but not real bugs against a real program. This doc is the gap between them: once you have a genuinely authorized target (a HackerOne program, or any site with a published VDP/`security.txt` safe-harbor policy — see `follow-up.md` §2), how do you actually point HackerFive at it — what to check first, how to narrow the template set to *that* target with `--tags` instead of firing everything, and how to run the scan itself.

**Every step below assumes the authorization step is already done.** Nothing here substitutes for reading a program's scope yourself — see doc05 §"Read Program Scope": *"If it's not explicitly in scope, don't test it."*

**Platform note:** commands below use the Linux/macOS binary name (`./hackerfive`) and `export VAR=val` for env vars. On Windows, that's `.\hackerfive.exe` and `$env:VAR = "val"` — see [README's Windows walkthrough](../README.md#download--install). Everything else (`git`, `curl`, flags) translates as-is.

---

## 1. Finding an authorized target

Two independent routes, not mutually exclusive:

- **HackerOne's public program directory** (`hackerone.com/directory`) — filter by asset type (API, Web Application), and per doc05 §2.1, favor "default"/less-mature programs early (less competition, similar payouts). Read the program's own scope page in full before touching anything — that page, not this doc, is the authoritative source of what's in/out of scope.
- **A published VDP without a bounty relationship** — [disclose.io](https://disclose.io) maintains a directory of organizations with a safe-harbor disclosure policy, which is a legitimate authorization even with no HackerOne program and no payout (`follow-up.md` §2). Confirm independently by checking the target's own `/.well-known/security.txt` ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)) — it should name a contact and, usually, a policy/scope URL. Save or screenshot it; it's your own record of authorization, separate from whatever disclose.io's listing says.

Either way, doc05 §2.2's rule applies unchanged: read in-scope *and* out-of-scope sections, not just the headline domain. Out-of-scope commonly includes third-party-hosted subdomains, legacy API versions, and — almost universally — rate-limiting/DoS/brute-force testing, which matches HackerFive's own read-only design anyway.

## 2. Recon before scanning

HackerFive has no crawler or fingerprinting module yet (the closest planned candidate is `follow-up.md` §4's "JavaScript — static analysis" idea, unscheduled). This step is manual, a few `curl` calls, and it directly feeds step 3 below — you can't pick a relevant template set without first knowing what's actually running.

1. **Confirm what you'd actually be hitting.** A scope's apex domain is often behind a CDN/WAF (Cloudflare, Akamai, Fastly) — the IP that resolves might be shared edge infrastructure, not the target org's own server. `dig <host>` and re-read the scope's exact wording for which subdomains/paths count; when in doubt, treat anything ambiguous as out of scope rather than guessing in your favor.
2. **Passive tech fingerprint**, a handful of read-only requests:
   ```bash
   curl -sI https://target-in-scope.example.com                     # Server, X-Powered-By headers
   curl -s  https://target-in-scope.example.com/robots.txt
   curl -s  https://target-in-scope.example.com/sitemap.xml
   curl -sI https://target-in-scope.example.com | grep -i set-cookie # framework tells: laravel_session, csrftoken (Django), connect.sid (Express), JSESSIONID (Java)...
   ```
   Look for a CMS/framework signature (WordPress `wp-content`/`wp-json`, Drupal `X-Drupal-*`, Laravel/Django/Express/Spring cookie names, Next.js `_next/static/`, exposed `/actuator`/`/swagger`/`/graphql` paths). This is the same signal class HackerFive's own `misconfig` detector partially surfaces on its own (missing-header/exposed-path checks) — running that detector first is itself a legitimate, low-risk recon step, not just a finding-generator.
3. **Decide scan mode against what the scope actually allows:**
   - `--detector misconfig` + Nuclei templates: no test account, additive/read-only, already measured at ~0% candidate-FP rate across four local targets (doc10 Step 4) — the safe default for a first pass.
   - `--detector idor`: only if the program's rules permit creating a second test account and you already have two real accounts on the target — doc05's own Medium-severity note (via `follow-up.md` §1) is that many programs restrict test-account creation; this is a manual judgment call per program, not something HackerFive checks for you.

## 3. Building a template set that fits the target

`--tags` filters at scan time: a template loads only if it carries at least one of the requested tags (comma-separated, OR match — same semantics as upstream Nuclei's own `-tags` flag). Point `--templates` at the full synced corpus and let `--tags` narrow it, rather than hand-curating a directory:

1. **Sync the full pinned corpus once**, if you haven't already:
   ```bash
   make templates-sync   # scripts/sync-nuclei-templates.sh — pinned commit, see doc10 Step 2
   ```
   This populates `.nuclei-templates-cache/http/{exposed-panels,misconfiguration,technologies}/` (gitignored, never committed).

   **Using just the downloaded release binary, no repo clone?** `make templates-sync` needs this repo checked out for its `Makefile`. Either clone the repo just for the sync script — `git clone https://github.com/tuangatech/hacker-five.git && cd hacker-five && make templates-sync` (needs `git`/`bash`/`make`, not Go) — or run the same sparse-checkout directly, copying the pinned commit and category list from [`scripts/sync-nuclei-templates.sh`](../scripts/sync-nuclei-templates.sh); those are plain `git` invocations, unchanged in PowerShell.

2. **Filter by what step 2's recon actually found**, using its own tags directly:
   ```bash
   # example: recon showed a WordPress site with a Grafana panel exposed
   --templates .nuclei-templates-cache --tags wordpress,grafana
   ```
   Matching is case-insensitive and trims whitespace, so `--tags WordPress, grafana` behaves the same. The scan's stderr summary (`loaded N nuclei-compatible, M native templates (R rejected, F filtered by tag)`) confirms how many actually matched before any request goes out — a `0`/`0` result with a nonzero `F` means the tag guess didn't match anything real, worth rechecking against a sample template's `tags:` line before assuming the target has nothing relevant.

3. **The small, already-live-verified generic set stays outside the tag filter** — run it as a second pass (or a second `--templates` directory) alongside the tag-filtered one, since generic checks (missing-security-headers, tech-detect) are worth keeping regardless of tag match:
   ```bash
   --templates templates/nuclei-samples
   ```

This keeps request volume roughly proportional to what's actually plausible against this target, instead of firing the full synced corpus (~2,500 templates) at it untagged. Step 4's own vAPI testing (doc10) found even a *local* dev server couldn't absorb that volume in reasonable time — a real target behind production infrastructure deserves at least as much restraint, not less, both for politeness and because most programs explicitly disallow high-volume/DoS-adjacent testing (doc05 §2.2).

## 4. Running the scan

```bash
export HACKERFIVE_AUTH_TOKEN="..."   # only if the in-scope paths require it

./hackerfive scan \
  -t https://target-in-scope.example.com \
  --detector misconfig \
  --templates .nuclei-templates-cache \
  --tags wordpress,grafana \
  --rate-limit 5 \
  --concurrency 5 \
  -o findings.json
```

- **`--rate-limit`/`--concurrency` are deliberately set well below the CLI's defaults (50 req/s / 25 workers).** `follow-up.md` §1 flagged that default as reasonable for a local lab benchmark but too aggressive for most bounty/VDP programs' actual rate limits — and there's no `--scope` enforcement or `Retry-After`-aware backoff in the CLI yet (also flagged there, still open). Staying inside the program's stated limits is on you, manually, not something the tool currently enforces.
- **Treat every finding here as a lead, not a report.** Doc05 §4.1 already requires manual verification (`curl`/Burp re-check, confirm exploitability, document reproduction) before anything gets written up — that step matters more against a real target than it did against crAPI/DVWA/Juice Shop, where the "0% candidate FP rate" (doc10 Step 4) was measured against known, fully-understood bugs. A real target has none of that ground truth to check against.
- **Don't run `--detector idor` here without a plan for the accounts it needs** — see step 2 above.

## See also
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — authorization, legal/ethical rules, the HackerOne joining workflow this doc assumes is already done
- [20-setup-testing-targets.md](20-setup-testing-targets.md) — local lab targets for validating the tool itself, before ever pointing it at something real
- [follow-up.md](follow-up.md) — VDP/disclose.io expansion decision (§2), and the open rate-limit-default/scope-enforcement/Retry-After gaps referenced above (§1)
- [10-implementation-plan-ph1b.md](10-implementation-plan-ph1b.md) — Nuclei-compatible template sync/pinning (Step 2) and the vAPI corpus-size finding referenced in §3 above (Step 4)
