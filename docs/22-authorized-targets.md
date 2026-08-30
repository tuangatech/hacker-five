# Authorized Targets Registry

> Part of the [HackerFive documentation set](../README.md).

A living list of real, authorized targets (found via disclose.io/HackerOne per [21-scanning-real-targets.md](21-scanning-real-targets.md) §1) that have been vetted for testing with HackerFive — so the vetting work (reading the policy, cross-checking `security.txt`, judging fit) isn't repeated from scratch each time.

**Being listed here does not substitute for reading a target's full policy yourself before scanning** — see [doc05](05-hackerone-and-legal.md)'s "Read Program Scope" rule. Policies change; re-check `security.txt`'s `Expires` field before relying on an old entry.

## Active targets

### a2x.io
- **Source:** disclose.io
- **Policy:** [a2x.io/security-policy](https://a2x.io/security-policy) — confirmed via `/.well-known/security.txt` (Contact + Policy fields consistent)
- **Scope:** "this domain, its subdomains, and services operated directly by us"; third-party services out of scope
- **Safe harbor:** explicit
- **Restrictions:** no DoS/destructive testing, no privacy/data-confidentiality violations, exploitation limited to what's necessary to demonstrate the issue
- **Bounty:** none (pure VDP)
- **Fit for HackerFive:** good — `--detector misconfig`'s read-only design matches their "no destructive testing" rule directly
- **Vetted:** 2026-08-26

### aalberts.com
- **Source:** disclose.io
- **Policy:** [aalberts.com/.well-known/policy.txt](https://aalberts.com/.well-known/policy.txt) — confirmed via `/.well-known/security.txt` (Contact + Policy fields consistent)
- **Scope:** "Aalberts' systems and infrastructure" — specific domains/assets not enumerated in the policy text
- **Safe harbor:** explicit
- **Restrictions:** no social engineering/physical attacks/DDoS/spam/"third-party tools"; no bounty-hunting motivated purely by financial gain; don't access more data than necessary; delete confidential data after resolution
- **Bounty:** yes — fixed Amazon gift cards, severity-assessed, non-negotiable
- **Fit for HackerFive:** ⚠️ **open question, resolve before scanning** — "third-party tools" is banned in the same clause as DDoS/social engineering, which most likely means third-party attack services (botnets, etc.), not vulnerability scanners — but it's genuinely ambiguous read cold. Per doc05's "when in doubt, treat as out of scope" rule: **email `security@aalberts.com` for explicit confirmation that automated scanning tools are permitted before pointing HackerFive at them.**
- **Vetted:** 2026-08-26

### abc8.immobilien
- **Source:** disclose.io
- **Policy:** [abc8.immobilien/security-policy](https://abc8.immobilien/security-policy/) — confirmed via `/.well-known/security.txt` (Contact + Policy fields consistent)
- **Scope:** "this domain, its subdomains, and services operated directly by us"; third-party services out of scope — same wording as a2x.io's policy
- **Safe harbor:** explicit
- **Restrictions:** no DoS/destructive testing, no privacy/data-confidentiality violations, exploitation limited to what's necessary to demonstrate the issue
- **Bounty:** none (pure VDP)
- **Fit for HackerFive:** good — same shape as a2x.io, `--detector misconfig`'s read-only design matches their "no destructive testing" rule directly
- **Vetted:** 2026-08-26

### meesho_bbp (Meesho)
- **Source:** HackerOne program the user is an active participant in (`https://hackerone.com/meesho_bbp`), not disclose.io — vetted directly via the real HackerOne API (`pkg/hackerone`) rather than a security.txt lookup.
- **Scope:** pulled live via `hackerfive report scopes --team meesho_bbp` (2026-08-30) — of 25 listed structured-scope entries, only 8 are `eligible_for_submission=true` web/API assets: `www.meesho.com`, `admin.meeshosupply.com`, `supplier.meesho.com`, `affiliate.meesho.com`, `prod.meeshoapi.com`, `www.valmo.in`, `superstoreapp.meesho.com`, `investor.meesho.com`. The other 17 (mobile app-store IDs, and 15 more web/wildcard entries like `grocery-supplier.meesho.com`, `*.meeshogcp.in`) are listed but `eligible_for_submission=false` — treated as out of scope per this doc's own rule. Full list with instructions/eligibility flags: `.engagements/meesho/scope.txt` (gitignored) and re-fetchable anytime via `report scopes`.
- **Policy:** pulled live via `hackerfive report weaknesses`/the program resource (`GET /programs/meesho_bbp`) — not a disclose.io/security.txt page. Full policy text + test credentials cached in `.engagements/meesho/policy.md` (gitignored), not reproduced here since it's specific to this HackerOne program, not a public page.
- **Hard requirements** (not optional, program-specified): every test request must carry header `X-Hackerone: <hackerone-username>` (use `--header`); rate-limit testing on the order flow is explicitly disallowed; no real financial transactions; no accessing/changing real user data or account security settings (password/email/2FA); test credentials (provided out-of-band, stored in `.local/`, not this file) exist for the Supplier Panel and Consumer/Mobile flows — don't share them.
- **Fit for HackerFive:** `--detector misconfig` is safe (read-only). `--detector businesslogic`'s mutating checks are hardcoded to crAPI's coupon endpoints and irrelevant/unsafe to point at this target without extensive, individually-reviewed reconfiguration — do not run `--allow-writes` here casually. `--detector authbypass`'s rate-limit-signal check should be avoided or used very conservatively given the explicit order-flow rate-limit restriction.
- **Real finding from first scan (2026-08-30):** `investor.meesho.com` sits behind an Akamai WAF/bot-protection layer that returns an identical "Access Denied" page for almost any path — this originally produced 10 misconfig false positives (the WAF page's boilerplate text trivially matched several `ExposedPaths` keyword rules) before `pkg/detectors/misconfig`'s baseline-canary suppression fix (this session) closed it to a single, accurate `misconfig-waf-blocked` note.
- **Vetted:** 2026-08-30

## Also checked, not added

Found via the same disclose.io search; recorded here so they aren't re-researched later.

| Domain | Why not |
|---|---|
| `aal.mil` | **.mil / US Army domain** (Army Applications Laboratory) — the page checked was a privacy policy, not a VDP; no security-testing authorization exists on it anywhere found. Military domains carry distinct legal exposure beyond a normal VDP — never add one without an explicit, verified DoD-program VDP (e.g. the official DoD program on HackerOne), and never from a bare page like this one. |
| `aapkerala.org` | `security.txt` exists but has no `Policy`/`Scope` field, and no VDP page was found on the site — no discoverable authorization. |
| `aatf.us` | `security.txt` is bare (no `Policy`/`Scope`); its own `Acknowledgments` link has no VDP either. Small 501(c)(3) nonprofit (Asian Arts Talents Foundation) — unlikely to have meaningful attack surface even if a policy turned up. |
| `abax.com` | Both the VDP page and `/.well-known/security.txt` returned 403 to automated fetching — inconclusive, not a rejection. Check manually in a browser before deciding. |
| `ab.co` (ABC Australia) | Redirects to a real-looking "ABC Responsible Disclosure Guideline" at `help.abc.net.au`, but that page returned 403 to automated fetch on repeated tries — inconclusive. A large, credible org (plausible legitimate program), but needs a manual read of the actual policy text before adding. |

## See also
- [21-scanning-real-targets.md](21-scanning-real-targets.md) — the workflow this registry feeds: recon, `--tags`-based template selection, running the scan itself
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — authorization/legal rules this registry's vetting is checked against
