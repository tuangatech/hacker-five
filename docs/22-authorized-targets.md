# Authorized Targets Registry

> Part of the [HackerFive documentation set](../README.md).

A living list of real, authorized targets (found via disclose.io/HackerOne per [21-scanning-real-targets.md](21-scanning-real-targets.md) §1) that have been vetted for testing with HackerFive — so the vetting work (reading the policy, cross-checking `security.txt`, judging fit) isn't repeated from scratch each time.

**Being listed here does not substitute for reading a target's full policy yourself before scanning** — see [doc05](05-hackerone-and-legal.md)'s "Read Program Scope" rule. Policies change; re-check `security.txt`'s `Expires` field before relying on an old entry.

**Weak fit: a program whose reward path is *bypassing* a WAF / upload filter.** If the bounty premise is "get a payload past our Secure Gateway / edge filter" (ALSCO's `securegateway.com` sandboxes, 2026-09-07), signature-driven scanning is near-zero yield and every blocked payload feeds the WAF's auto-ban heuristic — HackerFive has no WAF-fingerprint step, no "403-on-payload vs 200-on-benign = rule boundary" reasoning, no payload mutation/encoding retry, and no `uploadbypass` / native `sqli`/`xss`/`lfi` detector yet (all scheduled [Phase 9](18-implementation-plan-ph9.md) Step 4, LT-87). Until those land, treat such a program as out of scope for an automated run; a thin recon pass plus manual testing is the only fit.

**Finding new targets:** [disclose.io's directory, filtered to level ≥4](https://directory.disclose.io/?min_level=4) (disclose.io's own maturity scale — level 4+ policies carry an explicit legal safe-harbor commitment, not just a bare contact address) is the standing starting point for sourcing new candidates, rather than an open-ended web search. A candidate found there still needs the same vetting as any other entry here: fetch its `security.txt`/policy page, confirm scope is a real, named domain (not a vague "our systems" with nothing enumerated), and check whether it explicitly allows, bans, or is silent on automated scanning (silent + an explicit safe harbor + no destructive-testing restriction has been treated as a good fit for `--detector misconfig`, matching a2x.io/abc8.immobilien's precedent below; an explicit ban on automated scanning is a hard skip regardless of how the rest of the policy reads).

**Machine-readable companion (D2 pre-flight, [doc15](15-implementation-plan-ph6.md) Step 3):** the vetting recorded here in prose can be mirrored into a gitignored `policy.yaml` (`.engagements/<name>/policy.yaml`, or `.engagements/policy.yaml` for all engagements — see `policy.yaml.example` at the repo root). `hackerfive scan`/`recon`/`plan` (CLI and MCP) then hard-refuse a target with an `automated_scanning: disallowed` entry, and print an advisory warning for one that's `unknown` or absent. It only enforces an explicit "no" — it is not a substitute for this doc's judgement, just a guardrail against running against a target you've already determined bans scanners. A `disallowed`-marked target here (none currently) should get a `policy.yaml` entry.

## Active targets

### a16z.com
- **Source:** disclose.io / own `security.txt`
- **Policy:** [a16z.com/security-policy](https://a16z.com/security-policy) — confirmed via `/.well-known/security.txt` (Contact `cirt@a16z.com`, Expires 2027-07-15)
- **Scope:** a16z.com domain and subdomains
- **Safe harbor:** explicit — exempts good-faith research from ToS/AUP and applicable anti-hacking law claims within their control
- **Restrictions:** avoid privacy violations/disruption/unauthorized access/data destruction; limit data access to the minimum needed to demonstrate a PoC; stop and report immediately if real user data is encountered; **only interact with test accounts you own or have explicit permission for** — no cross-account testing without one; 90-day disclosure window before going public
- **Bounty:** none (pure VDP)
- **Fit for HackerFive:** good for `--detector misconfig` (read-only, no account needed). `idor`/`authbypass` cross-account checks are out unless a test account is separately arranged — the policy explicitly requires owning or being permitted to use any account tested.
- **Vetted:** 2026-09-12

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
- **Hard requirement (2026-09-02):** automated scanning is permitted, capped at **no more than 5 scan runs per day** against this target. HackerFive has no built-in per-day run counter — this is a manual limit the operator must track themselves, not something `--rate-limit`/`--concurrency` (which bound requests/sec within one run, not runs/day) enforce.
- **Fit for HackerFive:** ✅ resolved — the earlier "third-party tools" ambiguity (same clause as DDoS/social engineering) is confirmed to mean third-party attack services, not vulnerability scanners; automated scanning is explicitly authorized subject to the 5-runs/day cap above.
- **Vetted:** 2026-08-26, resolved 2026-09-02

### abc8.immobilien
- **Source:** disclose.io
- **Policy:** [abc8.immobilien/security-policy](https://abc8.immobilien/security-policy/) — confirmed via `/.well-known/security.txt` (Contact + Policy fields consistent)
- **Scope:** "this domain, its subdomains, and services operated directly by us"; third-party services out of scope — same wording as a2x.io's policy
- **Safe harbor:** explicit
- **Restrictions:** no DoS/destructive testing, no privacy/data-confidentiality violations, exploitation limited to what's necessary to demonstrate the issue
- **Bounty:** none (pure VDP)
- **Fit for HackerFive:** good — same shape as a2x.io, `--detector misconfig`'s read-only design matches their "no destructive testing" rule directly
- **Vetted:** 2026-08-26

### ably.com
- **Source:** own disclosure page (`ably.com/disclosure`)
- **Policy:** [ably.com/disclosure](https://ably.com/disclosure)
- **Scope:** `ably.com` + subdomains, plus named production realtime endpoints (`main.realtime.ably.net`, `realtime.ably.io`, `rest.ably.io`) and customer CNAME domains; `support.ably.com` and other non-customer-facing/internal services out of scope
- **Safe harbor:** explicit
- **Restrictions:** no targeted brute-force (e.g. probing rate limits via repeated password attempts), no DoS, no malware/phishing/physical attacks; good-faith effort to avoid privacy violations/data destruction/service disruption; low-quality/AI-generated reports rejected
- **Bounty:** yes — tiered, Low $150 / Medium $500 / High $1,500 / Critical $5,000, discretionary
- **Fit for HackerFive:** good — `--detector misconfig` fits; scope the target list to exactly the named domains/endpoints above, not a broader `*.ably.com` guess
- **Vetted:** 2026-09-12

### aetherweb.co.uk
- **Source:** own VDP page (`aetherweb.co.uk/vulnerability-disclosure-policy-vdp/`)
- **Policy:** [aetherweb.co.uk/vulnerability-disclosure-policy-vdp](https://www.aetherweb.co.uk/vulnerability-disclosure-policy-vdp/)
- **Scope:** `aetherweb.co.uk` + owned subdomains; explicitly lists IDOR/CSRF/SSRF/authorization-bypass, injection (SQLi/XSS/template/header), sensitive-data-exposure, and misconfiguration-with-real-impact as in-scope classes
- **Safe harbor:** explicit
- **Restrictions:** no DoS/stress testing, no accessing/altering real customer data, no social engineering/malware, no persistence beyond proving impact; third-party services, self-XSS, and missing-headers-without-practical-risk out of scope
- **Bounty:** none (explicitly no monetary reward — non-bounty program)
- **Fit for HackerFive:** ✅ best fit found so far — **explicitly names "low-rate automated scanning" as allowed**, and its in-scope vuln list lines up directly with `idor`/`ssrf`/`sqli`/`authbypass`/`misconfig`
- **Vetted:** 2026-09-12

### yosmart.com (YoLink/YoSmart)
- **Source:** own security policy page (`shop.yosmart.com/pages/security-policy`)
- **Policy:** [shop.yosmart.com/pages/security-policy](https://shop.yosmart.com/pages/security-policy)
- **Scope:** `*.yosmart.com` (web/API); also covers the YoLink mobile apps and current-gen hardware, both out of HackerFive's remit — scan only the web/API portion
- **Safe harbor:** explicit
- **Restrictions:** no accessing/modifying/deleting data that isn't yours; no volume-based DoS/DDoS; automated scanning not explicitly addressed either way
- **Bounty:** none (non-monetary recognition only, with permission)
- **Fit for HackerFive:** good — `--detector misconfig` against `*.yosmart.com`, same "explicit safe harbor + no destructive-testing ban + scanning unaddressed" shape as a2x.io/abc8.immobilien
- **Vetted:** 2026-09-12

### weglot.com
- **Source:** own responsible-disclosure page (`weglot.com/responsible-disclosure`)
- **Policy:** [weglot.com/responsible-disclosure](https://www.weglot.com/responsible-disclosure)
- **Scope:** `weglot.com` and `dashboard.weglot.com` only — `academy.`/`developers.`/`support.weglot.com` explicitly excluded (third-party hosted)
- **Safe harbor:** explicit
- **Restrictions:** DoS/DDoS explicitly excluded from scope; physical testing, social engineering, and UI-only bugs out of scope; automated scanning not explicitly addressed
- **Bounty:** none (a "Security Researcher Hall of Fame," under construction)
- **Fit for HackerFive:** good — narrow, explicit two-domain scope; `--detector misconfig` fits the same precedent as a2x.io/abc8.immobilien
- **Vetted:** 2026-09-12

### meesho_bbp (Meesho)
- **Source:** HackerOne program the user is an active participant in (`https://hackerone.com/meesho_bbp`), not disclose.io — vetted directly via the real HackerOne API (`pkg/hackerone`) rather than a security.txt lookup.
- **Scope:** pulled live via `hackerfive report scopes --team meesho_bbp` (2026-08-30) — of 25 listed structured-scope entries, only 8 are `eligible_for_submission=true` web/API assets: `www.meesho.com`, `admin.meeshosupply.com`, `supplier.meesho.com`, `affiliate.meesho.com`, `prod.meeshoapi.com`, `www.valmo.in`, `superstoreapp.meesho.com`, `investor.meesho.com`. The other 17 (mobile app-store IDs, and 15 more web/wildcard entries like `grocery-supplier.meesho.com`, `*.meeshogcp.in`) are listed but `eligible_for_submission=false` — treated as out of scope per this doc's own rule. Full list with instructions/eligibility flags: `.engagements/meesho/scope.txt` (gitignored) and re-fetchable anytime via `report scopes`.
- **Policy:** pulled live via `hackerfive report weaknesses`/the program resource (`GET /programs/meesho_bbp`) — not a disclose.io/security.txt page. Full policy text + test credentials cached in `.engagements/meesho/policy.md` (gitignored), not reproduced here since it's specific to this HackerOne program, not a public page.
- **Hard requirements** (not optional, program-specified): every test request must carry header `X-Hackerone: <hackerone-username>` (use `--header`); rate-limit testing on the order flow is explicitly disallowed; no real financial transactions; no accessing/changing real user data or account security settings (password/email/2FA); test credentials (provided out-of-band, stored in `.engagements/meesho/policy.md`, gitignored, not this file) exist for the Supplier Panel and Consumer/Mobile flows — don't share them.
- **Fit for HackerFive:** `--detector misconfig` is safe (read-only). `--detector businesslogic`'s mutating checks are hardcoded to crAPI's coupon endpoints and irrelevant/unsafe to point at this target without extensive, individually-reviewed reconfiguration — do not run `--allow-writes` here casually. `--detector authbypass`'s rate-limit-signal check should be avoided or used very conservatively given the explicit order-flow rate-limit restriction.
- **Real finding from first scan (2026-08-30):** `investor.meesho.com` sits behind an Akamai WAF/bot-protection layer that returns an identical "Access Denied" page for almost any path — this originally produced 10 misconfig false positives (the WAF page's boilerplate text trivially matched several `ExposedPaths` keyword rules) before `pkg/detectors/misconfig`'s baseline-canary suppression fix (this session) closed it to a single, accurate `misconfig-waf-blocked` note.
- **Vetted:** 2026-08-30

### shopify (Shopify)
- **Source:** HackerOne program the user is an active participant in (`https://hackerone.com/shopify`), not disclose.io — vetted directly via the real HackerOne API (`pkg/hackerone`).
- **Scope:** pulled live via `hackerfive report scopes --team shopify` (2026-09-01). `www.shopify.com` (the marketing site) is **not** in the structured scope at all — only `*.shopify.com` gets a discouraging mention ("reviewed per-case, unlikely bounty-eligible without demonstrated impact on `*.myshopify.com` users"). Real submittable web/API assets: `admin.shopify.com`, `partners.shopify.com`, `accounts.shopify.com`, `shop.app`, `shopify.plus`, `linkpop.com`, `shopifyinbox.com`, `arrive-server.shopifycloud.com`, `your-store.myshopify.com` (needs a dev store created first), plus wildcards `*.shopify.io`/`*.shopifykloud.com`/`*.shopifycloud.com`/`*.shopifycs.com`. Full list: `.engagements/shopify/scope.txt` (gitignored).
- **Policy:** pulled live via `GET /programs/shopify`'s `policy` attribute. Full text cached in `.engagements/shopify/policy.md` (gitignored).
- **Hard requirements:** only test against Shopify stores you created yourself with a HackerOne-aliased email (`YOURHANDLE@wearehackerone.com`) — this restricts `*.myshopify.com` storefront testing specifically, not corporate assets like `partners.shopify.com`/`admin.shopify.com`. Never contact Shopify Support during testing (disqualifying). No explicit rate-limit/header requirement stated (unlike Meesho).
- **Fit for HackerFive:** `--detector misconfig` is safe (read-only) against the Core corporate assets. No dedicated dev-store setup done yet, so `*.myshopify.com` storefront-level testing hasn't started.
- **Real finding from first scan (2026-09-01):** `partners.shopify.com` is missing `Content-Security-Policy`/`X-Frame-Options` headers — real but likely non-actionable without a demonstrated-impact PoC per Shopify's policy (bare missing-header reports are commonly closed N/A). Scan also surfaced and fixed a real `pkg/detectors/misconfig` false-positive bug: `PUT`/`DELETE`/`PATCH` on `/` returning the same generic Rails 404 page was wrongly classified as "method accepted."
- **Vetted:** 2026-09-01

## Owned / operator-authorized targets

Unlike the disclose.io/HackerOne entries above, these are the operator's own properties — the domain list itself (`.engagements/owned-sites/scope.txt`, gitignored) is the authorization, not a third-party VDP/program policy. No `security.txt`/policy page to vet, no bounty, no third-party restrictions to cross-check — but also no independent confirmation from anyone else, so treat these as lower-ceremony but not lower-caution: still read-only by default (no `--allow-writes`), still rate-limited, still logged.

| Domain | Confirmed with a third party? | Notes |
|---|---|---|
| `aalberts.com` | Yes — see the dedicated entry above (disclose.io VDP + explicit 5-runs/day cap agreed with their security team 2026-09-02) | Listed in both places since it's both operator-confirmed *and* a real disclose.io program |
| `andertone.com` | No | Operator-owned; user-confirmed 2026-09-04 |
| `aceautowreckers.com` | No | Operator-owned; user-confirmed 2026-09-04 |
| `nettix.com.pe` | No | Operator-owned; user-confirmed 2026-09-04. First HackerFive run: 2026-09-04 |

**Fit for HackerFive:** all four covered by `.engagements/owned-sites/scope.txt` (`*.`-wildcarded, so subdomains are in scope too). No detector-specific restrictions recorded — apply the same defaults as any other target (`--allow-writes` opt-in only for `businesslogic`, respect `--rate-limit`).

## Also checked, not added

Found via the same disclose.io search; recorded here so they aren't re-researched later.

| Domain | Why not |
|---|---|
| `aal.mil` | **.mil / US Army domain** (Army Applications Laboratory) — the page checked was a privacy policy, not a VDP; no security-testing authorization exists on it anywhere found. Military domains carry distinct legal exposure beyond a normal VDP — never add one without an explicit, verified DoD-program VDP (e.g. the official DoD program on HackerOne), and never from a bare page like this one. |
| `aapkerala.org` | `security.txt` exists but has no `Policy`/`Scope` field, and no VDP page was found on the site — no discoverable authorization. |
| `aatf.us` | `security.txt` is bare (no `Policy`/`Scope`); its own `Acknowledgments` link has no VDP either. Small 501(c)(3) nonprofit (Asian Arts Talents Foundation) — unlikely to have meaningful attack surface even if a policy turned up. |
| `abax.com` | Both the VDP page and `/.well-known/security.txt` returned 403 to automated fetching — inconclusive, not a rejection. Check manually in a browser before deciding. |
| `ab.co` (ABC Australia) | Redirects to a real-looking "ABC Responsible Disclosure Guideline" at `help.abc.net.au`, but that page returned 403 to automated fetch on repeated tries — inconclusive. A large, credible org (plausible legitimate program), but needs a manual read of the actual policy text before adding. |
| `box_private` (Box BB — `*.box.com`, `*.boxcloud.com`, `signrequest.com`, `sr-staging-1.com`) | **Private HackerOne program the operator is a member of** (scope + policy pulled 2026-09-07). **Policy explicitly bans automated scanners** — "The use of automated scanners is prohibited" (×3), "Mass scanning, indiscriminate automation, high-volume enumeration ... and use of automated vulnerability scanners are prohibited". No HackerFive mode (recon included) fits its "limited automation must be low-volume, narrowly targeted, non-disruptive" carve-out. Also: only researcher-owned Box accounts may be tested, and nearly every `misconfig`-detector output class is on its excluded-findings list. `signrequest.com` runs an auto-blocking `/administrator` honeypot. Manual, account-scoped, PoC-driven testing only. Recorded as a hard block in `.engagements/box_private/policy.yaml` (`automated_scanning: disallowed`). |
| `abuse.io` | Explicit ban: "heavy automated scanning" listed alongside DDoS as prohibited. Scope is also narrow (a handful of named domains + specific IP/CIDR ranges + GitHub repos). Would need written clarification that a light, rate-limited pass doesn't count as "heavy" before reconsidering. |
| `accodeing.com` | Explicit exclusion: "results from automated tools or scans" don't qualify for a reward — reads as "don't run a scanner here," not a reward-eligibility nuance. |
| `adidasfoundation.org` | Scope is clean (`adidasfoundation.org/*` only) and safe harbor is explicit, but automated scanning is neither allowed nor banned and there's no bounty to weigh against the ambiguity. Email to confirm before running anything, rather than assume silence means yes. |
| `aarts.info` | Coordinated disclosure + reward program exist, but "avoid ... third-party tools" is the same ambiguous phrase aalberts.com's policy once had — that resolution (meant attack *services*, not scanners) doesn't carry over to a different organization. Needs its own confirmation email. |
| `zenity.io` | Safe harbor explicit, but scope is only "any digital assets owned by Zenity Ltd/Inc" — no domain named at all, unlike a2x.io's "this domain, its subdomains" wording. Nothing concrete to point HackerFive at without asking them to name assets first. |
| `zerocopter.com` | The URL checked (`/coordinated-vulnerability-disclosure-policy/`) is Zerocopter's own generic CVD-platform template page, not a specific customer's scoped program — it names no company's domain to test. Not a vettable target on its own; a real Zerocopter-hosted customer program page would be. |
| `webflow-vdp-pro` (Bugcrowd) | Page is JS-rendered — automated fetch only returned the nav/login shell, no scope/policy text. Inconclusive, same as `abax.com`/`ab.co` above — needs a manual browser check or the Bugcrowd API before deciding. |

## See also
- [21-scanning-real-targets.md](21-scanning-real-targets.md) — the workflow this registry feeds: recon, `--tags`-based template selection, running the scan itself
- [23-live-testing-playbook.md](23-live-testing-playbook.md) — check before every round and update after: settings, monitoring, verification, and how to log a new enhancement
- [05-hackerone-and-legal.md](05-hackerone-and-legal.md) — authorization/legal rules this registry's vetting is checked against
