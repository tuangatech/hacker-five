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
