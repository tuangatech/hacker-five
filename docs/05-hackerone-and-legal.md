# HackerOne & Bug Bounty Workflow, Security & Legal Considerations

> Part of the [HackerFive documentation set](../README.md). Trimmed 2026-09-02 to focus on what's specific to running this tool responsibly — HackerOne's own onboarding (account creation, profile setup, payout/tax settings) is covered by HackerOne's own docs, not repeated here.

## Prerequisites Before Testing a Real Program

### Legal & Ethical
- [ ] Read HackerOne's terms of service and understand responsible disclosure
- [ ] Understand scope limitations — only test targets a program has explicitly authorized
- [ ] Never access data you're not supposed to; DoS/disruption is always prohibited
- [ ] Sign up as an individual if working solo

### Tool Maturity Gate (see [03-development-roadmap.md](03-development-roadmap.md) for the full checklist)
- [ ] v0.2+ released (minimum IDOR + misconfiguration + XSS)
- [ ] <5% false positive rate validated
- [ ] Documentation complete
- [ ] Docker image available
- [ ] Throughput validated against local lab targets (see [02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md) — that figure is a lab-target capability number, not a real-target operating rate; see this doc's own Rate Limits section below)

## Reading a Program's Scope

Each program defines:
- **In-scope:** domains/APIs to test, vulnerability types that count, examples of what's been paid before.
- **Out-of-scope:** rate limiting/DoS/brute force (almost always excluded), third-party services, physical security, social engineering.

**Rule:** If it's not explicitly in scope, don't test it.

## Automated Scanning Policy

Most bug bounty programs do not explicitly permit automated, tool-driven scanning. A minority prohibit it outright; the rest are simply silent — silence means "ask first," not "allowed."

- Check the program's own policy page for language like "automated scanning," "scanners," or "tools." Explicit permission is rare — treat its absence as automation being unauthorized until confirmed otherwise.
- Only point HackerFive at a program that has explicitly opted into automated testing. Everywhere else, a human drives the tool interactively (one template/detector at a time, reviewing each result) rather than firing the full corpus unattended.
- See "Rate Limits & Concurrency Against Real Targets" below for what "acting like a polite human, not a bot" means in practice.

## Target Selection

### Suitable for automation
Emerging targets not yet heavily scanned, stable APIs (less likely to change scope mid-engagement), large scopes, API-heavy companies (SaaS/fintech/e-commerce — this tool's sweet spot for IDOR/auth/logic flaws).

### Avoid early
Huge, hyper-competitive programs (Microsoft/Google/Apple-scale); bounties under $100; programs with many already-resolved reports (likely already picked over).

## Responsible Disclosure Workflow

1. **Confirm, don't trust blindly.** A tool-reported finding is a lead, not a report — manually verify with `curl`/Burp before writing anything up.
2. **Write the report**: one-sentence summary, vulnerability details (what/where/how), copy-paste reproduction steps, a PoC (curl command, screenshot, or tool output), real impact (what can an attacker actually do), and a recommended fix.
3. **Submit through the program's own form**, respond to clarification requests promptly, stay professional, and don't disclose publicly until the program authorizes it.

## See also
- [03-development-roadmap.md](03-development-roadmap.md) — tool maturity gates required before joining HackerOne
- [21-scanning-real-targets.md](21-scanning-real-targets.md) — the concrete scan workflow once a target from this page's process is actually authorized

---

## Security & Legal Considerations

### Running the Tool Against Live Programs: CLI, Not a Container

Once a program's scope is confirmed, run HackerFive as the **native CLI binary**, not the Docker image, for actual bounty work:
- Bug-hunting is interactive and iterative — tweak a template, rerun, check the Burp/MitmProxy trace, inspect output. A native binary has none of the friction a container adds: no volume-mounting for output files, no `host.docker.internal` indirection just to route `--proxy` to a proxy running on your own machine.
- This is also the reason Go/single-static-binary was chosen in the first place ([02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)) and why cross-platform `goreleaser` binaries are the planned release artifact — `curl`/`brew install`/download-and-run is the intended experience for the primary user (independent bug hunters), matching Nuclei's own distribution model.

The Docker image still ships and still earns its keep elsewhere — CI pipelines (the deferred GitHub Action) and unattended/scheduled scans on a remote server — but it's a secondary distribution path, not how you'd run a hands-on engagement against a real program.

Regardless of which one you run: only ever point either at hosts explicitly listed in a program's scope, same authorization boundary either way.

### Legal Requirements

- **Authorization**: always only test targets within a program's scope; never test outside scope without explicit written permission. Unauthorized testing is illegal (Computer Fraud & Abuse Act in the US, similar laws elsewhere).
- **Responsible disclosure**: report vulnerabilities directly to the program (never publicly first), honor their patch timeline (usually 90 days), never weaponize or sell exploits, never use a finding for personal leverage.
- **Data handling**: don't retain PII longer than necessary, don't download large datasets, don't exfiltrate credentials or API keys — test with minimal data impact.
- **Tax**: bounties are taxable income in most jurisdictions (in the US, HackerOne issues a 1099 for earnings over $600) — keep records and consult a tax advisor if unsure.

### Tool Security

- **No malicious payloads**: never deploy shellcode/reverse shells, never exfiltrate data, never modify target systems — only read/enumerate, never write/destroy (see CLAUDE.md's `--allow-writes` exception, which is scoped and opt-in even then).
- **Secure credential handling**: load tokens/keys from environment variables only, never hardcode them.
- **Request logging**: log request/response headers (sanitized — no tokens/keys) and URLs/methods/timestamps; never log response bodies (may contain PII); provide `--no-log-requests` for users who want privacy.
- **HTTPS/TLS**: verify certificates by default; `--insecure` is for local lab targets only, never a real target.

### Rate Limits & Concurrency Against Real Targets

[02-architecture-and-tech-stack.md](02-architecture-and-tech-stack.md)'s "150+ req/sec" figure is the engine's raw architectural throughput capacity, demonstrated against local lab targets — it is **not** a recommended operating rate against a real program, and the two should never be conflated. Against an authorized real target:
- Default concurrency is 25 workers (max 100) — that cap exists to bound the *engine's* behavior, not to license running it that hard against a live program.
- Start well below both: 5-10 req/sec is a reasonable default absent other guidance, and always defer to a program's own stated rate limits when they publish one.
- Run a small, targeted template/tag set for the first pass (start with `misconfig`, the lowest-risk detector) rather than the full corpus — expand only once you've confirmed the program tolerates it.
- Add delays between targets and use cooldown mechanisms; never test outside authorized scope.
- If you discover something out of scope, report it separately — don't exploit it. Stop immediately if a program asks you to.
- Report findings truthfully (don't exaggerate severity), never manufacture false positives, and never sell findings to other buyers.
