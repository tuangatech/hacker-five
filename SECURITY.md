# Security Policy

This doc is about vulnerabilities **in HackerFive itself** — a bug in this codebase (e.g. a way a malicious template could escape its sandboxing, a parser crash, a credential-handling bug). It is not about vulnerabilities HackerFive *finds* when scanning some other target — that workflow (responsible disclosure to the *target's* program) is covered in [docs/05-hackerone-and-legal.md](docs/05-hackerone-and-legal.md), a separate concern.

## Reporting a vulnerability in HackerFive

Please **do not** open a public GitHub issue for a security vulnerability in this project.

Instead, use [GitHub's private vulnerability reporting](https://github.com/tuangatech/hacker-five/security/advisories/new) for this repository, which opens a private advisory only visible to maintainers until a fix is ready.

Please include:
- What version/commit you're on.
- Steps to reproduce, or a minimal template/input that triggers the issue.
- What you'd expect to happen instead.

## Scope

Examples of what's in scope here: a Nuclei-compatible or native template that can trigger unintended code execution, file access, or network egress beyond the target being scanned; a parser crash/panic on malformed input (some of this is already covered by fuzz testing — see `docs/10-implementation-plan-ph1b.md` Step 4 — but gaps are still worth reporting); credential/token handling that doesn't follow this project's env-var-only rule (see [CLAUDE.md](CLAUDE.md)).

Out of scope: the fact that HackerFive, used against an authorized target, finds a real vulnerability *in that target* — that's the tool working as intended, not a bug in HackerFive.

## Supported versions

This project is pre-1.0 (`v0.x`). Security fixes land on `main` and the most recent tagged release; older `v0.x` tags don't get backports.
