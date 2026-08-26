## What and why

<!-- What changed, and why — the diff already shows what, focus on why. Link the issue this addresses if there is one. -->

## Checklist

- [ ] `make build test lint` passes locally
- [ ] Tests added/updated for the change
- [ ] If this adds/changes a detector or template: stays inside the <5% false-positive target (docs/03-development-roadmap.md)
- [ ] If this adds a Nuclei-compatible template by hand: stays inside the supported subset (docs/template-writing-guide.md) — no `raw:`/`payloads:`/`flow:`/disallowed protocol blocks
- [ ] Docs updated if this changes user-facing behavior (README, docs/template-writing-guide.md, or CLI `--help` text)
