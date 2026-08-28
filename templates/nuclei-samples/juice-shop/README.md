# Juice Shop-targeted sample templates

One real, unmodified upstream template — added 2026-08-27 as part of Future Enhancement #3 ([docs/10-implementation-plan-ph1b.md](../../../docs/10-implementation-plan-ph1b.md)), which closed the gap between "this template already proved it fires live against a real target" and "this template actually ships in the default `templates/` bundle."

Unlike [dvwa-php/](../dvwa-php/) and [crapi/](../crapi/), which were picked *before* a live run (reconning the target, then guessing which upstream templates had a real chance), this one was picked *after* the fact: Step 2's "Fourth live run" (full synced-corpus scan against a live Juice Shop instance, 2026-08-25) already found it produces a genuine finding — `owasp-juice-shop-detect.yaml` (upstream filename `owasp-juice-shop-detected.yaml`), fingerprinting Juice Shop by its `<title>OWASP Juice Shop</title>` marker. `http-missing-security-headers.yaml`, Juice Shop's other live finding from that same run, is already in [dvwa-php/](../dvwa-php/) and fires against Juice Shop too — templates aren't target-restricted, every loaded template runs against every scanned target — so it didn't need a second copy here.

**Not independently re-verified live in this session** — this checkout has no Docker/live Juice Shop access; the live result being relied on here is the one already recorded in doc10 from the 2026-08-25 run, not a fresh one. `tests/unit/nuclei_juice_shop_samples_test.go` confirms only that the file loads cleanly with the expected `id:`.

| File | Category | Live result (doc10, 2026-08-25) |
|---|---|---|
| `owasp-juice-shop-detect.yaml` | `http/technologies` | ✅ 1 finding — matches `<title>OWASP Juice Shop</title>` in the response body |
