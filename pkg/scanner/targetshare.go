package scanner

// Per-target rate share (docs/follow-up.md LT-106, the runtime half).
//
// One ratelimit.Limiter (ratelimit.New(cfg.RateLimit)) caps aggregate req/s
// across the whole scan. When many targets run concurrently they split that
// one bucket between them, so the effective per-target rate is
// RateLimit / (targets in flight). Against a large synced corpus and a
// per-target --max-target-duration budget that collapses to "dispatched
// ~0 templates before the budget fired" (LT-114: 8 hosts sharing
// --rate-limit 10 == 1.25 req/s each, and the budget expires having started
// 0-3 of thousands of templates).
//
// The fix is the LT's "scan fewer targets at a time when the loaded set is
// large" option: cap the cross-target worker pool so each in-flight target
// keeps at least minPerTargetShareQPS of the shared bucket. Total wall-clock
// is similar either way (the rate limiter is the real cap), but each target
// now actually gets its corpus dispatched instead of every target getting a
// thin, useless slice. A small --templates set or a native-only run is
// unaffected — the starvation only bites when thousands of templates compete
// for a per-target sliver.

const (
	// minPerTargetShareQPS is the floor req/s each in-flight target keeps of
	// the shared --rate-limit bucket once largeCorpusShareThreshold templates
	// are loaded. 5 req/s over a typical --max-target-duration of a few
	// minutes is ~900-1800 dispatched templates per target — enough for the
	// dispatch-priority order (dispatchorder.go) to reach the
	// misconfiguration/exposure/tech checks, not just the CVE tail.
	minPerTargetShareQPS = 5

	// largeCorpusShareThreshold is the loaded nuclei-template count past
	// which the per-target share is enforced. Below it, the corpus is small
	// enough (a scoped --templates dir, a tag-narrowed set, native-only) that
	// even a thin per-target rate dispatches all of it well inside any sane
	// budget, so the full configured cross-target concurrency stands.
	largeCorpusShareThreshold = 500
)

// effectiveTargetConcurrency returns the cross-target worker-pool size to use
// for this run: the configured value, reduced when a large nuclei corpus is
// loaded so that rateLimit / result >= minPerTargetShareQPS. It never raises
// concurrency above configured, never returns below 1, and is a no-op (returns
// configured) for a single target or a sub-threshold corpus. Pure function —
// all wiring and the operator-facing warning live in Run.
func effectiveTargetConcurrency(configured, rateLimit, nucleiCount, targets int) int {
	if configured < 1 {
		configured = 1
	}
	if targets <= 1 || nucleiCount < largeCorpusShareThreshold {
		return configured
	}
	share := rateLimit / minPerTargetShareQPS
	if share < 1 {
		share = 1
	}
	if share < configured {
		return share
	}
	return configured
}
