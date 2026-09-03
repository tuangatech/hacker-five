package llmfallback

import (
	"fmt"
	"sync"
)

// envGlobalSpendCeiling and defaultGlobalSpendCeilingUSD: a process-
// lifetime cumulative cap across every Client this process creates —
// added 2026-09-02 per real user feedback that a per-call-only ceiling
// (agenttask.PlanTree.SpendCeilingUSD, one per plan/findings.triage call)
// doesn't bound aggregate spend across many separate calls in a long-lived
// MCP server process ("hundreds of tasks"). This is the coarser, outer
// guard; the per-plan ceiling is the finer-grained one scoped to a single
// resolution pass. Both are USD, both env-overridable, both apply only to
// the frontier tier — the local tier always costs $0 (self-hosted, no
// metered API), so it's never gated by either ceiling.
const (
	envGlobalSpendCeiling        = "HACKERFIVE_SPEND_CEILING_TOTAL_USD"
	defaultGlobalSpendCeilingUSD = 2.00
)

var (
	globalSpendMu  sync.Mutex
	globalSpendUSD float64
)

// GlobalSpendCeilingUSD returns the process-lifetime cumulative cap, read
// fresh from the environment each call (cheap, and lets a test override it
// via t.Setenv without needing a Client rebuilt). <= 0 disables the cap.
func GlobalSpendCeilingUSD() float64 {
	return getenvFloat(envGlobalSpendCeiling, defaultGlobalSpendCeilingUSD)
}

// GlobalSpendSoFar returns the running total of every frontier-tier call's
// real cost, across every Client in this process since it started.
func GlobalSpendSoFar() float64 {
	globalSpendMu.Lock()
	defer globalSpendMu.Unlock()
	return globalSpendUSD
}

// resetGlobalSpendForTest zeroes the process-lifetime counter — test-only,
// unexported since every test that needs it lives in this same package.
func resetGlobalSpendForTest() {
	globalSpendMu.Lock()
	defer globalSpendMu.Unlock()
	globalSpendUSD = 0
}

// globalSpendExceeded reports whether the ceiling is already reached
// before a frontier-tier call is made — checked before, not just recorded
// after, so an already-exhausted global budget refuses the network call
// outright rather than always allowing "one more."
func globalSpendExceeded() bool {
	ceiling := GlobalSpendCeilingUSD()
	if ceiling <= 0 {
		return false
	}
	return GlobalSpendSoFar() >= ceiling
}

func addGlobalSpend(usd float64) {
	if usd <= 0 {
		return
	}
	globalSpendMu.Lock()
	globalSpendUSD += usd
	globalSpendMu.Unlock()
}

// errGlobalSpendCeilingExceeded is returned by complete (not wrapped
// further) so callers can distinguish "budget exhausted" from a genuine
// network/model error if they ever need to — today every caller treats it
// like any other fallback-call failure (escalate to human), per the same
// posture as a per-plan ceiling trip.
func errGlobalSpendCeilingExceeded() error {
	return fmt.Errorf("llmfallback: process-lifetime spend ceiling ($%.2f, %s) already reached — refusing further frontier-tier calls", GlobalSpendCeilingUSD(), envGlobalSpendCeiling)
}
