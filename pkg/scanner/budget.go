package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// targetCtx derives a per-target context that cancels after d (LT-79's
// --max-target-duration). d <= 0 means no cap — the parent ctx is returned
// with a no-op cancel so the caller's `defer cancel()` is always safe.
func targetCtx(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return parent, func() {}
	}
	return context.WithTimeout(parent, d)
}

// timeBudgetFinding records that a target hit its --max-target-duration cap
// before the corpus finished (LT-79). Informational severity: it is a
// coverage gap, not a vulnerability.
func timeBudgetFinding(target string, budget time.Duration, ran, total int) detectors.Finding {
	return detectors.Finding{
		ID:         "scan-partial-time-budget",
		Type:       "scan-meta",
		Severity:   "info",
		Confidence: "high",
		Target:     target,
		Description: fmt.Sprintf(
			"stopped dispatching templates for this target after the --max-target-duration budget of %s (roughly %d of %d templates started) — a slow or throttled host can otherwise consume the whole run; raise --max-target-duration or narrow --tags to cover the rest",
			budget, ran, total),
		Evidence: map[string]string{
			"max_target_duration": budget.String(),
			"templates_started":   fmt.Sprintf("%d", ran),
			"templates_total":     fmt.Sprintf("%d", total),
		},
	}
}

// adaptiveAbortFinding records that the adaptive throttle gave up on a
// target mid-run (LT-74 / LT-88). reason is "rate-limited" (sustained
// 429/503) or "unreachable" (a connect-failure spike after the host had
// been answering). ran/total are 0 when the trip was inherited from an
// earlier target in the same run.
func adaptiveAbortFinding(target, reason string, ran, total int) detectors.Finding {
	id, desc := "scan-target-rate-limited", "upstream returned sustained 429/503 — it is throttling the scan; results for this target are unreliable and template dispatch was stopped"
	if reason == "unreachable" {
		id = "scan-target-unreachable-mid-run"
		desc = "connect failures spiked mid-scan against a host that was answering earlier (a likely source-IP block or origin cut-off) — template dispatch was stopped"
	}
	if total > 0 {
		desc = fmt.Sprintf("%s (roughly %d of %d templates started)", desc, ran, total)
	}
	return detectors.Finding{
		ID:          id,
		Type:        "scan-meta",
		Severity:    "info",
		Confidence:  "high",
		Target:      target,
		Description: desc + ". Back off, verify the target is reachable from this egress, and re-run — consider a lower --rate-limit or an in-region egress.",
		Evidence: map[string]string{
			"reason":          reason,
			"adaptive_action": "rate halved on the first bad window, target aborted on the second (LT-74/LT-88)",
		},
	}
}
