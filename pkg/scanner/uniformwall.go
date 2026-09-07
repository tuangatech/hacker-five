package scanner

import (
	"fmt"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/uniformwall"
)

// uniformWallGate answers "did recon classify this target's host as a
// uniform response wall?" for Run's D6 corpus short-circuit
// (docs/16-implementation-plan-ph7.md Step 4, docs/follow-up.md LT-59). It
// reads the verdict a prior recon pass recorded on
// ReconResult.UniformResponse, threaded in via cfg.UniformWallHosts by the
// frontend (cmd/hackerfive/scan.go's --recon-file parse, pkg/webui,
// pkg/mcpserver).
//
// The engine deliberately does NOT probe inline: a scan run without a
// --recon-file is already scoped to the misconfig category floor (no tech
// tags to widen it) and the misconfig detector emits its own
// `misconfig-waf-blocked` on a walled host — the expensive case D6 targets
// is the ~2,200-template `--recon-file` corpus, which by definition has a
// recon result to carry the verdict. Probing every mock httptest server
// inline also mislabels a fixed-response test fixture as a catch-all.
type uniformWallGate struct {
	hints map[string]string // host -> "waf-block" | "catchall"
}

func newUniformWallGate(e *Engine) *uniformWallGate {
	return &uniformWallGate{hints: e.cfg.UniformWallHosts}
}

// verdict returns the recon-recorded uniform-wall classification for host,
// "" when recon saw normal routing (or ran without Wave 3).
func (g *uniformWallGate) verdict(host string) uniformwall.Verdict {
	if kind, ok := g.hints[host]; ok {
		return uniformwall.Verdict(kind)
	}
	return uniformwall.VerdictNone
}

// uniformWallFinding is the one finding Run emits in place of the skipped
// template corpus for a walled target. A "waf-block" verdict reuses the
// misconfig detector's own `misconfig-waf-blocked` ID so reporter.Dedup
// collapses the pair when --detector misconfig also ran; "catchall" gets its
// own ID.
func uniformWallFinding(target string, v uniformwall.Verdict) detectors.Finding {
	switch v {
	case uniformwall.VerdictWAFBlock:
		return detectors.Finding{
			ID:          "misconfig-waf-blocked",
			Type:        "misconfig",
			Severity:    "low",
			Confidence:  "low",
			Target:      target,
			Description: "recon found every request to this host — a guaranteed-nonexistent path included — hitting a WAF/bot-protection/auth block wall rather than the application's own routing; the per-target template corpus was skipped (it would fetch the one block page thousands of times for zero findings). Re-run with --scan-uniform-anyway to force it, or scan from an in-region/residential egress.",
			Evidence:    map[string]string{"detected_by": "D6 uniform-response-wall check (pkg/uniformwall, via --recon-file)"},
		}
	default:
		return detectors.Finding{
			ID:          "misconfig-uniform-catchall",
			Type:        "misconfig",
			Severity:    "low",
			Confidence:  "low",
			Target:      target,
			Description: "recon found this host returns one generic catch-all page (a SPA shell or static storage-bucket fallback) for every path, including a guaranteed-nonexistent one — there is no real routing here to scan; the per-target template corpus was skipped. Re-run with --scan-uniform-anyway to force it.",
			Evidence:    map[string]string{"detected_by": "D6 uniform-response-wall check (pkg/uniformwall, via --recon-file)"},
		}
	}
}

// warnUniformWall is the stderr line Run prints when it short-circuits a
// walled target.
func warnUniformWall(target string, v uniformwall.Verdict) string {
	kind := "catch-all page"
	if v == uniformwall.VerdictWAFBlock {
		kind = "WAF/bot/auth block wall"
	}
	return fmt.Sprintf("%s: recon classified this host as a %s — skipping the per-target template corpus (D6); pass --scan-uniform-anyway to override", target, kind)
}
