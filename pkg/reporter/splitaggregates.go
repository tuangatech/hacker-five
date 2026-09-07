package reporter

import (
	"strings"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

// canonicalSecurityHeaderName maps a lowercase security-header token — the
// spelling the nuclei "http-missing-security-headers" template uses in its
// matched-name list — to the canonical header name pkg/detectors/misconfig
// builds its own "misconfig-missing-header-<Name>" finding ID from. Only the
// headers the native check also grades need an entry: for those, splitting
// the aggregate into per-header findings lets Dedup's existing exact-ID key
// collapse the native/nuclei overlap on its own (LT-6 / doc16 C6), no fuzzy
// key. Every other header keeps an aggregate-derived ID and stays a distinct
// finding (it has no native counterpart to collapse against).
var canonicalSecurityHeaderName = map[string]string{
	"content-security-policy":   "Content-Security-Policy",
	"x-frame-options":           "X-Frame-Options",
	"strict-transport-security": "Strict-Transport-Security",
	"x-content-type-options":    "X-Content-Type-Options",
}

// SplitAggregates expands a nuclei "http-missing-security-headers" aggregate
// finding — one row whose Evidence["matched_checks"] lists many missing
// headers — into one finding per header, and passes every other finding
// through untouched with order preserved. Run it BEFORE Dedup (LT-6, doc16
// C6): a header the native misconfig check also grades gets that check's
// exact "misconfig-missing-header-<Name>" ID, so the subsequent Dedup
// collapses the pair (the native finding, emitted first by the engine, wins
// — it carries the real severity and request/response evidence); every other
// header gets a stable "nuclei-http-missing-security-headers-<token>" ID and
// keeps the aggregate's severity. Idempotent: a run whose aggregate was
// already split is a no-op.
func SplitAggregates(findings []detectors.Finding) []detectors.Finding {
	out := make([]detectors.Finding, 0, len(findings))
	for _, f := range findings {
		checks := aggregateMissingHeaderTokens(f)
		if len(checks) < 2 {
			out = append(out, f) // not the aggregate (or already a single header) — leave it
			continue
		}
		for _, tok := range checks {
			sub := f
			sub.Evidence = cloneEvidence(f.Evidence)
			delete(sub.Evidence, "matched_checks")
			if canon, ok := canonicalSecurityHeaderName[tok]; ok {
				sub.ID = "misconfig-missing-header-" + canon
				sub.Type = "misconfig"
				sub.Description = "response is missing the " + canon + " security header"
				sub.Evidence["header"] = canon
			} else {
				sub.ID = "nuclei-http-missing-security-headers-" + tok
				sub.Description = "response is missing the " + tok + " security header"
				sub.Evidence["header"] = tok
			}
			out = append(out, sub)
		}
	}
	return out
}

// aggregateMissingHeaderTokens returns the comma-separated header tokens of a
// nuclei http-missing-security-headers aggregate finding, or nil if f isn't
// one. Keyed on the template ID substring plus a populated matched_checks,
// so a native or unrelated finding never matches.
func aggregateMissingHeaderTokens(f detectors.Finding) []string {
	if !strings.Contains(f.ID, "http-missing-security-headers") {
		return nil
	}
	raw := f.Evidence["matched_checks"]
	if raw == "" {
		return nil
	}
	var toks []string
	for _, t := range strings.Split(raw, ",") {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			toks = append(toks, t)
		}
	}
	return toks
}

func cloneEvidence(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}
