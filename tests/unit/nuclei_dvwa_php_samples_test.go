package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiDVWAPHPSamples_LoadRealUpstreamTemplates is a regression test
// against templates/nuclei-samples/dvwa-php/ (see that directory's README
// for what each one is and its live result against DVWA). This only checks
// load/reject behavior — deterministic, no live target needed; the actual
// live-run results are documented (not re-asserted here) in that README,
// since re-running them live on every `go test` would make this a live
// integration test in disguise.
//
// http-missing-security-headers.yaml used to be rejected here too (unary
// "!" wasn't supported in the DSL grammar) — that gap is now fixed
// (pkg/template/dsl's parseUnary), so it loads and runs like the other
// three. apache-mod-negotiation-listing.yaml (raw:/payloads:, single
// inline-list payload key, plain word/status matchers — no matcher-DSL
// templating gap) now loads too, see doc10's raw:/payloads: note.
// missing-cookie-samesite-strict.yaml was added later (Future Enhancement
// #3) — one of DVWA's real "4 findings, all genuine" from Step 2's full
// synced-corpus run, previously missing from this curated set.
//
// dvwa-xss-reflected.yaml/dvwa-sqli-error-based.yaml are first-party
// HackerFive-authored (not upstream, unlike the rest of this directory) —
// added 2026-08-28 targeting DVWA's actual known-vulnerable query params
// (?name=, ?id=), closing the gap the generic xss/sqli samples (see
// ../xss/, ../sqli/) can't reach on their own. Live-verified real result
// documented in this directory's README.
func TestNucleiDVWAPHPSamples_LoadTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/dvwa-php")

	require.Empty(t, errs)

	require.Len(t, templates, 8)
	var ids []string
	for _, tmpl := range templates {
		ids = append(ids, tmpl.ID)
	}
	assert.ElementsMatch(t, []string{"apache-detect", "php-detect", "dir-listing", "http-missing-security-headers", "apache-mod-negotiation-listing", "missing-cookie-samesite-strict", "dvwa-xss-reflected", "dvwa-sqli-error-based"}, ids)
}
