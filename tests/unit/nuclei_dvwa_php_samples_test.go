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
// three; only apache-mod-negotiation-listing.yaml (raw:/payloads:) is still
// expected to be rejected.
func TestNucleiDVWAPHPSamples_LoadRealUpstreamTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/dvwa-php")

	require.Len(t, errs, 1, "only apache-mod-negotiation-listing.yaml (raw:/payloads:) should be rejected")
	assert.Contains(t, errs[0].Error(), "raw:/payloads:")

	require.Len(t, templates, 4)
	var ids []string
	for _, tmpl := range templates {
		ids = append(ids, tmpl.ID)
	}
	assert.ElementsMatch(t, []string{"apache-detect", "php-detect", "dir-listing", "http-missing-security-headers"}, ids)
}
