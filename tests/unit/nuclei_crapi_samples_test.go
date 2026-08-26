package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiCRAPISamples_LoadRealUpstreamTemplates is a regression test
// against templates/nuclei-samples/crapi/ (see that directory's README for
// what each one is and its live result against crAPI). This only checks
// load/reject behavior — deterministic, no live target needed; the actual
// live-run results are documented (not re-asserted here) in that README.
//
// springboot-actuator.yaml (base64_py()/mmh3()) and redoc-api-docs.yaml
// (content_type identifier) used to be rejected here — the exact two real
// DSL gaps this batch surfaced that the DVWA/PHP batch didn't. Both are now
// fixed (see docs/10-implementation-plan-ph1b.md's "Post-v0.1.0 DSL/part
// expansion" note), so all five templates in this directory load cleanly.
func TestNucleiCRAPISamples_LoadRealUpstreamTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/crapi")

	require.Empty(t, errs)
	require.Len(t, templates, 5)
	var ids []string
	for _, tmpl := range templates {
		ids = append(ids, tmpl.ID)
	}
	assert.ElementsMatch(t, []string{"mailhog-panel", "openapi", "springboot-env", "springboot-actuator", "redoc-api-docs"}, ids)
}
