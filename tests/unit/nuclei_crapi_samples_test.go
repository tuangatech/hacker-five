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
// springboot-actuator.yaml (base64_py()) and redoc-api-docs.yaml
// (content_type identifier) are expected rejections: real DSL gaps this
// batch surfaced that the DVWA/PHP batch didn't (unsupported hash/encoding
// functions and a missing built-in identifier), distinct from the
// raw:/payloads: rejection style already covered by the DVWA batch.
func TestNucleiCRAPISamples_LoadRealUpstreamTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/crapi")

	require.Len(t, errs, 2, "springboot-actuator.yaml and redoc-api-docs.yaml should be rejected for unsupported DSL functions/identifiers")
	var errMsgs []string
	for _, e := range errs {
		errMsgs = append(errMsgs, e.Error())
	}
	assert.Contains(t, errMsgs[0]+errMsgs[1], `unsupported function "base64_py"`)
	assert.Contains(t, errMsgs[0]+errMsgs[1], `unknown identifier "content_type"`)

	require.Len(t, templates, 3)
	var ids []string
	for _, tmpl := range templates {
		ids = append(ids, tmpl.ID)
	}
	assert.ElementsMatch(t, []string{"mailhog-panel", "openapi", "springboot-env"}, ids)
}
