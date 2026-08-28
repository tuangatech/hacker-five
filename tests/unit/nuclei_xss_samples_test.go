package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiXSSSamples_LoadRealUpstreamTemplates is a regression test against
// templates/nuclei-samples/xss/ (see that directory's README for what each
// template checks and its provenance). Only checks load behavior —
// deterministic, no live target needed; live-run results still need
// confirming against a real target, per that README.
func TestNucleiXSSSamples_LoadRealUpstreamTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/xss")

	require.Empty(t, errs)

	require.Len(t, templates, 2)
	var ids []string
	for _, tmpl := range templates {
		ids = append(ids, tmpl.ID)
	}
	assert.ElementsMatch(t, []string{"xss-uri-reflected", "top-xss-params"}, ids)
}
