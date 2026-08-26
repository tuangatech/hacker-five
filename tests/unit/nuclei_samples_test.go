package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiSamples_LoadRealUpstreamTemplates is a regression test against
// real, unmodified upstream templates under templates/nuclei-samples/ (see
// that directory's README, and dvwa-php/'s own README, for what each file
// is and why it's included), not synthetic fixtures. LoadDir recurses, so
// this picks up both the original four samples and the dvwa-php/ batch —
// dvwa-php's own load/reject counts are asserted precisely by
// TestNucleiDVWAPHPSamples_LoadRealUpstreamTemplates; this test only checks
// that the original four are still present and still well-formed among
// whatever else the tree recurses into.
func TestNucleiSamples_LoadRealUpstreamTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples")

	require.Empty(t, errs)

	var ids []string
	byID := map[string]nuclei.Template{}
	for _, tmpl := range templates {
		ids = append(ids, tmpl.ID)
		byID[tmpl.ID] = *tmpl
	}
	// cors-misconfig.yaml (raw:/payloads:) now loads (see doc10's raw:/
	// payloads: note) — but real upstream Nuclei helper functions this
	// template's payload values use (rand_base, RDN, FQDN) aren't
	// implemented, and its matcher DSL string references {{cors_origin}}
	// directly (payload-variable substitution inside a matcher, not just
	// the raw request) which this project doesn't render either. It loads
	// and runs without erroring, but won't produce a real CORS-reflection
	// finding yet — a known, documented v1 gap, not silently claimed fixed.
	assert.Subset(t, ids, []string{"angular-detect", "adminer-panel", "django-debug-config-enabled", "cors-misconfig"})

	adminer, ok := byID["adminer-panel"]
	require.True(t, ok)
	assert.Len(t, adminer.HTTP[0].Path, 9, "every candidate path must parse, not just the first")
	assert.True(t, adminer.HTTP[0].StopAtFirstMatch)
}
