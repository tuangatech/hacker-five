package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiJuiceShopSamples_LoadRealUpstreamTemplates is a regression test
// against templates/nuclei-samples/juice-shop/ (see that directory's README
// for what this template is and its live result against Juice Shop). Only
// checks load behavior — deterministic, no live target needed; the actual
// live-run result (Step 2's "Fourth live run") is documented, not re-asserted
// here, same convention as the dvwa-php/crapi sample tests.
func TestNucleiJuiceShopSamples_LoadRealUpstreamTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/juice-shop")

	require.Empty(t, errs)

	require.Len(t, templates, 1)
	assert.Equal(t, "owasp-juice-shop-detect", templates[0].ID)
}
