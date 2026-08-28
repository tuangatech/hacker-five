package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// TestNucleiSQLiSamples_LoadRealUpstreamTemplates is a regression test
// against templates/nuclei-samples/sqli/ (see that directory's README for
// what the template checks, its real matcher/extractor split, and its
// provenance). Only checks load behavior — deterministic, no live target
// needed; live-run results still need confirming against a real target, per
// that README.
func TestNucleiSQLiSamples_LoadRealUpstreamTemplates(t *testing.T) {
	templates, errs := nuclei.LoadDir("../../templates/nuclei-samples/sqli")

	require.Empty(t, errs)

	require.Len(t, templates, 1)
	assert.Equal(t, "error-based-sql-injection", templates[0].ID)
}
