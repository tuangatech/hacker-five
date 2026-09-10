package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

// TestDropSupersededNucleiFindings_WeakHSTS is the LT-6 tail: the native +
// nuclei weak-HSTS pair isn't an aggregate (SplitAggregates doesn't touch
// it), so it needs its own template-ID skip-list entry — the nuclei
// duplicate is dropped only when the same target also carries the native
// finding.
func TestDropSupersededNucleiFindings_WeakHSTS(t *testing.T) {
	findings := []detectors.Finding{
		{ID: "misconfig-weak-hsts-max-age", Type: "misconfig", Severity: "low", Target: "https://example.com"},
		{ID: "nuclei-weak-hsts-detect-0", Type: "misconfig", Severity: "info", Target: "https://example.com"},
		// a different target with only the nuclei finding (no native
		// counterpart there) must keep it.
		{ID: "nuclei-weak-hsts-detect-0", Type: "misconfig", Severity: "info", Target: "https://other.example.com"},
	}

	got := reporter.DropSupersededNucleiFindings(findings)

	require.Len(t, got, 2)
	assert.Equal(t, "misconfig-weak-hsts-max-age", got[0].ID)
	assert.Equal(t, "nuclei-weak-hsts-detect-0", got[1].ID)
	assert.Equal(t, "https://other.example.com", got[1].Target)
}

func TestDropSupersededNucleiFindings_UnrelatedFindingsUntouched(t *testing.T) {
	in := []detectors.Finding{
		{ID: "misconfig-missing-header-X-Frame-Options", Target: "https://example.com"},
		{ID: "nuclei-something-else-0", Target: "https://example.com"},
	}
	got := reporter.DropSupersededNucleiFindings(in)
	assert.Equal(t, in, got)
}
