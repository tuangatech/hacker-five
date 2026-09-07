package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

// TestValidateCitations covers C3's evidence-linked-claim gate (doc16 Phase
// 7 Step 3): a cited Finding.ID must exist in the finding set.
func TestValidateCitations(t *testing.T) {
	findings := []detectors.Finding{
		{ID: "misconfig-missing-header-X-Frame-Options"},
		{ID: "idor-report-id"},
	}

	assert.NoError(t, reporter.ValidateCitations(nil, findings), "no citation claims nothing")
	assert.NoError(t, reporter.ValidateCitations([]string{}, findings))
	assert.NoError(t, reporter.ValidateCitations(
		[]string{"idor-report-id", "misconfig-missing-header-X-Frame-Options"}, findings),
		"every cited ID is present")

	err := reporter.ValidateCitations([]string{"idor-report-id", "made-up-finding"}, findings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "made-up-finding")
	assert.NotContains(t, err.Error(), "idor-report-id", "a present citation is not part of the complaint")

	// Absent findings set: any citation is unsatisfiable.
	err = reporter.ValidateCitations([]string{"anything"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "anything")
}
