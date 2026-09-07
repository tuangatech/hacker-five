package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

// TestSplitAggregates_ThenDedup_CollapsesNativeNucleiOverlap is LT-6 / doc16
// C6's core: the nuclei http-missing-security-headers aggregate is split into
// per-header findings; for the headers the native misconfig check also
// grades, Dedup then collapses the pair keeping the native finding (real
// severity + evidence), while the headers with no native counterpart survive
// as their own findings.
func TestSplitAggregates_ThenDedup_CollapsesNativeNucleiOverlap(t *testing.T) {
	findings := []detectors.Finding{
		{ID: "misconfig-missing-header-Content-Security-Policy", Type: "misconfig", Severity: "medium", Evidence: map[string]string{"header": "Content-Security-Policy", "response": "HTTP 200"}},
		{ID: "misconfig-missing-header-X-Frame-Options", Type: "misconfig", Severity: "medium", Evidence: map[string]string{"header": "X-Frame-Options"}},
		{ID: "nuclei-http-missing-security-headers-0", Type: "misconfig", Severity: "info", Evidence: map[string]string{
			"matched_checks": "content-security-policy,x-frame-options,permissions-policy,referrer-policy",
		}},
	}

	got := reporter.Dedup(reporter.SplitAggregates(findings))

	byID := map[string]detectors.Finding{}
	for _, f := range got {
		byID[f.ID] = f
	}
	// the two native headers survive once, at native severity
	csp, ok := byID["misconfig-missing-header-Content-Security-Policy"]
	require.True(t, ok)
	assert.Equal(t, "medium", csp.Severity, "the native finding (emitted first) must win the collapse, not the info-severity nuclei split")
	assert.Equal(t, "HTTP 200", csp.Evidence["response"], "native evidence preserved")
	assert.Contains(t, byID, "misconfig-missing-header-X-Frame-Options")

	// the two headers with no native check become their own findings
	assert.Contains(t, byID, "nuclei-http-missing-security-headers-permissions-policy")
	assert.Contains(t, byID, "nuclei-http-missing-security-headers-referrer-policy")

	// the raw aggregate row is gone
	assert.NotContains(t, byID, "nuclei-http-missing-security-headers-0")
	for _, f := range got {
		assert.NotContains(t, f.Evidence, "matched_checks", "no split finding should still carry the aggregate list")
	}
	assert.Len(t, got, 4) // CSP, XFO, permissions-policy, referrer-policy
}

func TestSplitAggregates_NonAggregateFindingsUntouched(t *testing.T) {
	in := []detectors.Finding{
		{ID: "misconfig-weak-hsts-max-age", Severity: "low"},
		{ID: "nuclei-something-else-0", Evidence: map[string]string{"matched_checks": "a,b"}}, // matched_checks but not the missing-headers template
	}
	got := reporter.SplitAggregates(in)
	assert.Equal(t, in, got)
}

func TestSplitAggregates_SingleHeaderAggregateNotSplit(t *testing.T) {
	in := []detectors.Finding{
		{ID: "nuclei-http-missing-security-headers-0", Evidence: map[string]string{"matched_checks": "content-security-policy"}},
	}
	got := reporter.SplitAggregates(in)
	require.Len(t, got, 1)
	assert.Equal(t, "nuclei-http-missing-security-headers-0", got[0].ID, "a lone header isn't the N:1 case — leave it")
}

func TestSplitAggregates_Idempotent(t *testing.T) {
	in := []detectors.Finding{
		{ID: "nuclei-http-missing-security-headers-0", Type: "misconfig", Severity: "info", Evidence: map[string]string{
			"matched_checks": "content-security-policy,permissions-policy",
		}},
	}
	once := reporter.SplitAggregates(in)
	twice := reporter.SplitAggregates(once)
	assert.Equal(t, once, twice)
}
