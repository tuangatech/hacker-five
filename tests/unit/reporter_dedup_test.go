package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

func TestDedup_CollapsesRepeatedIDsKeepingFirstOccurrence(t *testing.T) {
	findings := []detectors.Finding{
		{ID: "a", Target: "http://one.example.com"},
		{ID: "b", Target: "http://two.example.com"},
		{ID: "a", Target: "http://one-duplicate.example.com"},
	}

	got := reporter.Dedup(findings)

	assert.Len(t, got, 2)
	assert.Equal(t, "http://one.example.com", got[0].Target)
	assert.Equal(t, "b", got[1].ID)
}

func TestDedup_NilInputStaysNil(t *testing.T) {
	assert.Nil(t, reporter.Dedup(nil))
}

func TestDedup_NoDuplicatesReturnsSameLength(t *testing.T) {
	findings := []detectors.Finding{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	assert.Len(t, reporter.Dedup(findings), 3)
}
