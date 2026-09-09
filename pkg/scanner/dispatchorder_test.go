package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

func dispatchTmpl(id, severity, tags string) *nuclei.Template {
	t := &nuclei.Template{ID: id}
	t.Info.Severity = severity
	t.Info.Tags = tags
	return t
}

func idsOf(ts []*nuclei.Template) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.ID
	}
	return out
}

// TestSortNucleiByDispatchPriority_BandThenCVE: severity band dominates, and
// within a band a CVE-specific template trails the generic checks. The input
// is in the loader's lexical order (CVE-* first), which is exactly the order
// LT-98/LT-114 is correcting.
func TestSortNucleiByDispatchPriority_BandThenCVE(t *testing.T) {
	ts := []*nuclei.Template{
		dispatchTmpl("CVE-2021-0001", "critical", "cve"),
		dispatchTmpl("CVE-2023-9999", "high", "cve,wordpress"),
		dispatchTmpl("apache-tech-detect", "info", "tech"),
		dispatchTmpl("dir-listing", "medium", "misconfig,exposure"),
		dispatchTmpl("exposed-env", "high", "exposure,config"),
		dispatchTmpl("weak-cors", "low", "misconfig"),
	}

	sortNucleiByDispatchPriority(ts)

	assert.Equal(t, []string{
		"CVE-2021-0001",      // critical band wins outright
		"exposed-env",        // high, generic
		"CVE-2023-9999",      // high, CVE — trails the generic high
		"dir-listing",        // medium
		"weak-cors",          // low
		"apache-tech-detect", // info
	}, idsOf(ts))
}

// TestSortNucleiByDispatchPriority_StableWithinBand: templates that share a
// dispatch priority keep their input (load) order — so a corpus carrying no
// severity/tag signal is left exactly as the loader produced it, and the
// existing "never dispatch t11" ctx-cancel test stays deterministic.
func TestSortNucleiByDispatchPriority_StableWithinBand(t *testing.T) {
	ts := []*nuclei.Template{
		dispatchTmpl("t00", "", ""),
		dispatchTmpl("t01", "", ""),
		dispatchTmpl("t02", "", ""),
		dispatchTmpl("t03", "", ""),
	}
	sortNucleiByDispatchPriority(ts)
	assert.Equal(t, []string{"t00", "t01", "t02", "t03"}, idsOf(ts))
}

func TestSeverityBand(t *testing.T) {
	assert.Equal(t, 0, severityBand("critical"))
	assert.Equal(t, 1, severityBand("HIGH"))
	assert.Equal(t, 2, severityBand(" medium "))
	assert.Equal(t, 3, severityBand("low"))
	assert.Equal(t, 4, severityBand("info"))
	assert.Equal(t, 4, severityBand(""))
	assert.Equal(t, 5, severityBand("bogus"))
}

func TestIsCVEish(t *testing.T) {
	assert.True(t, isCVEish(dispatchTmpl("CVE-2024-1234", "high", "")))
	assert.True(t, isCVEish(dispatchTmpl("some-check", "high", "wordpress,cve,rce")))
	assert.False(t, isCVEish(dispatchTmpl("cve-like-name-but-not", "high", "misconfig")))
	assert.False(t, isCVEish(dispatchTmpl("dir-listing", "medium", "exposure")))
}
