package webui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStepChain_Empty_RendersNothing(t *testing.T) {
	assert.Equal(t, "", string(stepChain(nil)))
}

func TestStepChain_PendingRunningDone_EachGetsItsOwnClass(t *testing.T) {
	html := string(stepChain([]WaveStatus{
		{Name: "wave0", Status: "done"},
		{Name: "wave1", Status: "running"},
		{Name: "wave2", Status: "pending"},
	}))

	assert.Contains(t, html, `class="step-done">Wave 0<`)
	assert.Contains(t, html, `class="step-running">Wave 1<`)
	assert.Contains(t, html, `class="step-pending">Wave 2<`)
	assert.Equal(t, 2, strings.Count(html, "step-arrow"), "3 steps need exactly 2 arrows between them, none trailing")
}

func TestStepChain_DetectorNames_UsePrettyDisplayNames(t *testing.T) {
	html := string(stepChain([]WaveStatus{
		{Name: "misconfig", Status: "done"},
		{Name: "authbypass", Status: "running"},
		{Name: "idor", Status: "pending"},
	}))

	assert.Contains(t, html, "Misconfig")
	assert.Contains(t, html, "Auth Bypass")
	assert.Contains(t, html, "IDOR")
}

func TestStepChain_UnknownName_FallsBackToRawString(t *testing.T) {
	html := string(stepChain([]WaveStatus{{Name: "some-future-step", Status: "done"}}))
	assert.Contains(t, html, "some-future-step")
}

func TestJob_SetDetectorStatus_SeedsThenTransitions(t *testing.T) {
	job := newTestJob("job1")

	job.SetDetectorStatus("misconfig", "pending")
	job.SetDetectorStatus("idor", "pending")
	snap := job.Snapshot()
	want := []WaveStatus{{Name: "misconfig", Status: "pending"}, {Name: "idor", Status: "pending"}}
	assert.Equal(t, want, snap.DetectorSteps, "seeding both as pending must not reorder or duplicate")

	job.SetDetectorStatus("misconfig", "running")
	snap = job.Snapshot()
	assert.Equal(t, "running", snap.DetectorSteps[0].Status, "updating an existing name must update in place, not append a duplicate")
	assert.Len(t, snap.DetectorSteps, 2)

	job.SetDetectorStatus("misconfig", "done")
	snap = job.Snapshot()
	assert.Equal(t, "done", snap.DetectorSteps[0].Status)
	assert.Equal(t, "pending", snap.DetectorSteps[1].Status, "idor is untouched until its own transition")
}
