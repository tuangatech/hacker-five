package webui

import (
	"fmt"
	"html/template"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

func noopFindingRender(f detectors.Finding) template.HTML { return template.HTML(f.ID) }
func noopLogRender(e LogEntry) template.HTML              { return template.HTML(e.Msg) }
func noopProgressRender(status string, _ error, _ []WaveStatus, _ string) template.HTML {
	return template.HTML(status)
}
func noopReconRender(result *recon.ReconResult) template.HTML {
	if result == nil {
		return ""
	}
	return template.HTML(result.Target)
}

func newTestJob(id string) *Job {
	return newJob(id, "http://example.com", noopFindingRender, noopLogRender, noopProgressRender, noopReconRender)
}

// TestJob_SubscribeThenUnsubscribe_RemovesChannel is the fix for the "Job.subs
// has no unsubscribe path" gap doc12's review surfaced — without this, subs
// would only ever grow across htmx's SSE auto-reconnects.
func TestJob_SubscribeThenUnsubscribe_RemovesChannel(t *testing.T) {
	j := newTestJob("t1")
	_, unsubscribe := j.Subscribe()

	j.mu.Lock()
	assert.Len(t, j.subs, 1)
	j.mu.Unlock()

	unsubscribe()

	j.mu.Lock()
	assert.Empty(t, j.subs, "unsubscribe must remove the channel from subs")
	j.mu.Unlock()
}

func TestJob_Unsubscribe_ClosesChannel(t *testing.T) {
	j := newTestJob("t2")
	ch, unsubscribe := j.Subscribe()
	unsubscribe()

	_, ok := <-ch
	assert.False(t, ok, "channel must be closed after unsubscribe")
}

// TestJob_Unsubscribe_Idempotent confirms a caller can safely defer
// unsubscribe() even if something else already called it (e.g. the SSE
// handler's own early-return paths) — a double close() would otherwise panic.
func TestJob_Unsubscribe_Idempotent(t *testing.T) {
	j := newTestJob("t3")
	_, unsubscribe := j.Subscribe()
	unsubscribe()
	assert.NotPanics(t, func() { unsubscribe() })
}

func TestJob_AppendFinding_AppendsBeforePublishing(t *testing.T) {
	j := newTestJob("t4")
	ch, unsubscribe := j.Subscribe()
	defer unsubscribe()

	j.AppendFinding(detectors.Finding{ID: "test-finding"})

	snap := j.Snapshot()
	require.Len(t, snap.Findings, 1)
	assert.Equal(t, "test-finding", snap.Findings[0].ID)

	select {
	case ev := <-ch:
		assert.Equal(t, EventFinding, ev.Type)
	case <-time.After(time.Second):
		t.Fatal("expected a finding event on the subscriber channel")
	}
}

// TestJob_Publish_NeverBlocksOnFullSubscriber is the direct test of doc12's
// non-blocking-send design: a subscriber that never drains its channel must
// never stall the scan (AppendLog/AppendFinding) that's publishing to it.
func TestJob_Publish_NeverBlocksOnFullSubscriber(t *testing.T) {
	j := newTestJob("t5")
	_, unsubscribe := j.Subscribe() // never read from — simulates a stalled/slow subscriber
	defer unsubscribe()

	done := make(chan struct{})
	go func() {
		for i := 0; i < subscriberBuffer+5; i++ {
			j.AppendLog("info", "msg")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("AppendLog blocked on a full subscriber channel — publish must be non-blocking")
	}
}

// TestJobStore_EvictsOldestPastCap is doc12's corrected eviction policy: cap
// the store at maxJobs (50), evicting the oldest on insert past the cap.
func TestJobStore_EvictsOldestPastCap(t *testing.T) {
	store := newJobStore()
	for i := 0; i < maxJobs+5; i++ {
		store.Add(newTestJob(fmt.Sprintf("job-%d", i)))
	}

	_, ok := store.Get("job-0")
	assert.False(t, ok, "the oldest job must be evicted once the store exceeds maxJobs")

	_, ok = store.Get(fmt.Sprintf("job-%d", maxJobs+4))
	assert.True(t, ok, "the newest job must still be present")

	assert.Len(t, store.jobs, maxJobs)
}

func TestJobStore_GetUnknownID(t *testing.T) {
	store := newJobStore()
	_, ok := store.Get("nope")
	assert.False(t, ok)
}

// TestJobStore_List_MostRecentFirst is Dashboard/Scan History's ordering
// contract — the newest scan must appear first, not last.
func TestJobStore_List_MostRecentFirst(t *testing.T) {
	store := newJobStore()
	store.Add(newTestJob("first"))
	store.Add(newTestJob("second"))
	store.Add(newTestJob("third"))

	got := store.List()
	require.Len(t, got, 3)
	assert.Equal(t, []string{"third", "second", "first"}, []string{got[0].ID, got[1].ID, got[2].ID})
}

// TestJobStore_List_ReflectsLiveState confirms List() reads each job's
// current status/finding count, not a stale value captured at Add time.
func TestJobStore_List_ReflectsLiveState(t *testing.T) {
	store := newJobStore()
	j := newTestJob("job-1")
	store.Add(j)

	j.SetRunning()
	j.AppendFinding(detectors.Finding{ID: "f1"})
	j.AppendFinding(detectors.Finding{ID: "f2"})

	got := store.List()
	require.Len(t, got, 1)
	assert.Equal(t, StatusRunning, got[0].Status)
	assert.Equal(t, 2, got[0].FindingCount)
}

func TestJobStore_List_Empty(t *testing.T) {
	store := newJobStore()
	assert.Empty(t, store.List())
}
