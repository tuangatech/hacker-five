package mcpserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func TestStorePendingPlan_TakePendingPlan_RoundTrip(t *testing.T) {
	p := &pendingPlan{tree: &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root"}}}
	id := storePendingPlan(p)
	require.NotEmpty(t, id)

	got, ok := takePendingPlan(id)
	require.True(t, ok)
	assert.Same(t, p, got)
}

func TestTakePendingPlan_IsOneShot(t *testing.T) {
	id := storePendingPlan(&pendingPlan{tree: &agenttask.PlanTree{}})

	_, ok := takePendingPlan(id)
	require.True(t, ok)

	_, ok = takePendingPlan(id)
	assert.False(t, ok, "a RequestState must not be redeemable twice")
}

func TestTakePendingPlan_UnknownID_ReturnsFalse(t *testing.T) {
	_, ok := takePendingPlan("does-not-exist")
	assert.False(t, ok)
}

func TestStorePendingPlan_SweepsExpiredEntries(t *testing.T) {
	pendingPlansMu.Lock()
	pendingPlans["stale"] = &pendingPlan{tree: &agenttask.PlanTree{}, createdAt: time.Now().Add(-2 * pendingPlanTTL)}
	pendingPlansMu.Unlock()

	// Any subsequent store sweeps expired entries as a side effect.
	storePendingPlan(&pendingPlan{tree: &agenttask.PlanTree{}})

	pendingPlansMu.Lock()
	_, stillThere := pendingPlans["stale"]
	pendingPlansMu.Unlock()
	assert.False(t, stillThere, "an entry older than pendingPlanTTL must be swept on the next store")
}

func TestMintStateID_ProducesDistinctNonEmptyIDs(t *testing.T) {
	a := mintStateID()
	b := mintStateID()
	assert.NotEmpty(t, a)
	assert.Len(t, a, 32, "16 random bytes hex-encoded")
	assert.NotEqual(t, a, b)
}

func TestStorePendingTriage_TakePendingTriage_RoundTrip(t *testing.T) {
	p := &pendingTriage{ranked: nil}
	id := storePendingTriage(p)
	require.NotEmpty(t, id)

	got, ok := takePendingTriage(id)
	require.True(t, ok)
	assert.Same(t, p, got)

	_, ok = takePendingTriage(id)
	assert.False(t, ok, "a triage RequestState must also be one-shot")
}

func TestStorePendingTriage_SweepsExpiredEntries(t *testing.T) {
	pendingTriagesMu.Lock()
	pendingTriages["stale"] = &pendingTriage{createdAt: time.Now().Add(-2 * pendingPlanTTL)}
	pendingTriagesMu.Unlock()

	storePendingTriage(&pendingTriage{})

	pendingTriagesMu.Lock()
	_, stillThere := pendingTriages["stale"]
	pendingTriagesMu.Unlock()
	assert.False(t, stillThere)
}
