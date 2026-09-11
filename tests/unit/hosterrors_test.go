package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tuangatech/hacker-five/pkg/scanner/hosterrors"
)

func TestCache_ShouldSkipAfterThreshold(t *testing.T) {
	cache := hosterrors.New(3)

	assert.False(t, cache.ShouldSkip("host-a"))
	cache.RecordError("host-a")
	cache.RecordError("host-a")
	assert.False(t, cache.ShouldSkip("host-a"))
	cache.RecordError("host-a")
	assert.True(t, cache.ShouldSkip("host-a"))
}

func TestCache_SuccessResetsCount(t *testing.T) {
	cache := hosterrors.New(3)

	cache.RecordError("host-a")
	cache.RecordError("host-a")
	cache.RecordSuccess("host-a")
	cache.RecordError("host-a")
	cache.RecordError("host-a")
	assert.False(t, cache.ShouldSkip("host-a"), "a success should have reset the consecutive-error count")
}

func TestCache_HostsAreIndependent(t *testing.T) {
	cache := hosterrors.New(2)

	cache.RecordError("host-a")
	cache.RecordError("host-a")
	assert.True(t, cache.ShouldSkip("host-a"))
	assert.False(t, cache.ShouldSkip("host-b"))
}

func TestDefaultThreshold(t *testing.T) {
	assert.Equal(t, 5, hosterrors.DefaultThreshold)
}

func TestCache_ShouldSkipWarnOnce_FirstTimeOnlyOnceThenSkipWithoutWarn(t *testing.T) {
	cache := hosterrors.New(2)

	skip, first := cache.ShouldSkipWarnOnce("host-a")
	assert.False(t, skip, "below threshold: no skip yet")
	assert.False(t, first)

	cache.RecordError("host-a")
	cache.RecordError("host-a")

	skip, first = cache.ShouldSkipWarnOnce("host-a")
	assert.True(t, skip, "at threshold: caller should skip this host")
	assert.True(t, first, "first caller to observe the trip should get firstTime=true")

	// Every subsequent call still reports skip=true, but firstTime=false —
	// this is what lets the engine log the "skipping host" warning exactly
	// once even though several remaining targets share the host.
	for i := 0; i < 3; i++ {
		skip, first = cache.ShouldSkipWarnOnce("host-a")
		assert.True(t, skip)
		assert.False(t, first, "only the first observer should get firstTime=true")
	}
}

func TestCache_ShouldSkipWarnOnce_HostsAreIndependent(t *testing.T) {
	cache := hosterrors.New(1)
	cache.RecordError("host-a")

	skipA, firstA := cache.ShouldSkipWarnOnce("host-a")
	assert.True(t, skipA)
	assert.True(t, firstA)

	skipB, firstB := cache.ShouldSkipWarnOnce("host-b")
	assert.False(t, skipB, "a different host must not inherit host-a's tripped state")
	assert.False(t, firstB)
}
