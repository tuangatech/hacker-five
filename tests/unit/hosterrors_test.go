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
