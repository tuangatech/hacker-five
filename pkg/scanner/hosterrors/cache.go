// Package hosterrors tracks consecutive errors per host so the scanner can
// stop hitting a host that's crossed its error threshold, instead of
// continuing to hammer an unreachable or broken target for the rest of an
// ID-enumeration run.
package hosterrors

import "sync"

// DefaultThreshold is used when Config.HostErrorThreshold is 0 (unset).
const DefaultThreshold = 5

// Cache tracks each host's current consecutive-error count.
type Cache struct {
	mu        sync.Mutex
	threshold int
	counts    map[string]int
}

// New creates a Cache that flags a host once it reaches threshold
// consecutive errors.
func New(threshold int) *Cache {
	return &Cache{threshold: threshold, counts: make(map[string]int)}
}

// RecordError increments host's consecutive-error count.
func (c *Cache) RecordError(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[host]++
}

// RecordSuccess resets host's consecutive-error count to 0.
func (c *Cache) RecordSuccess(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts[host] = 0
}

// ShouldSkip reports whether host has reached the error threshold.
func (c *Cache) ShouldSkip(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[host] >= c.threshold
}
