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
	warned    map[string]bool // hosts whose skip has already been logged once
}

// New creates a Cache that flags a host once it reaches threshold
// consecutive errors.
func New(threshold int) *Cache {
	return &Cache{threshold: threshold, counts: make(map[string]int), warned: make(map[string]bool)}
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

// ShouldSkipWarnOnce is ShouldSkip plus a one-shot latch: when it reports
// skip=true, firstTime is true only the first time that happens for host.
// A target list commonly carries several targets on the same host (e.g.
// multiple endpoints on one domain); without this latch every remaining
// target on a tripped host would otherwise produce its own identical "skip"
// log line for the rest of the run.
func (c *Cache) ShouldSkipWarnOnce(host string) (skip, firstTime bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counts[host] < c.threshold {
		return false, false
	}
	firstTime = !c.warned[host]
	c.warned[host] = true
	return true, firstTime
}
