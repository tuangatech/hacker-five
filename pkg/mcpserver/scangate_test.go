package mcpserver

import (
	"sync"
	"testing"
	"time"
)

// TestScanConcurrencyGate_SplitsBudgetAcrossConcurrentCalls is D1's DoD:
// two `scan` calls in flight against the same host each get roughly half
// the aggregate per-host template fan-out, not the full default each.
func TestScanConcurrencyGate_SplitsBudgetAcrossConcurrentCalls(t *testing.T) {
	g := newScanConcurrencyGate()
	targets := []string{"https://accounts.shopify.com"}

	b1, rel1 := g.enter(targets)
	if b1 != aggregateTemplateConcurrencyPerHost {
		t.Fatalf("lone call: got budget %d, want %d", b1, aggregateTemplateConcurrencyPerHost)
	}

	b2, rel2 := g.enter(targets) // second concurrent call against the same host
	if b2 != aggregateTemplateConcurrencyPerHost/2 {
		t.Fatalf("second concurrent call: got budget %d, want %d", b2, aggregateTemplateConcurrencyPerHost/2)
	}

	b3, rel3 := g.enter(targets)
	if b3 != aggregateTemplateConcurrencyPerHost/3 {
		t.Fatalf("third concurrent call: got budget %d, want %d", b3, aggregateTemplateConcurrencyPerHost/3)
	}

	rel1()
	rel2()
	rel3()

	// After everything releases, a fresh call is back to the full budget.
	b4, rel4 := g.enter(targets)
	defer rel4()
	if b4 != aggregateTemplateConcurrencyPerHost {
		t.Fatalf("post-release call: got budget %d, want %d", b4, aggregateTemplateConcurrencyPerHost)
	}
}

// TestScanConcurrencyGate_DifferentHostsDoNotContend confirms the ceiling
// is per-host: two calls against distinct hosts each keep the full budget.
func TestScanConcurrencyGate_DifferentHostsDoNotContend(t *testing.T) {
	g := newScanConcurrencyGate()

	b1, rel1 := g.enter([]string{"https://accounts.shopify.com"})
	defer rel1()
	b2, rel2 := g.enter([]string{"https://shop.app"})
	defer rel2()

	if b1 != aggregateTemplateConcurrencyPerHost || b2 != aggregateTemplateConcurrencyPerHost {
		t.Fatalf("distinct hosts must not contend: got %d and %d", b1, b2)
	}
}

// TestScanConcurrencyGate_HardBackpressure confirms a call beyond
// maxConcurrentScansPerHost against one host blocks in enter until a
// slot frees.
func TestScanConcurrencyGate_HardBackpressure(t *testing.T) {
	g := newScanConcurrencyGate()
	targets := []string{"https://accounts.shopify.com"}

	var releases []func()
	for i := 0; i < maxConcurrentScansPerHost; i++ {
		_, rel := g.enter(targets)
		releases = append(releases, rel)
	}

	entered := make(chan struct{})
	go func() {
		_, rel := g.enter(targets) // must block: host is at the call ceiling
		close(entered)
		rel()
	}()

	select {
	case <-entered:
		t.Fatal("enter returned while the host was already at maxConcurrentScansPerHost")
	case <-time.After(100 * time.Millisecond):
	}

	releases[0]() // free one slot
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("enter did not unblock after a slot was released")
	}
	for _, rel := range releases[1:] {
		rel()
	}
}

// TestScanConcurrencyGate_ReleaseIsIdempotent guards the once-guarded
// release func.
func TestScanConcurrencyGate_ReleaseIsIdempotent(t *testing.T) {
	g := newScanConcurrencyGate()
	targets := []string{"https://accounts.shopify.com"}

	_, rel := g.enter(targets)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rel() }()
	}
	wg.Wait()

	b, rel2 := g.enter(targets)
	defer rel2()
	if b != aggregateTemplateConcurrencyPerHost {
		t.Fatalf("double release corrupted the counter: got budget %d", b)
	}
}
