package idor

import (
	"regexp"
	"testing"
)

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestRandomUUIDStrategy_IncludesSeedAndFillerCount proves Generate returns
// the real seed ID first, followed by exactly FillerCount freshly generated
// UUIDs — the shape runBaseline's Establish relies on to safely mix one real
// sample into an otherwise-synthetic denial baseline (LT-95,
// docs/follow-up.md).
func TestRandomUUIDStrategy_IncludesSeedAndFillerCount(t *testing.T) {
	strategy := RandomUUIDStrategy{Seed: "1b4e28ba-2fa1-11d2-883f-0016d3cca427", FillerCount: 20}
	got := strategy.Generate()

	if len(got) != 21 {
		t.Fatalf("got %d IDs, want 21 (1 seed + 20 filler)", len(got))
	}
	if got[0] != strategy.Seed {
		t.Fatalf("got first ID %q, want the seed %q", got[0], strategy.Seed)
	}
}

// TestRandomUUIDStrategy_FillersAreWellFormedAndDistinct guards the actual
// v4-UUID bit-twiddling: a malformed filler could either fail to match any
// real target's ID shape (silently useless) or, worse, collide with the
// seed and corrupt the baseline.
func TestRandomUUIDStrategy_FillersAreWellFormedAndDistinct(t *testing.T) {
	strategy := RandomUUIDStrategy{FillerCount: 50}
	got := strategy.Generate()

	if len(got) != 50 {
		t.Fatalf("got %d IDs, want 50", len(got))
	}
	seen := map[string]bool{}
	for _, id := range got {
		if !uuidV4Pattern.MatchString(id) {
			t.Fatalf("filler %q is not a well-formed v4 UUID", id)
		}
		if seen[id] {
			t.Fatalf("duplicate filler UUID %q", id)
		}
		seen[id] = true
	}
}

// TestRandomUUIDStrategy_NoSeed confirms an empty Seed contributes no extra
// entry — a filler-only baseline run, never a blank/zero-value ID.
func TestRandomUUIDStrategy_NoSeed(t *testing.T) {
	strategy := RandomUUIDStrategy{FillerCount: 5}
	got := strategy.Generate()

	if len(got) != 5 {
		t.Fatalf("got %d IDs, want 5 (no seed)", len(got))
	}
	for _, id := range got {
		if id == "" {
			t.Fatal("got an empty ID in the filler-only case")
		}
	}
}
