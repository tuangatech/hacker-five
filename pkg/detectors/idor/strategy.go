package idor

import (
	"crypto/rand"
	"fmt"
	"strconv"
)

// Strategy generates the candidate ID values an IDOR detector enumerates.
type Strategy interface {
	Generate() []string
}

// SequentialIntStrategy enumerates every integer in [Start, End].
type SequentialIntStrategy struct {
	Start, End int
}

// Generate returns every integer from Start to End, inclusive, as a string.
func (s SequentialIntStrategy) Generate() []string {
	if s.End < s.Start {
		return nil
	}
	ids := make([]string, 0, s.End-s.Start+1)
	for i := s.Start; i <= s.End; i++ {
		ids = append(ids, strconv.Itoa(i))
	}
	return ids
}

// WordlistStrategy enumerates a fixed list of candidate IDs (e.g. non-numeric
// identifiers, or a curated wordlist).
type WordlistStrategy struct {
	Words []string
}

// Generate returns Words as-is.
func (s WordlistStrategy) Generate() []string {
	return s.Words
}

// RandomUUIDStrategy is SequentialIntStrategy's UUID-keyed counterpart
// (LT-95, docs/follow-up.md): a UUID-keyed BOLA (e.g. crAPI's
// vehicle/{vehicleId}/location) is unreachable by brute-forcing a numeric
// range, but a fresh, random UUID is vanishingly unlikely to collide with a
// real record — so FillerCount of them safely establish runBaseline's
// "denied" signature (Establish requires ≥3 samples, ≥80% agreement,
// unchanged) exactly as a normal int-range scan would, and the one real
// Seed ID (recon.SuggestIDORSeedIDs) is then evaluated against that
// baseline like any other sample. Zero changes to runBaseline itself —
// only the ID source differs.
type RandomUUIDStrategy struct {
	// Seed is a real, concrete ID recon actually observed (never invented) —
	// omitted (empty) runs the filler-only baseline with nothing real to
	// test against, which is never useful but also never wrong.
	Seed        string
	FillerCount int
}

// Generate returns [Seed] (if non-empty) followed by FillerCount freshly
// generated, well-formed v4 UUIDs.
func (s RandomUUIDStrategy) Generate() []string {
	ids := make([]string, 0, s.FillerCount+1)
	if s.Seed != "" {
		ids = append(ids, s.Seed)
	}
	for i := 0; i < s.FillerCount; i++ {
		ids = append(ids, randomUUIDv4())
	}
	return ids
}

// randomUUIDv4 generates a well-formed RFC 4122 v4 UUID from 16
// crypto/rand-sourced bytes — no new dependency for what's ~10 lines of
// bit-twiddling (version nibble set to 4, variant bits set to RFC 4122). The
// read error is deliberately ignored, same convention as
// pkg/oob.randomHexID/businesslogic.randomHex: a catastrophic
// system-entropy failure has no sane fallback here either, and Generate's
// []string return has nowhere to carry an error.
func randomUUIDv4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
