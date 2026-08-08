package idor

import "strconv"

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
