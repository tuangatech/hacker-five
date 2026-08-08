package idor

import "fmt"

// MinBaselineSamples is the fewest otherToken samples required before a
// majority "denied" signature can be trusted.
const MinBaselineSamples = 3

// BaselineMajorityThreshold is the fraction of samples that must agree for a
// cluster to be called "the" denied signature.
const BaselineMajorityThreshold = 0.8

// Baseline is the majority-vote "denied" signature sampled from otherToken
// across many candidate IDs — what most of the ID space should look like
// from an account with no access.
type Baseline struct {
	denied Signature
}

// Establish computes the baseline from samples. It returns an error if there
// aren't enough samples to trust a majority, or if no cluster reaches
// BaselineMajorityThreshold — e.g. because the endpoint doesn't consistently
// reject otherToken at all, which is itself worth surfacing rather than
// silently swallowing.
func Establish(samples []Signature) (Baseline, error) {
	if len(samples) < MinBaselineSamples {
		return Baseline{}, fmt.Errorf("establishing baseline: need at least %d samples, got %d", MinBaselineSamples, len(samples))
	}

	best, bestCount := largestCluster(samples)
	if float64(bestCount)/float64(len(samples)) < BaselineMajorityThreshold {
		return Baseline{}, fmt.Errorf("establishing baseline: no consistent denial pattern (largest cluster %d/%d samples, need %.0f%%)", bestCount, len(samples), BaselineMajorityThreshold*100)
	}

	return Baseline{denied: best}, nil
}

// largestCluster groups samples by Same() and returns a representative of
// the largest group along with its size.
func largestCluster(samples []Signature) (Signature, int) {
	var (
		representatives []Signature
		counts          []int
	)
	for _, s := range samples {
		matched := false
		for i, rep := range representatives {
			if rep.Same(s) {
				counts[i]++
				matched = true
				break
			}
		}
		if !matched {
			representatives = append(representatives, s)
			counts = append(counts, 1)
		}
	}

	bestIdx := 0
	for i, c := range counts {
		if c > counts[bestIdx] {
			bestIdx = i
		}
	}
	return representatives[bestIdx], counts[bestIdx]
}

// Bypassed reports whether sig deviates from the established denial baseline
// — i.e. access that should've been refused wasn't.
func (b Baseline) Bypassed(sig Signature) bool {
	return sig.DiffersFrom(b.denied)
}
