package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddTech_SameNameAndHost_MergesInsteadOfDuplicating(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Cloudflare", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Cloudflare", Host: "example.com", Source: "fingerprint-header", Confidence: ConfidenceHigh})

	result := agg.finalize()
	if assert.Len(t, result.TechStack, 1, "the same (Name, Host) observed by two sources must merge into one row, not two") {
		fact := result.TechStack[0]
		assert.Equal(t, "httpx-tech-detect, fingerprint-header", fact.Source)
		assert.Equal(t, ConfidenceHigh, fact.Confidence, "confidence must promote to the higher of the two sources, not stay at the first-seen value")
	}
}

func TestAddTech_DifferentHost_StaysDistinct(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Cloudflare", Host: "a.example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Cloudflare", Host: "b.example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})

	result := agg.finalize()
	assert.Len(t, result.TechStack, 2, "the same tech on two distinct hosts is genuinely distinct information, not a duplicate")
}

func TestAddTech_DifferentName_StaysDistinct(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Cloudflare", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Nginx", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})

	result := agg.finalize()
	assert.Len(t, result.TechStack, 2)
}

func TestAddTech_SameSourceTwice_SourceNotDuplicatedInString(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Cloudflare", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Cloudflare", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})

	result := agg.finalize()
	if assert.Len(t, result.TechStack, 1) {
		assert.Equal(t, "httpx-tech-detect", result.TechStack[0].Source, "the same source reported twice must not repeat itself in the merged string")
	}
}

func TestAddTech_LowerConfidenceArrivesSecond_DoesNotDowngrade(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Cloudflare", Host: "example.com", Source: "fingerprint-header", Confidence: ConfidenceHigh})
	agg.addTech(TechFact{Name: "Cloudflare", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})

	result := agg.finalize()
	if assert.Len(t, result.TechStack, 1) {
		assert.Equal(t, ConfidenceHigh, result.TechStack[0].Confidence, "a later, lower-confidence source must never downgrade an already-higher confidence")
	}
}
