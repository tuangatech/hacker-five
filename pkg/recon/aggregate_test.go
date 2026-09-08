package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestClassifyAppSurface covers LT-68's synthesised none/thin/full verdict.
func TestClassifyAppSurface(t *testing.T) {
	twoXX := func(n int) []EndpointFact {
		out := make([]EndpointFact, n)
		for i := range out {
			out[i] = EndpointFact{StatusCode: 200}
		}
		return out
	}
	tech := []TechFact{{Name: "nginx"}}

	assert.Equal(t, "none", classifyAppSurface(nil, nil, &UniformResponseFact{Kind: "waf-block"}).Verdict)
	assert.Equal(t, "none", classifyAppSurface(nil, nil, nil).Verdict)
	assert.Equal(t, "none", classifyAppSurface([]EndpointFact{{StatusCode: 301}}, nil, nil).Verdict)
	assert.Equal(t, "thin", classifyAppSurface(nil, tech, nil).Verdict)
	assert.Equal(t, "thin", classifyAppSurface(twoXX(2), nil, nil).Verdict)
	assert.Equal(t, "full", classifyAppSurface(twoXX(9), tech, nil).Verdict)

	// LT-102: a host-scoped uniform-wall verdict must not condemn a
	// multi-host result where other hosts plainly served real applications.
	realApp := func(host, title string) EndpointFact {
		return EndpointFact{URL: "https://" + host + "/", StatusCode: 200, Title: title}
	}
	crawledRoute := func(host, path string) EndpointFact {
		return EndpointFact{URL: "https://" + host + path, StatusCode: 200, Source: "katana-crawl"}
	}
	wall := &UniformResponseFact{Host: "erp.nettix.com.pe", Kind: "catchall"}

	// Only the walled host has any content → still "none".
	assert.Equal(t, "none", classifyAppSurface(
		[]EndpointFact{realApp("erp.nettix.com.pe", "Login")}, nil, wall).Verdict)

	// Two other hosts served real, titled applications → not blind; "thin".
	got := classifyAppSurface([]EndpointFact{
		realApp("www.nettix.com.pe", "Bienvenido a Nettix Perú |"),
		realApp("cloud01.nettix.com.pe", "Login – Nextcloud"),
	}, nil, wall)
	assert.Equal(t, "thin", got.Verdict)
	assert.Contains(t, got.Reason, "catchall wall on erp.nettix.com.pe")

	// Four+ real-app hosts alongside the wall → "full".
	assert.Equal(t, "full", classifyAppSurface([]EndpointFact{
		realApp("www.nettix.com.pe", "Bienvenido a Nettix Perú |"),
		realApp("soporte.nettix.com.pe", "Soporte Nettix"),
		realApp("cloud01.nettix.com.pe", "Login – Nextcloud"),
		realApp("cloud02.nettix.com.pe", "Login – Nextcloud"),
		crawledRoute("wiki.nettix.com.pe", "/doku.php"),
	}, nil, wall).Verdict)

	// A generic server landing page / auth interstitial is not a "real app".
	assert.False(t, endpointShowsRealApp(realApp("pe01.nettix.com.pe", "Welcome to nginx!")))
	assert.False(t, endpointShowsRealApp(EndpointFact{URL: "https://x/", StatusCode: 200, Title: "401 Authorization Required"}))
	assert.True(t, endpointShowsRealApp(crawledRoute("ixn.nettix.com.pe", "/viewimage.php")))
}

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

// TestAddTech_SameNameDifferentCase_MergesInsteadOfDuplicating guards the
// 2026-09-04 fix: a real target's Tech Stack showed both "LiteSpeed Cache"
// and "Litespeed Cache" as two rows for the same plugin — httpx's own
// embedded fingerprint catalog carries both castings as separate entries.
func TestAddTech_SameNameDifferentCase_MergesInsteadOfDuplicating(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "LiteSpeed Cache", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Litespeed Cache", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})

	result := agg.finalize()
	if assert.Len(t, result.TechStack, 1, "the same technology observed with different casing must merge into one row, not two") {
		assert.Equal(t, "LiteSpeed Cache", result.TechStack[0].Name, "the first-seen casing is kept as the canonical display name")
	}
}

// TestAddTech_WwwAndCaseHostVariants_MergeInsteadOfDuplicating guards the
// LT-14 fix (docs/follow-up.md): a real target's Tech Stack showed the
// same technology three times over, once each for "www.nettix.com.pe",
// "Nettix.com.pe" and "nettix.com.pe" — httpx probes a target's bare/www./
// as-typed host variants independently, and each produced its own TechFact
// with a differently-cased or www.-prefixed Host, none of which collided
// under addTech's pre-fix (lowercased-Name, raw-Host) key.
func TestAddTech_WwwAndCaseHostVariants_MergeInsteadOfDuplicating(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Site Kit", Host: "www.nettix.com.pe", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Site Kit", Host: "Nettix.com.pe", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Site Kit", Host: "nettix.com.pe", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})

	result := agg.finalize()
	assert.Len(t, result.TechStack, 1, "www./bare/mixed-case variants of the same host must merge into one row, not three")
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
