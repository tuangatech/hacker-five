package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	assert.Equal(t, "none", classifyAppSurface(nil, nil, uniformMap(UniformResponseFact{Kind: "waf-block"})).Verdict)
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
	wall := uniformMap(UniformResponseFact{Host: "erp.nettix.com.pe", Kind: "catchall"})

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

// uniformMap builds classifyAppSurface's uniform argument the same way
// aggregator.finalize() does — keyed by NormalizeHost(Host) — from a
// var-args list of facts, so a test reads as a plain list of walled hosts.
func uniformMap(facts ...UniformResponseFact) map[string]UniformResponseFact {
	m := make(map[string]UniformResponseFact, len(facts))
	for _, f := range facts {
		m[NormalizeHost(f.Host)] = f
	}
	return m
}

// TestClassifyAppSurface_TwoWalledHosts guards LT-140: a multi-host recon
// run with more than one uniform-response wall must judge "blind" against
// *all* of them, not just a single named host — before the fix,
// classifyAppSurface only ever took one UniformResponseFact, so a second
// walled host in the same run was invisible to this function entirely.
func TestClassifyAppSurface_TwoWalledHosts(t *testing.T) {
	realApp := func(host, title string) EndpointFact {
		return EndpointFact{URL: "https://" + host + "/", StatusCode: 200, Title: title}
	}
	walls := uniformMap(
		UniformResponseFact{Host: "waf.nettix.com.pe", Kind: "waf-block"},
		UniformResponseFact{Host: "bucket.nettix.com.pe", Kind: "catchall"},
	)

	// Only the two walled hosts have any content → still "none", not just
	// checked against whichever wall happened to be first.
	assert.Equal(t, "none", classifyAppSurface(
		[]EndpointFact{realApp("waf.nettix.com.pe", "Blocked"), realApp("bucket.nettix.com.pe", "Shell")},
		nil, walls).Verdict)

	// A third, unwalled host serves a real app → not blind; "thin", and the
	// reason names both walled hosts.
	got := classifyAppSurface([]EndpointFact{
		realApp("waf.nettix.com.pe", "Blocked"),
		realApp("www.nettix.com.pe", "Bienvenido a Nettix Perú |"),
	}, nil, walls)
	assert.Equal(t, "thin", got.Verdict)
	assert.Contains(t, got.Reason, "2 host(s)")
	assert.Contains(t, got.Reason, "bucket.nettix.com.pe")
	assert.Contains(t, got.Reason, "waf.nettix.com.pe")
}

// TestSetUniformResponse_MultipleHosts_AllRecorded guards LT-140's actual
// aggregator-level bug: before the fix, setUniformResponse kept only "the
// first verdict seen" full stop, so a second walled host in the same
// multi-host recon run was silently dropped from the final ReconResult.
func TestSetUniformResponse_MultipleHosts_AllRecorded(t *testing.T) {
	agg := &aggregator{}
	agg.setUniformResponse(UniformResponseFact{Host: "waf.example.test", Kind: "waf-block", CanaryStatus: 403})
	agg.setUniformResponse(UniformResponseFact{Host: "bucket.example.test", Kind: "catchall", CanaryStatus: 200})

	result := agg.finalize()
	require.Len(t, result.UniformResponses, 2, "both walled hosts must survive to the final result, not just the first one probed")

	hosts := result.UniformWallHosts()
	assert.Equal(t, "waf-block", hosts["waf.example.test"])
	assert.Equal(t, "catchall", hosts["bucket.example.test"])
}

// TestSetUniformResponse_SameHostTwice_FirstWriterWins guards the existing
// per-host discipline: a later, weaker signal for a host already recorded
// must not clear or replace its verdict.
func TestSetUniformResponse_SameHostTwice_FirstWriterWins(t *testing.T) {
	agg := &aggregator{}
	agg.setUniformResponse(UniformResponseFact{Host: "www.example.test", Kind: "waf-block", CanaryStatus: 403})
	agg.setUniformResponse(UniformResponseFact{Host: "example.test", Kind: "catchall", CanaryStatus: 200})

	result := agg.finalize()
	require.Len(t, result.UniformResponses, 1, "www./bare variants of the same host must not produce two entries (NormalizeHost dedup, LT-14 convention)")
	assert.Equal(t, "waf-block", result.UniformResponses[0].Kind, "the first-seen verdict for a host must win")
}

func TestUniformResponseForHost_NormalizesHostAndMisses(t *testing.T) {
	result := &ReconResult{UniformResponses: []UniformResponseFact{
		{Host: "www.example.test", Kind: "waf-block"},
	}}

	got := result.UniformResponseForHost("Example.test")
	if assert.NotNil(t, got, "a www./case variant must still match") {
		assert.Equal(t, "waf-block", got.Kind)
	}
	assert.Nil(t, result.UniformResponseForHost("other.test"))
	assert.Nil(t, (*ReconResult)(nil).UniformResponseForHost("example.test"))
	assert.Nil(t, (&ReconResult{}).UniformWallHosts())
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

// TestAddTech_UnversionedThenVersioned_UpgradesInPlace is Phase 8 Step 4:
// httpx-tech-detect's bare "Nginx" arrives first, a later
// Server:-header parse resolves "Nginx:1.25.3" for the same host — the
// existing row upgrades to the versioned Name instead of producing a second,
// redundant row.
func TestAddTech_UnversionedThenVersioned_UpgradesInPlace(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Nginx", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Nginx:1.25.3", Host: "example.com", Source: "recon-server-header", Confidence: ConfidenceMedium})

	result := agg.finalize()
	if assert.Len(t, result.TechStack, 1, "the versioned fact must merge into the existing row, not add a second one") {
		assert.Equal(t, "Nginx:1.25.3", result.TechStack[0].Name)
		assert.Contains(t, result.TechStack[0].Source, "httpx-tech-detect")
		assert.Contains(t, result.TechStack[0].Source, "recon-server-header")
	}
}

// TestAddTech_SecondConflictingVersion_FirstVersionWins guards against
// flip-flopping: once a version is recorded, a second, different version
// for the same product+host never overwrites it.
func TestAddTech_SecondConflictingVersion_FirstVersionWins(t *testing.T) {
	agg := &aggregator{}
	agg.addTech(TechFact{Name: "Nginx:1.25.3", Host: "example.com", Source: "recon-server-header", Confidence: ConfidenceMedium})
	agg.addTech(TechFact{Name: "Nginx:1.24.0", Host: "example.com", Source: "httpx-tech-detect", Confidence: ConfidenceMedium})

	result := agg.finalize()
	if assert.Len(t, result.TechStack, 1) {
		assert.Equal(t, "Nginx:1.25.3", result.TechStack[0].Name, "first-recorded version wins, never overwritten by a later one")
	}
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

// TestAddHost_SameHost_MergesInsteadOfDuplicating guards the LT-147 fix
// (docs/follow-up.md): a real target's Hosts table showed the apex host
// twice — once from Wave 1's passive WHOIS/ASN lookup (Source
// "passive-whois-asn", carrying .Notes) and once from Wave 2's httpx/naabu
// probe (Source "httpx", carrying .Ports) — every other discovered host got
// exactly one entry. Mirrors TestAddTech_SameNameAndHost_
// MergesInsteadOfDuplicating's shape.
func TestAddHost_SameHost_MergesInsteadOfDuplicating(t *testing.T) {
	agg := &aggregator{}
	agg.addHost(HostFact{Host: "nettix.com.pe", Notes: []string{"asn: AS12345 | Example ISP | PE"}, Source: "passive-whois-asn", Confidence: ConfidenceMedium})
	agg.addHost(HostFact{Host: "nettix.com.pe", Ports: []PortFact{{Port: 443, Protocol: "tcp", Service: "https"}}, Source: "httpx", Confidence: ConfidenceHigh})

	result := agg.finalize()
	if assert.Len(t, result.Hosts, 1, "the apex host observed by two waves must merge into one row, not two") {
		host := result.Hosts[0]
		assert.Equal(t, "passive-whois-asn, httpx", host.Source)
		assert.Equal(t, []string{"asn: AS12345 | Example ISP | PE"}, host.Notes, "Notes from the first source must be kept, not dropped")
		if assert.Len(t, host.Ports, 1, "Ports from the second source must be unioned in, not dropped") {
			assert.Equal(t, 443, host.Ports[0].Port)
		}
		assert.Equal(t, ConfidenceHigh, host.Confidence, "confidence must promote to the higher of the two sources")
	}
}

// TestAddHost_WwwAndCaseHostVariants_MergeInsteadOfDuplicating mirrors
// TestAddTech_WwwAndCaseHostVariants_MergeInsteadOfDuplicating — the same
// NormalizeHost key addHost now shares with addTech.
func TestAddHost_WwwAndCaseHostVariants_MergeInsteadOfDuplicating(t *testing.T) {
	agg := &aggregator{}
	agg.addHost(HostFact{Host: "www.nettix.com.pe", Source: "httpx", Confidence: ConfidenceMedium})
	agg.addHost(HostFact{Host: "Nettix.com.pe", Source: "httpx", Confidence: ConfidenceMedium})
	agg.addHost(HostFact{Host: "nettix.com.pe", Source: "httpx", Confidence: ConfidenceMedium})

	result := agg.finalize()
	assert.Len(t, result.Hosts, 1, "www./bare/mixed-case variants of the same host must merge into one row, not three")
}

func TestAddHost_DifferentHost_StaysDistinct(t *testing.T) {
	agg := &aggregator{}
	agg.addHost(HostFact{Host: "a.example.com", Source: "httpx", Confidence: ConfidenceMedium})
	agg.addHost(HostFact{Host: "b.example.com", Source: "httpx", Confidence: ConfidenceMedium})

	result := agg.finalize()
	assert.Len(t, result.Hosts, 2, "two distinct hosts is genuinely distinct information, not a duplicate")
}

func TestAddHost_SameSourceTwice_SourceNotDuplicatedInString(t *testing.T) {
	agg := &aggregator{}
	agg.addHost(HostFact{Host: "example.com", Source: "httpx", Confidence: ConfidenceMedium})
	agg.addHost(HostFact{Host: "example.com", Source: "httpx", Confidence: ConfidenceMedium})

	result := agg.finalize()
	if assert.Len(t, result.Hosts, 1) {
		assert.Equal(t, "httpx", result.Hosts[0].Source, "the same source reported twice must not repeat itself in the merged string")
	}
}

func TestAddHost_LowerConfidenceArrivesSecond_DoesNotDowngrade(t *testing.T) {
	agg := &aggregator{}
	agg.addHost(HostFact{Host: "example.com", Source: "httpx", Confidence: ConfidenceHigh})
	agg.addHost(HostFact{Host: "example.com", Source: "passive-whois-asn", Confidence: ConfidenceMedium})

	result := agg.finalize()
	if assert.Len(t, result.Hosts, 1) {
		assert.Equal(t, ConfidenceHigh, result.Hosts[0].Confidence, "a later, lower-confidence source must never downgrade an already-higher confidence")
	}
}

// TestAddHost_DuplicatePort_NotDuplicated guards mergePortFacts: two waves
// that both happen to observe the same (Port, Protocol) on a host must not
// produce two identical PortFact rows.
func TestAddHost_DuplicatePort_NotDuplicated(t *testing.T) {
	agg := &aggregator{}
	agg.addHost(HostFact{Host: "example.com", Ports: []PortFact{{Port: 443, Protocol: "tcp"}}, Source: "httpx"})
	agg.addHost(HostFact{Host: "example.com", Ports: []PortFact{{Port: 443, Protocol: "tcp"}, {Port: 21, Protocol: "tcp"}}, Source: "naabu"})

	result := agg.finalize()
	if assert.Len(t, result.Hosts, 1) {
		assert.Len(t, result.Hosts[0].Ports, 2, "the port both sources agree on must appear once, the new one must still be added")
	}
}
