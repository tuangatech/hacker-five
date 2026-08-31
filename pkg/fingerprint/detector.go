// Package fingerprint implements deterministic tech-signature detection
// (docs/14-implementation-plan-ph5.md Step 3's R7, docs/90-research-
// hackerbot.md's Decision 6/I2): a static signature table matching
// response headers, body substrings, favicon hashes, and well-known ports
// against a product name. This doesn't replace pkg/recon's own
// httpx-driven -tech-detect facts — it's a deterministic layer built on
// top of the same signals httpx already collects, for what Wappalyzer's own
// dataset (what -tech-detect uses) doesn't catch.
package fingerprint

import "strings"

// Signal is the observable evidence one probed host produced, for Match to
// check against Signature's conditions.
type Signal struct {
	Headers     map[string]string // lowercase header name -> value (httpx's own JSON output is already lowercase-keyed)
	Body        string
	FaviconHash string
	Ports       []int
}

// SourceHeader/SourceBody/SourceFavicon/SourcePort label which signal type
// produced a Match — the caller (pkg/recon) uses this to band a
// resulting TechFact's Confidence: a header or favicon match is strong
// (exact/structured evidence), a body substring is a heuristic, and a
// port-only match is weak (an open port doesn't confirm what's listening).
const (
	SourceHeader  = "fingerprint-header"
	SourceBody    = "fingerprint-body"
	SourceFavicon = "fingerprint-favicon"
	SourcePort    = "fingerprint-port"
)

// Match is one signature that fired against a Signal.
type Match struct {
	Product string
	Source  string
}

// Detect checks every Signature against s, returning one Match per
// signature whose non-empty conditions are all satisfied (AND semantics).
// The same product can appear more than once if multiple independent
// signatures fire for it (e.g. both a header and a body match) — the
// caller decides whether/how to dedupe.
func Detect(s Signal) []Match {
	var matches []Match
	for _, sig := range signatures {
		if src, ok := evaluate(sig, s); ok {
			matches = append(matches, Match{Product: sig.Product, Source: src})
		}
	}
	return matches
}

// evaluate reports whether every non-empty condition on sig holds against
// s, and which single Source label to report — signatures in this table
// only ever set one condition at a time (see signatures.go), so the first
// condition found true is the one reported; a future multi-condition
// signature would need this to report all of them, not just the first.
func evaluate(sig Signature, s Signal) (source string, ok bool) {
	if sig.HeaderName != "" {
		v, found := lookupHeader(s.Headers, sig.HeaderName)
		if !found || !containsFold(v, sig.HeaderContains) {
			return "", false
		}
		return SourceHeader, true
	}
	if sig.BodyContains != "" {
		if !containsFold(s.Body, sig.BodyContains) {
			return "", false
		}
		return SourceBody, true
	}
	if sig.FaviconHash != "" {
		if s.FaviconHash != sig.FaviconHash {
			return "", false
		}
		return SourceFavicon, true
	}
	if sig.Port != 0 {
		if !containsPort(s.Ports, sig.Port) {
			return "", false
		}
		return SourcePort, true
	}
	return "", false
}

func lookupHeader(headers map[string]string, name string) (string, bool) {
	lower := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == lower {
			return v, true
		}
	}
	return "", false
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func containsPort(ports []int, want int) bool {
	for _, p := range ports {
		if p == want {
			return true
		}
	}
	return false
}
