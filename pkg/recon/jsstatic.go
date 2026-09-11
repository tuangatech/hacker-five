package recon

import (
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// jsAsset is one served JavaScript body Wave 3 already fetched (via katana's
// own -jc crawl) that runJSStaticAnalysis inspects — captured once at
// ingestion (runKatana), analyzed here with zero new requests (Phase 8 Step
// 3, docs/17-implementation-plan-ph8.md: "pure functions over data recon
// already has in hand").
type jsAsset struct {
	URL  string
	Body string
}

const (
	// maxJSStaticAssets bounds how many distinct .js bodies one recon run
	// analyzes — the crawl can surface far more than this on a large SPA;
	// analyzing the first N keeps the regex/entropy work bounded.
	maxJSStaticAssets = 25
	// maxJSStaticBodyBytes truncates a single JS body before it's even kept
	// (set at capture time in runKatana) — a multi-MB bundle's tail is
	// usually vendored/minified library code, not application routes.
	maxJSStaticBodyBytes = 512 << 10
	// maxJSQuotedStringsPerAsset bounds how many quoted-string candidates one
	// asset's regex pass considers, so a single pathological bundle (huge
	// data URI, embedded JSON blob) can't blow up the CPU cost of one file.
	maxJSQuotedStringsPerAsset = 5000
	// maxJSStaticEndpoints / maxJSStaticSecrets bound the total facts one run
	// emits from this pass, each with a truncation warning past the cap —
	// same "bounded, not silently truncated" convention as maxSpecEndpoints.
	maxJSStaticEndpoints = 150
	maxJSStaticSecrets   = 50
)

// looksLikeJSAsset reports whether a katana-observed record is a JavaScript
// response worth capturing the body of — by URL extension (the common case)
// or by a captured Content-Type header (a .js-less route serving script,
// e.g. a bundler dev-server path).
func looksLikeJSAsset(rawURL string, headers map[string]string) bool {
	if u, err := url.Parse(rawURL); err == nil && strings.HasSuffix(strings.ToLower(u.Path), ".js") {
		return true
	}
	for k, v := range headers {
		if strings.EqualFold(k, "content-type") {
			ct := strings.ToLower(v)
			return strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
		}
	}
	return false
}

// jsQuotedStringRe pulls every double- or single-quoted string literal out
// of a JS body — deliberately shape-agnostic (LinkFinder-style: grab
// everything quoted, then filter in Go) rather than trying to encode "looks
// like a URL" into the regex itself, which is far harder to review and tune.
var jsQuotedStringRe = regexp.MustCompile(`"([^"\n]{2,200})"|'([^'\n]{2,200})'`)

// isCandidateEndpointString reports whether a quoted string literal is
// shaped like a real request path or absolute URL — the coarse pre-filter
// before IsPlausibleURLPath/IsNonRouteAssetPath do the real work.
func isCandidateEndpointString(s string) bool {
	if strings.HasPrefix(s, "/") {
		return len(s) > 2 && s[1] != '/' && s[1] != '.'
	}
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// extractJSEndpoints returns every plausible relative-path or absolute-URL
// candidate found in body, resolved against assetURL's own host for a
// relative path. Filtering reuses the same IsPlausibleURLPath (LT-85,
// rejects a JS-syntax fragment) / IsNonRouteAssetPath (static/build-artifact
// noise) helpers the recon-derived candidate suggesters already rely on, so
// this pass holds itself to the identical bar rather than inventing a
// second one.
func extractJSEndpoints(assetURL, body string) []string {
	assetHost := ""
	if u, err := url.Parse(assetURL); err == nil {
		assetHost = u.Scheme + "://" + u.Host
	}

	matches := jsQuotedStringRe.FindAllStringSubmatch(body, maxJSQuotedStringsPerAsset)
	seen := map[string]bool{}
	var out []string
	for _, m := range matches {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		if !isCandidateEndpointString(s) {
			continue
		}
		if strings.HasPrefix(s, "/") {
			if !IsPlausibleURLPath(s) || IsNonRouteAssetPath(s) {
				continue
			}
			if assetHost == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, assetHost+s)
			continue
		}
		u, err := url.Parse(s)
		if err != nil || u.Host == "" || u.Path == "" || u.Path == "/" {
			continue
		}
		if !IsPlausibleURLPath(u.Path) || IsNonRouteAssetPath(u.Path) {
			continue
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// jsSecretPattern is one curated, high-signal secret pattern — deliberately
// small (Phase 8 Step 3, docs/follow-up.md: "a doubtful pattern is left out,
// not guessed", feeding the project's <5% false-positive target). group
// selects which regex submatch is the value to redact/entropy-check (0 =
// whole match); entropyFloor > 0 marks a shape-only pattern (no fixed
// vendor prefix) that also needs Shannon-entropy + placeholder screening.
type jsSecretPattern struct {
	kind         string
	severity     string
	re           *regexp.Regexp
	group        int
	entropyFloor float64
}

var jsSecretPatterns = []jsSecretPattern{
	// AWS access/session key IDs: a fixed 4-letter prefix + 16 fixed-width
	// base32-ish chars — effectively zero false-positive rate on its own.
	{kind: "aws-access-key", severity: "high", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	// Google API keys always start "AIzaSy" and are a fixed 39 chars.
	{kind: "google-api-key", severity: "medium", re: regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{kind: "slack-token", severity: "high", re: regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,72}\b`)},
	// GitHub's current fine-grained/classic token prefixes.
	{kind: "github-token", severity: "critical", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{kind: "private-key", severity: "critical", re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	// The one shape-only pattern — no vendor-fixed prefix, so it leans on
	// the entropy floor + placeholder screen below to cut noise.
	{kind: "hardcoded-bearer-token", severity: "medium",
		re:    regexp.MustCompile(`(?i)authorization["']?\s*[:=]\s*["']Bearer\s+([A-Za-z0-9\-_.=]{20,})["']`),
		group: 1, entropyFloor: 3.0},
}

// bearerPlaceholderMarkers are substrings (case-insensitive) that mark a
// Bearer-token literal as sample/placeholder text rather than a real leaked
// credential — checked before the entropy floor since a long repetitive
// placeholder can still clear a low entropy threshold.
var bearerPlaceholderMarkers = []string{
	"your_token", "your-token", "yourtoken", "changeme", "example",
	"xxxx", "placeholder", "token_here", "test_token", "sample",
	"<token>", "{{", "}}", "insert_token", "replace_me", "dummy", "fake",
}

// shannonEntropy returns the Shannon entropy of s in bits per character —
// low for repetitive/placeholder text, high for a genuinely random token.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// redactSecret keeps only the first/last few characters of a matched secret
// — enough to confirm the finding without the real value ever leaving this
// process into a ReconResult / JSON export.
func redactSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// extractJSSecrets scans body for jsSecretPatterns and returns one
// JSSecretFact per accepted hit, each carrying a 1-based line number and a
// redacted match — never the real secret value.
func extractJSSecrets(assetURL, body string) []JSSecretFact {
	var out []JSSecretFact
	for _, pat := range jsSecretPatterns {
		locs := pat.re.FindAllStringSubmatchIndex(body, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			if pat.group > 0 {
				gi := pat.group * 2
				if gi+1 >= len(loc) || loc[gi] < 0 {
					continue
				}
				start, end = loc[gi], loc[gi+1]
			}
			value := body[start:end]
			if pat.entropyFloor > 0 {
				lower := strings.ToLower(value)
				placeholder := false
				for _, m := range bearerPlaceholderMarkers {
					if strings.Contains(lower, m) {
						placeholder = true
						break
					}
				}
				if placeholder || shannonEntropy(value) < pat.entropyFloor {
					continue
				}
			}
			line := strings.Count(body[:start], "\n") + 1
			out = append(out, JSSecretFact{
				URL: assetURL, Line: line, Kind: pat.kind,
				Severity: pat.severity, Redacted: redactSecret(value),
			})
		}
	}
	return out
}

// cloudBucketRef is one AWS S3 / GCS bucket URL shape found in already-
// fetched text (a JS body or an endpoint URL) — P1-5, docs/follow-up.md.
type cloudBucketRef struct {
	kind string // "s3" | "gcp"
	url  string // the canonical bucket URL, host- or path-style as found
}

// The path-style patterns require the literal scheme immediately before the
// shared-bucket host ("https://s3.amazonaws.com/bucket") — without that
// anchor they also fire inside a host-style URL
// ("https://bucket.s3.amazonaws.com/key"), misreading the object key as a
// second, bogus bucket name.
var (
	s3BucketHostRe  = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b`)
	s3BucketPathRe  = regexp.MustCompile(`(?i)https?://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\b`)
	gcsBucketHostRe = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9_.-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b`)
	gcsBucketPathRe = regexp.MustCompile(`(?i)https?://storage\.googleapis\.com/([a-z0-9][a-z0-9_.-]{1,61}[a-z0-9])\b`)
)

// extractCloudBucketRefs finds AWS S3 / GCS bucket-URL shapes in text,
// deduped by (kind, url) within this one call.
func extractCloudBucketRefs(text string) []cloudBucketRef {
	seen := map[string]bool{}
	var refs []cloudBucketRef
	add := func(kind, rawURL string) {
		key := kind + "|" + rawURL
		if seen[key] {
			return
		}
		seen[key] = true
		refs = append(refs, cloudBucketRef{kind: kind, url: rawURL})
	}
	for _, m := range s3BucketHostRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("s3", "https://"+bucket+".s3.amazonaws.com/")
	}
	for _, m := range s3BucketPathRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("s3", "https://s3.amazonaws.com/"+bucket+"/")
	}
	for _, m := range gcsBucketHostRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("gcp", "https://"+bucket+".storage.googleapis.com/")
	}
	for _, m := range gcsBucketPathRe.FindAllStringSubmatch(text, -1) {
		bucket := strings.ToLower(m[1])
		add("gcp", "https://storage.googleapis.com/"+bucket+"/")
	}
	return refs
}

// recordCloudBucketRef turns one discovered bucket-URL shape into recon
// facts, gated on the bucket's own scope check — never on the page that
// mentioned it. The corpus's aws/s3/gcp-tagged bucket-exposure templates
// (aws-object-listing, s3-username-disclosure, ...) need to run *against the
// bucket itself* to mean anything, so the TechFact is attached to the
// bucket's own host, and only once that host independently clears --scope:
// a page can reference any number of third-party buckets that have nothing
// to do with the target's own infrastructure, so a mention alone earns
// neither a scan nor a fact about the referencing host.
func (r *Recon) recordCloudBucketRef(agg *aggregator, ref cloudBucketRef) {
	bucketHost := hostOnly(ref.url)
	if r.scope != nil && !r.scope.Allowed(ref.url) {
		agg.addOutOfScope(bucketHost)
		return
	}
	agg.addEndpoint(EndpointFact{URL: ref.url, Method: http.MethodGet, Source: "js-static-cloud", Confidence: ConfidenceLow})
	agg.addTech(TechFact{Name: ref.kind, Host: bucketHost, Source: "js-static-cloud", Confidence: ConfidenceMedium})
}

// runJSStaticAnalysis is Phase 8 Step 3 (docs/17-implementation-plan-ph8.md):
// endpoint extraction, hardcoded-secret detection, and cloud-provider
// bucket-URL fingerprinting over Wave 3's already-fetched JS bodies — pure
// functions over data recon already has in hand, no new request, no new
// dependency.
//
// LT-144 (docs/follow-up.md): extractJSEndpoints's absolute-URL branch only
// checks path *shape* (IsPlausibleURLPath/IsNonRouteAssetPath), never host —
// a page can reference an absolute URL on a completely unrelated third-party
// domain (a namespace URI, a CDN, a vendor's own site) and that host must
// clear --scope before its fact is kept, exactly like recordCloudBucketRef
// already does for bucket URLs a few lines above. Silently dropping an
// out-of-scope endpoint here isn't enough on its own — addOutOfScope logs it
// the same way every other out-of-scope path in this codebase does, so a
// surprising extraction is loud, not silently absent.
func (r *Recon) runJSStaticAnalysis(agg *aggregator, assets []jsAsset) {
	endpointsAdded, secretsAdded := 0, 0
	endpointsTruncated, secretsTruncated := false, false

	for _, asset := range assets {
		for _, epURL := range extractJSEndpoints(asset.URL, asset.Body) {
			if endpointsAdded >= maxJSStaticEndpoints {
				endpointsTruncated = true
				break
			}
			if r.scope != nil && !r.scope.Allowed(epURL) {
				agg.addOutOfScope(hostOnly(epURL))
				continue
			}
			agg.addEndpoint(EndpointFact{URL: epURL, Method: http.MethodGet, Source: "js-static", Confidence: ConfidenceLow})
			endpointsAdded++
		}

		for _, s := range extractJSSecrets(asset.URL, asset.Body) {
			if secretsAdded >= maxJSStaticSecrets {
				secretsTruncated = true
				break
			}
			agg.addSecret(s)
			secretsAdded++
		}

		for _, ref := range extractCloudBucketRefs(asset.Body) {
			r.recordCloudBucketRef(agg, ref)
		}
	}

	// Also check URLs already crawled by other Wave 3 passes — a bucket
	// referenced by a plain HTML tag (<img src>) rather than JS never
	// reaches the loop above. Snapshotted first since recordCloudBucketRef
	// can itself append to agg.endpoints (a self-referential match on the
	// js-static-cloud endpoint just added there just re-derives the same
	// already-recorded fact, not a new request, but iterating a live slice
	// while appending to it is needless subtlety to lean on).
	existingURLs := make([]string, len(agg.endpoints))
	for i, ep := range agg.endpoints {
		existingURLs[i] = ep.URL
	}
	for _, epURL := range existingURLs {
		for _, ref := range extractCloudBucketRefs(epURL) {
			r.recordCloudBucketRef(agg, ref)
		}
	}

	if endpointsTruncated {
		agg.addWarning("wave3: js-static: endpoint extraction hit its %d-candidate cap — more may be present in the crawled JS (Phase 8 Step 3)", maxJSStaticEndpoints)
	}
	if secretsTruncated {
		agg.addWarning("wave3: js-static: secret detection hit its %d-hit cap — more may be present in the crawled JS (Phase 8 Step 3)", maxJSStaticSecrets)
	}
	if secretsAdded > 0 {
		agg.addWarning("wave3: js-static: found %d hardcoded secret(s) in served JavaScript (Phase 8 Step 3) — see the ReconResult's \"secrets\" field", secretsAdded)
	}
}
