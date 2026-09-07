// Package uniformwall is the one shared primitive behind Phase 7 Step 4's
// D6: "does this host answer every request with a single generic page?".
//
// Two distinct shapes both defeat every content-matching detector and waste
// a full template-corpus pass:
//
//   - a WAF / bot-protection / auth layer that intercepts every request and
//     returns a block page (HTTP 403/401/429, or a vendor block-page
//     signature) — hit live on www.valmo.in, 2026-09-07 (Akamai), where a
//     `--recon-file` misconfig scan ran 30 min+ for 0 findings while the
//     native detector answered `misconfig-waf-blocked` in 5.8 s
//     (docs/follow-up.md LT-43, LT-57, LT-59);
//   - a SPA shell / storage-bucket fallback that returns one 2xx page for
//     every path — hit live on www.valmo.in (2026-09-06, GCS 200 catch-all)
//     and linkpop.com (2026-09-07, decommissioned; GCS `UploadServer`
//     serving one 746-byte 404 shell for every path) — docs/follow-up.md
//     LT-30, LT-66.
//
// pkg/recon records the verdict on ReconResult; pkg/registry consumes it so
// a blanket 403 no longer re-admits misconfig's ~1,591-template panel floor
// (LT-58); pkg/scanner consumes it to short-circuit the per-target corpus
// (LT-59); the block-page marker list is the single copy
// pkg/detectors/misconfig's own WAF recognition now also reads.
package uniformwall

import (
	"net/http"
	"strings"
)

// Verdict classifies how uniformly a host responds.
type Verdict string

const (
	// VerdictNone is a normal host: a guaranteed-nonexistent path gets a
	// real 404 (or another app-routed status), distinct from real content.
	VerdictNone Verdict = ""
	// VerdictWAFBlock means a layer above the application intercepts every
	// request — a known block-page signature, or a guaranteed-nonexistent
	// path answered 401/403/429 instead of 404.
	VerdictWAFBlock Verdict = "waf-block"
	// VerdictCatchall means every path resolves to one generic 2xx/3xx page
	// (a SPA shell, a static storage-bucket fallback) — no real routing.
	VerdictCatchall Verdict = "catchall"
)

// blockPageMarkers are content signatures of a specific, live-confirmed
// WAF/CDN interception page. Seeded from — and kept in sync with —
// pkg/detectors/misconfig's original `knownWAFBlockPageMarkers`: only
// Akamai's confirmed marker, deliberately narrow, expand only with the same
// live-confirmation discipline (CLAUDE.md's "flag doubtful matchers instead
// of guessing"). Just the alphanumeric run "edgesuite", not the dotted
// "errors.edgesuite.net" — Akamai HTML-entity-encodes punctuation in this
// page, so a marker with literal dots silently never matches.
var blockPageMarkers = []string{
	"edgesuite", // Akamai's block-page reference-link domain (errors.edgesuite.net)
}

// storageOriginServerTokens are lower-cased Server header values that mark a
// static object store answering with one fallback object for every path
// (Google Cloud Storage's `UploadServer`, an S3 website endpoint). On their
// own they are not a wall — paired with a 2xx guaranteed-nonexistent path,
// they are a catch-all.
var storageOriginServerTokens = []string{
	"uploadserver", // Google Cloud Storage
	"amazons3",     // S3 REST endpoint
}

// LooksLikeKnownBlockPage reports whether body carries a known WAF/CDN
// block-page signature. Exported so pkg/detectors/misconfig reads this one
// copy instead of its own.
func LooksLikeKnownBlockPage(body []byte) bool {
	s := string(body)
	for _, m := range blockPageMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// Observation is one probe's response shape — enough for Classify to decide
// uniformity without holding whole bodies. Body is a sample (callers may
// truncate) used only for marker matching.
type Observation struct {
	Status       int
	BodyLen      int
	ContentType  string // raw Content-Type; normalized internally
	ServerHeader string // raw Server header
	Body         []byte // sample for block-page marker matching
}

// StorageOrigin reports whether the Server header names a static object
// store (see storageOriginServerTokens).
func (o Observation) StorageOrigin() bool {
	s := strings.ToLower(strings.TrimSpace(o.ServerHeader))
	for _, t := range storageOriginServerTokens {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// Classify decides whether a host is a uniform wall from its response to a
// guaranteed-nonexistent canary path and, when available, its root ("/")
// response. root may be nil (recon has it from httpx; the scan engine
// fetches it). A block-page signature or an intercept status on the canary
// is decisive on its own; a catch-all needs corroboration (root is
// shape-identical, or the canary came from a storage origin) so a normal
// SPA that legitimately serves its shell on an unknown path but real JSON
// on real API routes is not mislabeled.
func Classify(canary Observation, root *Observation) Verdict {
	if LooksLikeKnownBlockPage(canary.Body) || (root != nil && LooksLikeKnownBlockPage(root.Body)) {
		return VerdictWAFBlock
	}
	switch canary.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return VerdictWAFBlock
	}
	if canary.Status >= 200 && canary.Status < 400 {
		if root != nil && sameShape(canary, *root) {
			return VerdictCatchall
		}
		if canary.StorageOrigin() {
			return VerdictCatchall
		}
	}
	return VerdictNone
}

// sameShape reports whether two observations are the same generic page:
// identical status and normalized media type, body lengths within a small
// relative tolerance (a shell can embed the requested path or a nonce).
// Mirrors pkg/recon's own canaryResponse.sameAsCanary tolerance.
func sameShape(a, b Observation) bool {
	if a.Status != b.Status || normalizeContentType(a.ContentType) != normalizeContentType(b.ContentType) {
		return false
	}
	tol := a.BodyLen / 10
	if tol < 64 {
		tol = 64
	}
	d := a.BodyLen - b.BodyLen
	if d < 0 {
		d = -d
	}
	return d <= tol
}

// normalizeContentType lower-cases a Content-Type and drops its parameters
// (";charset=utf-8"), leaving the media type. Duplicated (three lines) from
// pkg/recon rather than depending on it — pkg/recon imports consumers of
// this package, not the other way around.
func normalizeContentType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}
