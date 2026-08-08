package idor

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
)

// interestingKeywords is the fixed set of substrings whose presence in a
// response body is tracked as a signal of real user content.
var interestingKeywords = []string{"email", "name", "user_id", "username", "phone", "address"}

// Signature is a compact fingerprint of an HTTP response, used to tell
// "denied" responses apart from real content without comparing raw bodies
// byte-for-byte (which would flag a timestamp or request-id in an error
// envelope as a different response).
type Signature struct {
	StatusCode int
	BodySize   int
	Hash       string   // SHA256 of the body
	Keywords   []string // presence of interestingKeywords — sorted, so two signatures with the same keyword set compare equal regardless of extraction order
}

// Sign fingerprints an HTTP response. body must be the already-read response body.
func Sign(resp *http.Response, body []byte) Signature {
	sum := sha256.Sum256(body)

	lower := strings.ToLower(string(body))
	var found []string
	for _, kw := range interestingKeywords {
		if strings.Contains(lower, kw) {
			found = append(found, kw)
		}
	}
	sort.Strings(found)

	return Signature{
		StatusCode: resp.StatusCode,
		BodySize:   len(body),
		Hash:       hex.EncodeToString(sum[:]),
		Keywords:   found,
	}
}

// Same reports whether a and b represent equivalent responses: StatusCode
// must match exactly, and either the body hash matches, or the body size is
// within 5% and the keyword sets are equal. The size+keywords fallback
// exists because two "denied" bodies can differ byte-for-byte (a timestamp
// or request-id in an error envelope) while still being the same denial.
func (a Signature) Same(b Signature) bool {
	if a.StatusCode != b.StatusCode {
		return false
	}
	if a.Hash == b.Hash {
		return true
	}
	return withinTolerance(a.BodySize, b.BodySize, 0.05) && sameKeywords(a.Keywords, b.Keywords)
}

// DiffersFrom is the negation of Same.
func (a Signature) DiffersFrom(b Signature) bool {
	return !a.Same(b)
}

func withinTolerance(a, b int, fraction float64) bool {
	if a == 0 && b == 0 {
		return true
	}
	diff := a - b
	if diff < 0 {
		diff = -diff
	}
	largest := a
	if b > largest {
		largest = b
	}
	return float64(diff) <= float64(largest)*fraction
}

func sameKeywords(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
