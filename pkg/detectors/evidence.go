package detectors

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// MaxEvidenceBodyBytes caps how much of a request/response body FormatRequest
// and FormatResponse capture — enough for a reproducible PoC without
// inflating findings.json with an entire large response body.
const MaxEvidenceBodyBytes = 2048

// redactedHeaders never appear verbatim in Evidence output. These carry
// live credentials (the scan's own bearer token, session cookies) that
// would otherwise leak into findings.json — a file routinely pasted into a
// report or shared as proof — in plaintext. Mirrors doc05's existing
// "Request Logging Best Practices: sanitize tokens/keys" rule, applied here
// to Finding.Evidence rather than request logs.
var redactedHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"proxy-authorization": true,
	"x-api-key":           true,
}

// FormatRequest renders a request's method, URL, headers (redacted per
// redactedHeaders), and body into a single string suitable for
// Finding.Evidence["request"] — the raw-request half of the
// reproducible-proof evidence trail flagged as missing in follow-up.md's
// senior-security-engineer review. body may be nil/empty for a bodyless
// request.
func FormatRequest(method, url string, headers http.Header, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", method, url)
	writeHeaders(&b, headers)
	writeBody(&b, body)
	return b.String()
}

// FormatResponse is FormatRequest's response-side counterpart, for
// Finding.Evidence["response"].
func FormatResponse(statusCode int, headers http.Header, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d\n", statusCode)
	writeHeaders(&b, headers)
	writeBody(&b, body)
	return b.String()
}

// writeHeaders sorts keys first so output (and therefore any test asserting
// against it) is deterministic — http.Header's own iteration order isn't.
func writeHeaders(b *strings.Builder, headers http.Header) {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := strings.Join(headers[k], ", ")
		if redactedHeaders[strings.ToLower(k)] {
			v = "[REDACTED]"
		}
		fmt.Fprintf(b, "%s: %s\n", k, v)
	}
}

func writeBody(b *strings.Builder, body []byte) {
	if len(body) == 0 {
		return
	}
	b.WriteString("\n")
	if len(body) <= MaxEvidenceBodyBytes {
		b.Write(body)
		return
	}
	b.Write(body[:MaxEvidenceBodyBytes])
	fmt.Fprintf(b, "\n... [truncated, %d bytes total]", len(body))
}
