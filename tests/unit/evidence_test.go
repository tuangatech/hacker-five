package unit

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

func TestFormatRequest_RedactsSensitiveHeaders(t *testing.T) {
	headers := http.Header{
		"Authorization": {"Bearer super-secret-token"},
		"Cookie":        {"session=abc123"},
		"X-Api-Key":     {"key-123"},
		"Accept":        {"application/json"},
	}
	out := detectors.FormatRequest(http.MethodGet, "http://example.com/api/users/2", headers, nil)

	assert.NotContains(t, out, "super-secret-token", "bearer token must never appear in Evidence — findings.json is routinely shared as report proof")
	assert.NotContains(t, out, "abc123")
	assert.NotContains(t, out, "key-123")
	assert.Contains(t, out, "Authorization: [REDACTED]")
	assert.Contains(t, out, "Cookie: [REDACTED]")
	assert.Contains(t, out, "X-Api-Key: [REDACTED]")
	assert.Contains(t, out, "Accept: application/json", "non-sensitive headers must still appear in full")
	assert.Contains(t, out, "GET http://example.com/api/users/2")
}

func TestFormatResponse_RedactsSetCookie(t *testing.T) {
	headers := http.Header{"Set-Cookie": {"session=xyz; HttpOnly"}, "Content-Type": {"application/json"}}
	out := detectors.FormatResponse(http.StatusOK, headers, []byte(`{"id":2}`))

	assert.NotContains(t, out, "xyz")
	assert.Contains(t, out, "Set-Cookie: [REDACTED]")
	assert.Contains(t, out, "HTTP 200")
	assert.Contains(t, out, `{"id":2}`, "response body is the proof itself and must not be redacted")
}

func TestFormatResponse_TruncatesLargeBody(t *testing.T) {
	body := []byte(strings.Repeat("a", detectors.MaxEvidenceBodyBytes+500))
	out := detectors.FormatResponse(http.StatusOK, http.Header{}, body)

	assert.Contains(t, out, "truncated, ")
	assert.Less(t, len(out), len(body), "truncated output must be meaningfully smaller than the original body")
}

func TestFormatRequest_HeaderOrderIsDeterministic(t *testing.T) {
	headers := http.Header{"Zebra": {"1"}, "Alpha": {"2"}, "Mike": {"3"}}
	out1 := detectors.FormatRequest(http.MethodGet, "http://example.com", headers, nil)
	out2 := detectors.FormatRequest(http.MethodGet, "http://example.com", headers, nil)

	assert.Equal(t, out1, out2)
	assert.Less(t, strings.Index(out1, "Alpha"), strings.Index(out1, "Mike"), "headers must be sorted, not map-iteration order")
	assert.Less(t, strings.Index(out1, "Mike"), strings.Index(out1, "Zebra"))
}

func TestFormatRequest_EmptyBodyOmitsBlankSection(t *testing.T) {
	out := detectors.FormatRequest(http.MethodGet, "http://example.com", http.Header{}, nil)
	assert.False(t, strings.HasSuffix(out, "\n\n"), "no body means no trailing blank body section")
}
