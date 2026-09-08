package recon

import "strings"

// normalizeHostname lowercases and trims raw, strips a trailing FQDN dot and
// a leading "*." wildcard label, and reports whether what remains is a
// syntactically valid DNS hostname. It exists because passive enumeration
// sources are not always well-behaved: subfinder has been observed emitting
// an FTP multiline-greeting continuation line verbatim as a host
// ("220-sinchi01.nettix.com.pe"), and one such value fed to `httpx -l`
// silently voids the entire batch (exit 0, zero output). Callers drop
// anything this rejects and log the count (docs/follow-up.md LT-112).
func normalizeHostname(raw string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimPrefix(h, "*.")
	if h == "" || len(h) > 253 {
		return "", false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", false // a bare label is never a scan target here
	}
	for _, label := range labels {
		if !validLabel(label) {
			return "", false
		}
	}
	if !validTLD(labels[len(labels)-1]) {
		return "", false
	}
	if looksLikeProtocolBanner(labels[0]) {
		return "", false
	}
	return h, true
}

// looksLikeProtocolBanner reports whether label begins with an FTP/SMTP
// multiline-reply prefix — three digits then a hyphen, e.g. the "220-" in
// "220-sinchi01.nettix.com.pe". That is valid LDH per the charset rules but
// is never a real leftmost DNS label; it is a banner line a passive source
// scraped and mistook for a host (docs/follow-up.md LT-112).
func looksLikeProtocolBanner(label string) bool {
	if len(label) < 4 || label[3] != '-' {
		return false
	}
	return label[0] >= '0' && label[0] <= '9' &&
		label[1] >= '0' && label[1] <= '9' &&
		label[2] >= '0' && label[2] <= '9'
}

// validLabel reports whether s is a valid DNS label: 1–63 chars of
// [a-z0-9-], not beginning or ending with a hyphen.
func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			continue
		}
		return false
	}
	return true
}

// validTLD reports whether s is a plausible top-level label: at least two
// characters, all letters. This rejects an all-numeric final label (an IP
// literal reaches recon through a different path) and the digit-laden
// fragments a malformed source line tends to end on.
func validTLD(s string) bool {
	if len(s) < 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 'a' || s[i] > 'z' {
			return false
		}
	}
	return true
}
