package misconfig

import "testing"

// TestHttpDowngrade locks in LT-156's fallback rule: an https target gets a
// plain-http variant to retry checkHostHeaderRedirect against (real
// deployments often front a correctly SNI/Host-matched HTTPS vhost with a
// more permissive plain-HTTP default vhost — found live against
// www.yosmart.com, 2026-09-13); anything already http gets no variant, since
// probeHostHeaderRedirect already tried it as the primary scheme.
func TestHttpDowngrade(t *testing.T) {
	cases := []struct {
		name   string
		target string
		want   string
	}{
		{"https downgrades to http", "https://example.com", "http://example.com"},
		{"https with path and port preserved", "https://example.com:8443/base", "http://example.com:8443/base"},
		{"already http gets no variant", "http://example.com", ""},
		{"malformed URL gets no variant", "://not a url", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := httpDowngrade(tc.target)
			if got != tc.want {
				t.Fatalf("httpDowngrade(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}
