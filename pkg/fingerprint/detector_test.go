package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetect_HeaderMatch(t *testing.T) {
	matches := Detect(Signal{Headers: map[string]string{"Server": "openresty/1.27.1.2"}})
	assertHasMatch(t, matches, "OpenResty", SourceHeader)
}

func TestDetect_HeaderMatch_CaseInsensitiveNameAndValue(t *testing.T) {
	matches := Detect(Signal{Headers: map[string]string{"SERVER": "Apache/2.4.25 (Debian)"}})
	assertHasMatch(t, matches, "Apache HTTP Server", SourceHeader)
}

func TestDetect_BodyMatch(t *testing.T) {
	matches := Detect(Signal{Body: `<html><body>Powered by WordPress, see wp-content/themes</body></html>`})
	assertHasMatch(t, matches, "WordPress", SourceBody)
}

func TestDetect_FaviconMatch(t *testing.T) {
	// "-254193850" is crAPI's own real favicon mmh3 hash, confirmed live
	// against the running container (see signatures.go's comment) — not a
	// fabricated test value.
	matches := Detect(Signal{FaviconHash: "-254193850"})
	assertHasMatch(t, matches, "crAPI", SourceFavicon)
}

func TestDetect_PortMatch(t *testing.T) {
	matches := Detect(Signal{Ports: []int{22, 3306, 8080}})
	assertHasMatch(t, matches, "MySQL", SourcePort)
}

func TestDetect_NoMatch(t *testing.T) {
	matches := Detect(Signal{Headers: map[string]string{"server": "totally-unknown-server/1.0"}, Body: "nothing interesting here", Ports: []int{9999}})
	assert.Empty(t, matches)
}

func TestDetect_CombinedSignals_MultipleIndependentMatches(t *testing.T) {
	matches := Detect(Signal{
		Headers: map[string]string{"server": "nginx/1.25", "x-powered-by": "PHP/8.1"},
		Body:    "<?php phpinfo(); ?>",
		Ports:   []int{3306},
	})
	assertHasMatch(t, matches, "Nginx", SourceHeader)
	assertHasMatch(t, matches, "PHP", SourceHeader)
	assertHasMatch(t, matches, "PHP", SourceBody)
	assertHasMatch(t, matches, "MySQL", SourcePort)
}

// TestDetect_CloudProviderHeaders guards Phase 8 Step 3 / P1-5
// (docs/follow-up.md): each cloud-provider signature must fire on its own
// header, and a header-presence-only signature (empty HeaderContains) must
// match regardless of the header's actual value.
func TestDetect_CloudProviderHeaders(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		product string
	}{
		{"API Gateway / Lambda", map[string]string{"x-amzn-requestid": "abc-123"}, "aws"},
		{"ALB / API Gateway trace", map[string]string{"x-amzn-trace-id": "Root=1-abc"}, "aws"},
		{"CloudFront edge", map[string]string{"x-amz-cf-id": "xyz"}, "aws"},
		{"Elastic Load Balancer", map[string]string{"server": "awselb/2.0"}, "aws"},
		{"S3 bucket region header", map[string]string{"x-amz-bucket-region": "us-east-1"}, "s3"},
		{"S3 static website Server", map[string]string{"server": "AmazonS3"}, "s3"},
		{"GCS object generation", map[string]string{"x-goog-generation": "12345"}, "gcp"},
		{"GCS uploader header", map[string]string{"x-guploader-uploadid": "abc"}, "gcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches := Detect(Signal{Headers: tc.headers})
			assertHasMatch(t, matches, tc.product, SourceHeader)
		})
	}
}

func TestDetect_CloudProviderHeaders_NoFalsePositiveOnUnrelatedHeaders(t *testing.T) {
	matches := Detect(Signal{Headers: map[string]string{"server": "nginx/1.25", "content-type": "text/html"}})
	for _, m := range matches {
		assert.NotContains(t, []string{"aws", "s3", "gcp"}, m.Product, "an unrelated header set must not fire a cloud-provider signature")
	}
}

func assertHasMatch(t *testing.T, matches []Match, product, source string) {
	t.Helper()
	for _, m := range matches {
		if m.Product == product && m.Source == source {
			return
		}
	}
	t.Errorf("expected a Match{Product: %q, Source: %q} in %+v", product, source, matches)
}

// TestDetect_CMSProducts guards LT-129: each self-hosted product's marker,
// taken from a live instance's real response, must fire its own product, and
// VersionRegex must capture a version only where the response discloses one.
func TestDetect_CMSProducts(t *testing.T) {
	cases := []struct {
		name        string
		sig         Signal
		product     string
		source      string
		wantVersion string
	}{
		{"Webmin Server header with version", Signal{Headers: map[string]string{"server": "MiniServ/2.111"}}, "Webmin", SourceHeader, "2.111"},
		{"Webmin three-segment version", Signal{Headers: map[string]string{"Server": "miniserv/1.994.1"}}, "Webmin", SourceHeader, "1.994.1"},
		// cloud02.nettix.com.pe:10000, live: MiniServ hides its version pre-login.
		{"Webmin bare Server header", Signal{Headers: map[string]string{"server": "MiniServ"}}, "Webmin", SourceHeader, ""},
		{"Webmin open port", Signal{Ports: []int{22, 10000}}, "Webmin", SourcePort, ""},
		{"Dolibarr session cookie", Signal{Headers: map[string]string{"set-cookie": "DOLSESSID_ab729a9b=c734771b; path=/; secure; HttpOnly"}}, "Dolibarr", SourceHeader, ""},
		{"Dolibarr author meta with asset version", Signal{Body: `<meta name="author" content="Dolibarr Development Team"><link href="/theme/eldy/style.css.php?lang=en&amp;version=23.0.3">`}, "Dolibarr", SourceBody, "23.0.3"},
		{"Dolibarr author meta, version unparseable", Signal{Body: `<meta name="author" content="Dolibarr Development Team">`}, "Dolibarr", SourceBody, ""},
		{"Nextcloud session passphrase cookie", Signal{Headers: map[string]string{"set-cookie": "oc_sessionPassphrase=v9rS%2F; path=/; secure"}}, "Nextcloud", SourceHeader, ""},
		{"Nextcloud __Host-nc cookie", Signal{Headers: map[string]string{"set-cookie": "__Host-nc_sameSiteCookielax=true; path=/"}}, "Nextcloud", SourceHeader, ""},
		{"DokuWiki session cookie", Signal{Headers: map[string]string{"set-cookie": "DokuWiki=fu9kbar92ingvr9kri13oubv1n; path=/; secure"}}, "DokuWiki", SourceHeader, ""},
		{"DokuWiki generator meta", Signal{Body: `<meta name="generator" content="DokuWiki"/>`}, "DokuWiki", SourceBody, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *Match
			for _, m := range Detect(tc.sig) {
				if m.Product == tc.product && m.Source == tc.source {
					m := m
					got = &m
					break
				}
			}
			if got == nil {
				t.Fatalf("expected a Match{Product: %q, Source: %q}, got %+v", tc.product, tc.source, Detect(tc.sig))
			}
			assert.Equal(t, tc.wantVersion, got.Version)
		})
	}
}

func TestDetect_CMSProducts_NoFalsePositives(t *testing.T) {
	cms := []string{"Webmin", "Dolibarr", "Nextcloud", "DokuWiki"}
	unrelated := []Signal{
		{Headers: map[string]string{"server": "nginx", "set-cookie": "PHPSESSID=abc; path=/", "x-powered-by": "PHP/8.2"}},
		// An unrelated open port must not read as Webmin, and Webmin's own
		// port must not read as anything else.
		{Ports: []int{80, 443, 3306, 20000}},
		// WordPress body that merely mentions a wiki / a cloud.
		{Body: `<html><head><title>My cloud and wiki notes</title></head><body>see wp-content</body></html>`},
	}
	for _, sig := range unrelated {
		for _, m := range Detect(sig) {
			assert.NotContains(t, cms, m.Product, "unrelated signal %+v must not fire %s", sig, m.Product)
		}
	}
}

func TestSignatures_VersionRegexesCompile(t *testing.T) {
	for _, s := range signatures {
		if s.VersionRegex == "" {
			continue
		}
		re, ok := versionRegexes[s.VersionRegex]
		if !ok || re.NumSubexp() < 1 {
			t.Errorf("signature %q: VersionRegex %q must compile and have a capture group", s.Product, s.VersionRegex)
		}
		if s.HeaderName == "" && s.BodyContains == "" {
			t.Errorf("signature %q: VersionRegex only applies to header/body signatures", s.Product)
		}
	}
}
