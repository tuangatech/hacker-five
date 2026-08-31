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

func assertHasMatch(t *testing.T, matches []Match, product, source string) {
	t.Helper()
	for _, m := range matches {
		if m.Product == product && m.Source == source {
			return
		}
	}
	t.Errorf("expected a Match{Product: %q, Source: %q} in %+v", product, source, matches)
}
