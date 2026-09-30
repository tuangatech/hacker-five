package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// TestRun_CMSFingerprint_VersionedAndPortFacts is LT-129's recon half: a host
// httpx returns with Dolibarr's cookie + author <meta> + asset version yields
// ONE merged, versioned "Dolibarr:23.0.3" TechFact (header and body signatures
// agreeing collapse via addTech, the unversioned header fact upgrading to the
// versioned body one), and an open :10000 from naabu yields a weak, port-only
// "Webmin" fact — the signal that dispatches checkWebmin for a host httpx never
// probed on that port.
func TestRun_CMSFingerprint_VersionedAndPortFacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()
	target := srv.URL
	targetHost := hostOnly(target)

	body := `<meta name=\"author\" content=\"Dolibarr Development Team\"><link href=\"/theme/eldy/style.css.php?lang=en&amp;version=23.0.3\">`
	responses := map[string]string{
		"dnsx":  `{"host":"` + targetHost + `"}`,
		"naabu": `{"ip":"` + targetHost + `","port":10000,"protocol":"tcp"}`,
		"httpx": `{"url":"` + target + `","host":"` + targetHost + `","host_ip":"` + targetHost + `","status_code":200,` +
			`"header":{"set-cookie":"DOLSESSID_ab729a9b=c734771b; path=/; secure; HttpOnly"},"body":"` + body + `"}`,
	}
	_, fake := recordingRun(t, responses)

	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(scopeFile, []byte(targetHost+"\n"), 0o644))
	s, err := scope.Parse(scopeFile)
	require.NoError(t, err)

	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), target, DepthActive)
	require.NoError(t, err)

	byProduct := map[string]TechFact{}
	for _, tf := range result.TechStack {
		byProduct[techProductKey(tf.Name)] = tf
	}
	doli, ok := byProduct["dolibarr"]
	require.True(t, ok, "expected a Dolibarr TechFact, got %+v", result.TechStack)
	assert.Equal(t, "Dolibarr:23.0.3", doli.Name, "the body signature's captured version must upgrade the header-only fact")
	assert.Equal(t, ConfidenceHigh, doli.Confidence)
	assert.Contains(t, doli.Source, "fingerprint-header")
	assert.Contains(t, doli.Source, "fingerprint-body")

	webmin, ok := byProduct["webmin"]
	require.True(t, ok, "expected a port-only Webmin TechFact, got %+v", result.TechStack)
	assert.Equal(t, "Webmin", webmin.Name)
	assert.Equal(t, ConfidenceLow, webmin.Confidence, "an open :10000 alone is weak evidence")
	assert.Equal(t, "fingerprint-port", webmin.Source)
}
