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
)

// TestDiscoverContentPaths_SkipsUniformWallHost guards the D6 suppression in
// discoverContentPaths: a host probeCommonPaths already classified as a
// uniform wall (every path, including the canary, answers 403) must not get
// any wave3-content-discovery endpoints — a wordlist "hit" there is the wall
// itself, not a real discovered path.
func TestDiscoverContentPaths_SkipsUniformWallHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // every path, including the canary
	}))
	defer srv.Close()

	httpxPathOut := `{"url":"` + srv.URL + `/admin","status_code":200,"content_length":512,"content_type":"text/html"}`
	fake := func(_ context.Context, _ string, name string, a ...string) ([]byte, error) {
		if name != "httpx" {
			return nil, nil
		}
		for _, arg := range a {
			if arg == "-path" {
				return []byte(httpxPathOut), nil
			}
		}
		return nil, nil
	}

	r := New(newTestClient(), withRun(fake), WithContentDiscovery(true))
	res, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	require.NotEmpty(t, res.UniformResponses, "the WAF-block verdict must actually be recorded for this test to prove anything")
	assert.Equal(t, "waf-block", res.UniformResponses[0].Kind)
	for _, ep := range res.Endpoints {
		assert.NotEqual(t, "wave3-content-discovery", ep.Source,
			"a wordlist hit on a host already classified as a uniform wall must be suppressed as noise")
	}
}

// TestContentDiscoveryWordlistFile_EmbeddedDefault confirms the embedded
// SecLists common.txt is written out intact when no --content-discovery-
// wordlist override is given, and is cleaned up afterward.
func TestContentDiscoveryWordlistFile_EmbeddedDefault(t *testing.T) {
	r := New(newTestClient())
	path, cleanup, provenance, err := r.contentDiscoveryWordlistFile()
	require.NoError(t, err)
	require.NotEmpty(t, path)
	assert.Contains(t, provenance, "built-in")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, embeddedContentDiscoveryWordlist, string(data), "the temp file must be a byte-for-byte copy of the embedded wordlist")
	assert.Contains(t, string(data), "admin", "the real SecLists common.txt must be embedded, not a placeholder")

	cleanup()
	_, statErr := os.Stat(path)
	assert.True(t, os.IsNotExist(statErr), "cleanup must remove the temp file")
}

// TestContentDiscoveryWordlistFile_Override confirms an explicit
// --content-discovery-wordlist path is used verbatim (no temp file, no
// cleanup needed) and a missing override file surfaces as an error rather
// than silently falling back to the embedded default.
func TestContentDiscoveryWordlistFile_Override(t *testing.T) {
	wl := filepath.Join(t.TempDir(), "mywords.txt")
	require.NoError(t, os.WriteFile(wl, []byte("admin\nbackup\n"), 0o644))

	r := New(newTestClient(), WithContentDiscoveryWordlist(wl))
	path, cleanup, provenance, err := r.contentDiscoveryWordlistFile()
	require.NoError(t, err)
	assert.Equal(t, wl, path)
	assert.Contains(t, provenance, "mywords.txt")
	cleanup() // must be a safe no-op — the operator's own file must survive

	_, statErr := os.Stat(wl)
	assert.NoError(t, statErr, "the operator's own wordlist file must never be deleted")
}

func TestContentDiscoveryWordlistFile_MissingOverride_Errors(t *testing.T) {
	r := New(newTestClient(), WithContentDiscoveryWordlist(filepath.Join(t.TempDir(), "does-not-exist.txt")))
	_, _, _, err := r.contentDiscoveryWordlistFile()
	require.Error(t, err)
}
