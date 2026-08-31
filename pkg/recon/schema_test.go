package recon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

func compileReconSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "docs", "schema", "recon-result.schema.json"))
	require.NoError(t, err)
	schema, err := jsonschema.Compile(schemaPath)
	require.NoError(t, err)
	return schema
}

// TestReconResult_SchemaRoundTrip exercises every wave (via a mocked runFunc
// covering all six binaries, and a real httptest server for Wave 0/3's own
// direct HTTP calls) so the ReconResult validated here carries a real host,
// endpoint, tech-stack entry, out-of-scope entry, and warning — not an
// empty/degenerate struct — then proves the frozen schema round-trips it
// without loss.
func TestReconResult_SchemaRoundTrip(t *testing.T) {
	schema := compileReconSchema(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>login form</html>"))
	}))
	defer srv.Close()
	target := srv.URL
	targetHost := hostOnly(target)

	// httpx/naabu/katana are pointed at the real local httptest server
	// (target/targetHost) so Wave 3's own direct HTTP calls
	// (probeCommonPaths/tagAuthBoundary) stay hermetic — subfinder/tlsx's
	// extra synthetic hosts are never dialed for real, they only need to
	// round-trip through the schema.
	responses := map[string]string{
		"subfinder": `{"host":"sibling.example.com"}` + "\n" + `{"host":"evil.other.net"}`,
		"tlsx":      `{"subject_an":["san.example.com"]}`,
		"dnsx":      `{"host":"` + targetHost + `"}`,
		"naabu":     `{"ip":"` + targetHost + `","port":80,"protocol":"tcp"}`,
		"httpx":     `{"url":"` + target + `","host":"` + targetHost + `","host_ip":"` + targetHost + `","status_code":200,"tech":["Nginx"]}`,
		"katana":    `{"request":{"endpoint":"` + target + `/app.js","method":"GET"}}`,
	}
	_, fake := recordingRun(t, responses)

	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	scopeContent := targetHost + "\n" // sibling.example.com/evil.other.net/san.example.com deliberately excluded
	require.NoError(t, os.WriteFile(scopeFile, []byte(scopeContent), 0o644))
	s, err := scope.Parse(scopeFile)
	require.NoError(t, err)

	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), target, DepthFull)
	require.NoError(t, err)

	// Sanity: this is exercising real content, not a degenerate empty struct.
	require.NotEmpty(t, result.Hosts)
	require.NotEmpty(t, result.Endpoints)
	require.NotEmpty(t, result.TechStack)
	require.Contains(t, result.OutOfScope, "evil.other.net")

	raw, err := json.Marshal(result)
	require.NoError(t, err)

	var asAny any
	require.NoError(t, json.Unmarshal(raw, &asAny))
	assert.NoError(t, schema.Validate(asAny), "ReconResult must satisfy docs/schema/recon-result.schema.json: %s", raw)

	var roundTripped ReconResult
	require.NoError(t, json.Unmarshal(raw, &roundTripped))
	rawAgain, err := json.Marshal(roundTripped)
	require.NoError(t, err)
	assert.JSONEq(t, string(raw), string(rawAgain), "ReconResult must round-trip through the frozen schema without loss")
}
