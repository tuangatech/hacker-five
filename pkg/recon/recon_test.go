package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

func newTestClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{Timeout: 2 * time.Second, MaxRedirects: 5, MaxIdleConnsPerHost: 10})
}

// recordingRun returns a runFunc that records every binary name it was
// asked to run (with its stdin, for assertions on what hosts a wave was
// actually given) and, for names in responses, returns the corresponding
// canned JSONL output.
type invocation struct {
	name  string
	stdin string
}

func recordingRun(t *testing.T, responses map[string]string) (*[]invocation, runFunc) {
	t.Helper()
	var calls []invocation
	fn := func(_ context.Context, stdin string, name string, _ ...string) ([]byte, error) {
		calls = append(calls, invocation{name: name, stdin: stdin})
		if out, ok := responses[name]; ok {
			return []byte(out), nil
		}
		return nil, nil
	}
	return &calls, fn
}

func namesOf(calls []invocation) []string {
	var out []string
	for _, c := range calls {
		out = append(out, c.name)
	}
	return out
}

func TestRun_PassiveDepth_NeverInvokesActiveBinaries(t *testing.T) {
	calls, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), srv.URL, DepthPassive)
	require.NoError(t, err)
	require.NotNil(t, result)

	invoked := namesOf(*calls)
	assert.Contains(t, invoked, "subfinder")
	assert.Contains(t, invoked, "tlsx")
	assert.NotContains(t, invoked, "dnsx")
	assert.NotContains(t, invoked, "naabu")
	assert.NotContains(t, invoked, "httpx")
	assert.NotContains(t, invoked, "katana")
}

func TestDefaultScheme(t *testing.T) {
	assert.Equal(t, "https://www.example.com", defaultScheme("www.example.com"))
	assert.Equal(t, "https://example.com", defaultScheme("example.com"))
	assert.Equal(t, "http://example.com", defaultScheme("http://example.com"), "an explicit scheme is never overridden")
	assert.Equal(t, "https://example.com:8443", defaultScheme("https://example.com:8443"), "already-schemed input passes through unchanged")
}

// TestRun_BareDomainTarget_DoesNotErrorOut confirms a schemeless target
// (found live: an operator typing "www.example.com" into the Web UI's
// /recon form got "not a valid target URL" instead of the obviously-
// intended https:// target) no longer rejects upfront. srv is plain HTTP,
// so Wave 0's own direct call against the now-https-defaulted bare host
// fails silently (runWave0's own designed tolerance for any error, see
// passive.go) — this test isn't about Wave 0 succeeding, only that Run
// itself accepts the target and proceeds to invoke the passive binaries.
func TestRun_BareDomainTarget_DoesNotErrorOut(t *testing.T) {
	calls, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	bareTarget := strings.TrimPrefix(srv.URL, "http://") // e.g. "127.0.0.1:54321", no scheme

	r := New(newTestClient(), withRun(fake))
	result, err := r.Run(context.Background(), bareTarget, DepthPassive)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "https://"+bareTarget, result.Target)

	invoked := namesOf(*calls)
	assert.Contains(t, invoked, "subfinder")
	assert.Contains(t, invoked, "tlsx")
}

func TestRun_ActiveDepth_NeverInvokesCrawlBinary(t *testing.T) {
	calls, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()

	r := New(newTestClient(), withRun(fake))
	_, err := r.Run(context.Background(), srv.URL, DepthActive)
	require.NoError(t, err)

	invoked := namesOf(*calls)
	assert.Contains(t, invoked, "dnsx")
	assert.Contains(t, invoked, "naabu")
	assert.Contains(t, invoked, "httpx")
	assert.NotContains(t, invoked, "katana")
}

func TestRun_OutOfScopeHost_GetsZeroActiveProbes(t *testing.T) {
	const evilHost = "evil.other.net"
	responses := map[string]string{
		"subfinder": `{"host":"` + evilHost + `"}`,
	}
	calls, fake := recordingRun(t, responses)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()
	target := srv.URL // host is httptest's own 127.0.0.1:PORT

	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	parsedTarget, err := url.Parse(target)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(scopeFile, []byte(parsedTarget.Hostname()+"\n"), 0o644))
	s, err := scope.Parse(scopeFile)
	require.NoError(t, err)

	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), target, DepthActive)
	require.NoError(t, err)

	assert.Contains(t, result.OutOfScope, evilHost)
	for _, c := range *calls {
		if c.name == "dnsx" || c.name == "naabu" || c.name == "httpx" {
			assert.NotContains(t, c.stdin, evilHost, "%s must never be given the out-of-scope host", c.name)
		}
	}
}

func TestRun_MissingBinaries_DegradesToWarningsNotFailure(t *testing.T) {
	fn := func(_ context.Context, _ string, name string, _ ...string) ([]byte, error) {
		return nil, &errBinaryMissing{name: name}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer srv.Close()

	r := New(newTestClient(), withRun(fn))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err, "a missing binary must never be a hard Run failure")
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Warnings)

	joined := strings.Join(result.Warnings, " | ")
	for _, bin := range []string{"subfinder", "tlsx", "dnsx", "naabu", "httpx", "katana"} {
		assert.Contains(t, joined, bin, "expected a warning mentioning %s", bin)
	}
}

// TestRun_ExplicitTargetOutOfScope_SkipsEntirely mirrors scan's own
// convention (pkg/scanner/engine.go's loadScope: an explicitly-given target
// not covered by --scope is skipped, not scanned). This guards a real bug
// this package had during development: adding the target's own host:port to
// Wave 2's httpx input unconditionally (to preserve a non-default port
// subfinder/tlsx can't discover) bypassed the scope filter entirely for the
// one host a user is most likely to have gotten wrong.
func TestRun_ExplicitTargetOutOfScope_SkipsEntirely(t *testing.T) {
	calls, fake := recordingRun(t, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("target must never be contacted once its own host fails --scope, got request for %s", r.URL)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(scopeFile, []byte("some-other-host.example.com\n"), 0o644))
	s, err := scope.Parse(scopeFile)
	require.NoError(t, err)

	r := New(newTestClient(), withRun(fake), WithScope(s))
	result, err := r.Run(context.Background(), srv.URL, DepthFull)
	require.NoError(t, err)

	assert.Empty(t, *calls, "no recon binary should ever run once the target itself fails --scope")
	assert.Contains(t, result.OutOfScope, hostOnly(srv.URL))
	assert.Empty(t, result.Hosts)
	assert.Empty(t, result.Endpoints)
}
