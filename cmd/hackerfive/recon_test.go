package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/toolsync"
)

func TestNewReconCmd_MissingTarget_ReturnsError(t *testing.T) {
	cmd := newReconCmd(&rootFlags{})
	cmd.SetArgs([]string{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--targets is required")
}

func TestNewReconCmd_InvalidDepth_ReturnsError(t *testing.T) {
	cmd := newReconCmd(&rootFlags{})
	cmd.SetArgs([]string{"--targets", "http://example.com", "--recon-depth", "bogus"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--recon-depth must be")
}

func TestNewReconCmd_InvalidScopeFile_ReturnsError(t *testing.T) {
	cmd := newReconCmd(&rootFlags{})
	cmd.SetArgs([]string{"--targets", "http://example.com", "--scope", filepath.Join(t.TempDir(), "does-not-exist.txt")})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing --scope")
}

// TestNewReconCmd_NoScopeFile_ReturnsError confirms P2-2's hard-fail
// (docs/follow-up.md P2-6): unlike scan's --targets (already an exact,
// explicit list), recon can silently wander into whatever it discovers —
// this refuses outright unless a --scope file or --allow-no-scope is given,
// rather than the old warn-and-proceed default.
func TestNewReconCmd_NoScopeFile_ReturnsError(t *testing.T) {
	cmd := newReconCmd(&rootFlags{})
	cmd.SetArgs([]string{"--targets", "http://example.com"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope is required")
}

// TestNewReconCmd_AllowNoScope_WarnsAndRunsAgainstLocalServer drives the
// full happy path against a local httptest.Server target with the explicit
// opt-out flag, matching the pattern pkg/webui's own tests use to keep the
// suite free of real external network calls: --recon-depth passive skips
// the shelled active-probe binaries entirely, and the loopback target means
// pkg/recon's own WHOIS/ASN guard (isPrivateOrLoopbackHost) skips those too
// — the only real request made is Wave 0's security.txt probe, straight
// back to this same local server.
func TestNewReconCmd_AllowNoScope_WarnsAndRunsAgainstLocalServer(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cmd := newReconCmd(&rootFlags{})
	cmd.SetArgs([]string{"--targets", srv.URL, "--recon-depth", "passive", "--allow-no-scope"})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, errOut.String(), "--allow-no-scope set")

	var result recon.ReconResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result))
}

func TestNewReconCmd_OutputFlag_WritesToFile(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	outPath := filepath.Join(t.TempDir(), "recon.json")
	flags := &rootFlags{output: outPath}
	cmd := newReconCmd(flags)
	cmd.SetArgs([]string{"--targets", srv.URL, "--recon-depth", "passive", "--scope", writeScopeFile(t, srv.URL)})

	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var result recon.ReconResult
	require.NoError(t, json.Unmarshal(data, &result))
}

// isolateFromInstalledReconBinaries forces resolveBinaryPath's two lookup
// paths (PATH, then toolsync.DefaultInstallDir()) to both miss, regardless
// of whether this machine has actually run `hackerfive recon setup` —
// found live, 2026-09-03: this dev machine has the real subfinder/tlsx
// binaries installed at its real os.UserConfigDir(), so a naive happy-path
// test here silently shelled out to them for real, against a fake
// "127.0.0.1" domain, burning ~30s per run on real passive-DNS network
// queries with no results. Same bug class as the WHOIS/ASN loopback fix
// (docs/15-implementation-plan-ph6.md addendum item 7) — a test target that
// merely looks safe (a local httptest.Server) can still trigger a real
// network dependency two layers down. Without this, the test's speed and
// determinism depend on the host machine's own local state, not on this
// test's own inputs.
func isolateFromInstalledReconBinaries(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
}

// writeScopeFile writes a minimal --scope file allowing target's own host,
// reused by both recon_test.go and plan_test.go.
func writeScopeFile(t *testing.T, target string) string {
	t.Helper()
	u, err := url.Parse(target)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(path, []byte(u.Hostname()+"\n"), 0o644))
	return path
}

func TestPrintToolStatus_FormatsInstalledAndMissing(t *testing.T) {
	var buf bytes.Buffer
	err := printToolStatus(&buf, []toolsync.ToolStatus{
		{Name: "subfinder", Installed: true, Version: "2.6.0"},
		{Name: "naabu", Installed: false},
	}, "/tmp/tools")
	require.NoError(t, err)

	out := buf.String()
	assert.Contains(t, out, "subfinder")
	assert.Contains(t, out, "2.6.0")
	assert.Contains(t, out, "naabu")
	assert.Contains(t, out, "install directory: /tmp/tools")
}

func TestNewReconSetupCmd_CheckFlag_NoNetworkNoDownload(t *testing.T) {
	cmd := newReconSetupCmd()
	cmd.SetArgs([]string{"--check", "--dir", t.TempDir()})
	var out bytes.Buffer
	cmd.SetOut(&out)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "install directory:")
}

func TestNewReconCmd_FlagDefaults(t *testing.T) {
	cmd := newReconCmd(&rootFlags{})

	depth := cmd.Flags().Lookup("recon-depth")
	require.NotNil(t, depth)
	assert.Equal(t, "passive", depth.DefValue)

	rateLimit := cmd.Flags().Lookup("rate-limit")
	require.NotNil(t, rateLimit)

	// LT-4 (docs/follow-up.md): recon no longer exposes --insecure at all —
	// its own direct HTTP client always skips TLS verification now
	// (recon.ClientConfig), matching katana/httpx's own hardcoded posture.
	assert.Nil(t, cmd.Flags().Lookup("insecure"), "recon's --insecure flag should be gone, not just defaulted false")

	// LT-11 (docs/follow-up.md): --verbose wires the already-existing
	// recon.WithProgressCallback into stderr — off by default so scripted
	// invocations see no output change.
	verbose := cmd.Flags().Lookup("verbose")
	require.NotNil(t, verbose, "--verbose must be registered")
	assert.Equal(t, "false", verbose.DefValue)
}

// TestVerboseProgress_WritesWaveStatusToStderr locks in LT-11's fix directly:
// the callback verboseProgress returns must write exactly the wave/status
// pairs recon.WithProgressCallback fires, not silently drop them.
func TestVerboseProgress_WritesWaveStatusToStderr(t *testing.T) {
	var buf bytes.Buffer
	fn := verboseProgress(&buf)

	fn("wave0", "running")
	fn("wave0", "done")

	assert.Equal(t, "wave0: running\nwave0: done\n", buf.String())
}
