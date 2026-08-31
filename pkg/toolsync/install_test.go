package toolsync

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSTokenFor(t *testing.T) {
	cases := []struct {
		goos    string
		want    string
		wantErr bool
	}{
		{goos: "darwin", want: "macOS"},
		{goos: "linux", want: "linux"},
		{goos: "windows", want: "windows"},
		{goos: "plan9", wantErr: true},
	}
	for _, c := range cases {
		got, err := osTokenFor(c.goos)
		if c.wantErr {
			assert.Error(t, err, c.goos)
			continue
		}
		require.NoError(t, err, c.goos)
		assert.Equal(t, c.want, got, c.goos)
	}
}

// The exact real asset names captured live against each tool's own
// releases/latest response (see the plan's Context section) — used here
// as fixtures rather than invented names, so this test fails if the real
// naming convention this package depends on ever changes.
func TestFindAsset(t *testing.T) {
	assets := []githubAsset{
		{Name: "httpx_1.11.0_linux_amd64.zip"},
		{Name: "httpx_1.11.0_macOS_arm64.zip"},
		{Name: "httpx_1.11.0_checksums.txt"},
	}
	got, ok := findAsset(assets, "httpx_1.11.0_macOS_arm64.zip")
	require.True(t, ok)
	assert.Equal(t, "httpx_1.11.0_macOS_arm64.zip", got.Name)

	_, ok = findAsset(assets, "httpx_1.11.0_freebsd_amd64.zip")
	assert.False(t, ok)
}

func TestFindChecksumsAsset(t *testing.T) {
	cases := []struct {
		name   string
		assets []githubAsset
	}{
		{name: "versioned underscore (httpx)", assets: []githubAsset{{Name: "httpx_1.11.0_linux_amd64.zip"}, {Name: "httpx_1.11.0_checksums.txt"}}},
		{name: "unversioned dash (naabu)", assets: []githubAsset{{Name: "naabu_2.6.1_linux_amd64.zip"}, {Name: "naabu-checksums.txt"}}},
		{name: "versioned dash (katana)", assets: []githubAsset{{Name: "katana_1.7.0_linux_amd64.zip"}, {Name: "katana-1.7.0-checksums.txt"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asset, ok := findChecksumsAsset(c.assets)
			require.True(t, ok)
			assert.Contains(t, asset.Name, "checksums")
		})
	}

	_, ok := findChecksumsAsset([]githubAsset{{Name: "httpx_1.11.0_linux_amd64.zip"}})
	assert.False(t, ok)
}

func TestVerifyChecksum(t *testing.T) {
	data := []byte("fake zip contents")
	sum := sha256.Sum256(data)
	hexSum := hex.EncodeToString(sum[:])

	// Real sha256sum-style format: hex, two spaces, filename — same shape
	// confirmed by downloading a real checksums.txt live.
	checksums := hexSum + "  httpx_1.11.0_linux_amd64.zip\n" +
		"deadbeef  other_1.0.0_linux_amd64.zip\n"

	assert.NoError(t, verifyChecksum(data, checksums, "httpx_1.11.0_linux_amd64.zip"))
	assert.Error(t, verifyChecksum(data, checksums, "other_1.0.0_linux_amd64.zip"), "wrong hash for a different file must not verify")
	assert.Error(t, verifyChecksum(data, checksums, "not_listed.zip"), "an asset with no checksums-file entry must not silently pass")
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func TestExtractBinary(t *testing.T) {
	binName := binaryFilename("httpx")

	t.Run("exact name match", func(t *testing.T) {
		data := makeZip(t, map[string][]byte{
			binName:      []byte("binary-bytes"),
			"LICENSE.md": []byte("license text"),
			"README.md":  []byte("readme text"),
		})
		got, err := extractBinary(data, "httpx")
		require.NoError(t, err)
		assert.Equal(t, []byte("binary-bytes"), got)
	})

	t.Run("falls back to the only non-license/readme entry", func(t *testing.T) {
		data := makeZip(t, map[string][]byte{
			"httpx-cli":  []byte("binary-bytes-2"), // naming drifted, doesn't match binName exactly
			"LICENSE.md": []byte("license text"),
		})
		got, err := extractBinary(data, "httpx")
		require.NoError(t, err)
		assert.Equal(t, []byte("binary-bytes-2"), got)
	})

	t.Run("no candidate found", func(t *testing.T) {
		data := makeZip(t, map[string][]byte{"LICENSE.md": []byte("license text")})
		_, err := extractBinary(data, "httpx")
		assert.Error(t, err)
	})
}

// fakeReleaseServer serves a minimal, generic GitHub-releases-API-shaped
// server: releases/latest for any repo returns one zip asset (containing a
// stub executable) plus a checksums asset in whichever naming style style
// dictates, both downloadable from the same server — enough for a real,
// end-to-end Install() run without touching the real network.
func fakeReleaseServer(t *testing.T, version string, checksumsStyle func(tool string) string, failTool string) *httptest.Server {
	t.Helper()
	osTok, err := osTokenFor(runtime.GOOS)
	require.NoError(t, err)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		// Path shape: /repos/{owner}/{repo}/releases/latest
		parts := splitPath(r.URL.Path)
		require.GreaterOrEqual(t, len(parts), 2)
		tool := parts[1]

		if tool == failTool {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		zipName := fmt.Sprintf("%s_%s_%s_%s.zip", tool, version, osTok, runtime.GOARCH)
		checksumsName := checksumsStyle(tool)

		rel := githubRelease{
			TagName: "v" + version,
			Assets: []githubAsset{
				{Name: zipName, BrowserDownloadURL: srv.URL + "/dl/" + tool + "/" + zipName},
				{Name: checksumsName, BrowserDownloadURL: srv.URL + "/dl/" + tool + "/" + checksumsName},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(rel))
	})

	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		parts := splitPath(r.URL.Path)
		require.GreaterOrEqual(t, len(parts), 2)
		tool, filename := parts[0], parts[1]

		zipName := fmt.Sprintf("%s_%s_%s_%s.zip", tool, version, osTok, runtime.GOARCH)
		zipData := makeZip(t, map[string][]byte{binaryFilename(tool): []byte("#!/bin/sh\nexit 0\n")})

		if filename == zipName {
			_, _ = w.Write(zipData)
			return
		}
		// anything else under /dl/{tool}/ is the checksums file
		sum := sha256.Sum256(zipData)
		_, _ = fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), zipName)
	})

	return srv
}

// splitPath trims leading "/repos/"/"/dl/" and returns the remaining
// segments — small local helper, not worth pulling in a routing library
// for a test-only fake server.
func splitPath(p string) []string {
	trimmed := p
	for _, prefix := range []string{"/repos/", "/dl/"} {
		if len(trimmed) >= len(prefix) && trimmed[:len(prefix)] == prefix {
			trimmed = trimmed[len(prefix):]
			break
		}
	}
	var parts []string
	cur := ""
	for _, c := range trimmed {
		if c == '/' {
			if cur != "" {
				parts = append(parts, cur)
			}
			cur = ""
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}

func TestInstall_AllToolsSucceed(t *testing.T) {
	srv := fakeReleaseServer(t, "1.0.0", func(tool string) string {
		return tool + "-checksums.txt" // exercise the naabu-style naming for every tool
	}, "")
	origBase := githubAPIBase
	githubAPIBase = srv.URL
	t.Cleanup(func() { githubAPIBase = origBase })

	dir := t.TempDir()
	var messages []string
	result := Install(context.Background(), dir, func(tool, msg string) {
		messages = append(messages, tool+": "+msg)
	})

	require.Len(t, result.Tools, len(Tools))
	for _, tr := range result.Tools {
		assert.True(t, tr.OK, "%s: %s", tr.Name, tr.Err)
		assert.Equal(t, "1.0.0", tr.Version)

		path := filepath.Join(dir, binaryFilename(tr.Name))
		info, err := os.Stat(path)
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
		}
	}

	manifest := readManifest(dir)
	require.NotNil(t, manifest)
	for _, tool := range Tools {
		assert.Equal(t, "1.0.0", manifest[tool.Name].Version)
	}

	joined := ""
	for _, m := range messages {
		joined += m + "\n"
	}
	assert.Contains(t, joined, "checking latest release")
	assert.Contains(t, joined, "installed v1.0.0")
}

func TestInstall_OneToolFails_OthersStillSucceed(t *testing.T) {
	srv := fakeReleaseServer(t, "1.0.0", func(tool string) string {
		return tool + "-checksums.txt"
	}, "naabu")

	origBase := githubAPIBase
	githubAPIBase = srv.URL
	t.Cleanup(func() { githubAPIBase = origBase })

	dir := t.TempDir()
	result := Install(context.Background(), dir, nil)

	require.Len(t, result.Tools, len(Tools))
	var naabuResult *ToolResult
	okCount := 0
	for i := range result.Tools {
		tr := &result.Tools[i]
		if tr.Name == "naabu" {
			naabuResult = tr
			continue
		}
		if tr.OK {
			okCount++
		}
	}
	require.NotNil(t, naabuResult)
	assert.False(t, naabuResult.OK)
	assert.NotEmpty(t, naabuResult.Err)
	assert.Equal(t, len(Tools)-1, okCount, "every tool except the one that failed should still install")
}
