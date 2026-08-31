package toolsync

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// userAgent is required by GitHub's REST API — an unset/generic User-Agent
// gets a 403, confirmed against the real API while researching this
// package (docs/04-environment-and-testing.md's own "verify against the
// real thing, don't assume" discipline).
const userAgent = "hackerfive-toolsync"

// osToken/archToken map Go's own runtime.GOOS/GOARCH to each tool's real
// release-asset naming, confirmed live against subfinder/tlsx/dnsx/naabu/
// httpx/katana's actual `releases/latest` API responses: assets are named
// "<tool>_<version>_<os>_<arch>.zip" where <os> is "macOS" — not Go's own
// "darwin" — for a Darwin build; "linux"/"windows" already match GOOS
// directly. <arch> tokens ("amd64", "arm64", "386", "arm") already match
// GOARCH verbatim, no mapping needed.
func osToken() (string, error) {
	return osTokenFor(runtime.GOOS)
}

// osTokenFor is osToken's table, factored out so tests can exercise every
// GOOS branch without needing to actually run on each platform.
func osTokenFor(goos string) (string, error) {
	switch goos {
	case "darwin":
		return "macOS", nil
	case "linux", "windows":
		return goos, nil
	default:
		return "", fmt.Errorf("toolsync: unsupported OS %q", goos)
	}
}

type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// githubAPIBase is overridden by tests to point at a local httptest server
// instead of the real GitHub API.
var githubAPIBase = "https://api.github.com"

// SetGitHubAPIBaseForTesting overrides the GitHub API base URL Install uses —
// exported (test-support-only, despite the name) so another package's own
// test (pkg/webui's POST /recon/setup handler test) can point a real
// Install call at a local fake server instead of the real network, the
// same way this package's own install_test.go does internally. Returns a
// restore func; callers should defer it or use it in t.Cleanup.
func SetGitHubAPIBaseForTesting(base string) (restore func()) {
	orig := githubAPIBase
	githubAPIBase = base
	return func() { githubAPIBase = orig }
}

func fetchLatestRelease(ctx context.Context, repo string) (*githubRelease, error) {
	url := githubAPIBase + "/repos/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("fetching %s: unexpected status %s: %s", url, resp.Status, body)
	}

	var rel githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decoding release metadata from %s: %w", url, err)
	}
	return &rel, nil
}

// findAsset returns the release asset whose name exactly equals want.
func findAsset(assets []githubAsset, want string) (*githubAsset, bool) {
	for i := range assets {
		if assets[i].Name == want {
			return &assets[i], true
		}
	}
	return nil, false
}

// findChecksumsAsset matches by substring, never an exact filename: the
// checksums asset's own name is not consistent across these 6 tools'
// releases (confirmed live) — "httpx_1.11.0_checksums.txt" vs.
// "naabu-checksums.txt" (no version) vs. "katana-1.7.0-checksums.txt"
// (dashes, not underscores). The file *contents* are a uniform
// sha256sum-style "<hex>  <filename>" line per asset regardless of the
// container filename's own format.
func findChecksumsAsset(assets []githubAsset) (*githubAsset, bool) {
	for i := range assets {
		if strings.Contains(strings.ToLower(assets[i].Name), "checksums") {
			return &assets[i], true
		}
	}
	return nil, false
}

func downloadBytes(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading %s: unexpected status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// verifyChecksum finds assetName's own line in checksumsText (a real
// sha256sum-format file: "<hex>  <filename>" per line, whitespace-
// separated) and compares it against data's own SHA-256.
func verifyChecksum(data []byte, checksumsText, assetName string) error {
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])

	for _, line := range strings.Split(checksumsText, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		want, filename := fields[0], fields[len(fields)-1]
		if filename != assetName {
			continue
		}
		if !strings.EqualFold(want, got) {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", assetName, want, got)
		}
		return nil
	}
	return fmt.Errorf("no checksum entry for %s in checksums file", assetName)
}

// extractBinary pulls the single executable out of a downloaded release
// zip. Most of these releases contain the binary itself plus LICENSE.md/
// README.md — matched first by exact name (binaryFilename(toolName)),
// falling back to the only entry that isn't a license/readme/text file if
// naming ever drifts, rather than failing outright.
func extractBinary(zipData []byte, toolName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("reading zip: %w", err)
	}

	want := binaryFilename(toolName)
	var fallback *zip.File
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		if strings.EqualFold(base, want) {
			return readZipFile(f)
		}
		lower := strings.ToLower(base)
		if strings.HasPrefix(lower, "license") || strings.HasPrefix(lower, "readme") || strings.HasSuffix(lower, ".txt") || strings.HasSuffix(lower, ".md") {
			continue
		}
		if fallback == nil {
			fallback = f
		}
	}
	if fallback != nil {
		return readZipFile(fallback)
	}
	return nil, fmt.Errorf("no executable found in zip for %s", toolName)
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	return io.ReadAll(rc)
}

// ToolResult is one Tool's outcome from a single Install call.
type ToolResult struct {
	Name    string
	Version string
	OK      bool
	Err     string // empty when OK
}

// Result summarizes a completed Install — per-tool, never all-or-nothing:
// one tool failing (a renamed asset, a transient network error) doesn't
// stop the other five from installing.
type Result struct {
	Dir   string
	Tools []ToolResult
}

// Install downloads, verifies, and installs every Tool into dir, calling
// progress(tool, message) at each step so a CLI can print lines and a Web
// UI handler can drive an htmx indicator. Always fetches each tool's real
// latest release — unlike templatesync's frozen PinnedCommit, these are
// general-purpose recon utilities, not a matching corpus whose drift
// affects false-positive rate, so "latest" is the right default (same as
// the `go install ...@latest` this replaces).
func Install(ctx context.Context, dir string, progress func(tool, message string)) Result {
	if progress == nil {
		progress = func(string, string) {}
	}

	result := Result{Dir: dir}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		for _, t := range Tools {
			result.Tools = append(result.Tools, ToolResult{Name: t.Name, Err: fmt.Sprintf("creating %s: %v", dir, err)})
		}
		return result
	}

	manifest := readManifest(dir)
	if manifest == nil {
		manifest = make(map[string]manifestEntry)
	}

	httpxInstalled := false
	for _, t := range Tools {
		version, err := installOne(ctx, dir, t, progress)
		if err != nil {
			progress(t.Name, "failed: "+err.Error())
			result.Tools = append(result.Tools, ToolResult{Name: t.Name, Err: err.Error()})
			continue
		}
		manifest[t.Name] = manifestEntry{Version: version, InstalledAt: time.Now()}
		result.Tools = append(result.Tools, ToolResult{Name: t.Name, Version: version, OK: true})
		progress(t.Name, "installed v"+version)
		if t.Name == "httpx" {
			httpxInstalled = true
		}
	}

	if err := writeManifest(dir, manifest); err != nil {
		progress("", "warning: could not write install manifest: "+err.Error())
	}

	if httpxInstalled {
		warmUpHTTPXModel(ctx, filepath.Join(dir, binaryFilename("httpx")), progress)
	}

	return result
}

func installOne(ctx context.Context, dir string, t Tool, progress func(tool, message string)) (string, error) {
	progress(t.Name, "checking latest release")
	release, err := fetchLatestRelease(ctx, t.Repo)
	if err != nil {
		return "", err
	}
	version := strings.TrimPrefix(release.TagName, "v")

	osTok, err := osToken()
	if err != nil {
		return "", err
	}
	assetName := fmt.Sprintf("%s_%s_%s_%s.zip", t.Name, version, osTok, runtime.GOARCH)

	asset, ok := findAsset(release.Assets, assetName)
	if !ok {
		return "", fmt.Errorf("no release asset named %q for %s %s", assetName, release.TagName, t.Repo)
	}
	checksumsAsset, ok := findChecksumsAsset(release.Assets)
	if !ok {
		return "", fmt.Errorf("no checksums asset found in %s %s release", release.TagName, t.Repo)
	}

	progress(t.Name, "downloading "+assetName)
	zipData, err := downloadBytes(ctx, asset.BrowserDownloadURL)
	if err != nil {
		return "", err
	}
	checksumsData, err := downloadBytes(ctx, checksumsAsset.BrowserDownloadURL)
	if err != nil {
		return "", err
	}

	progress(t.Name, "verifying checksum")
	if err := verifyChecksum(zipData, string(checksumsData), assetName); err != nil {
		return "", err
	}

	binData, err := extractBinary(zipData, t.Name)
	if err != nil {
		return "", err
	}

	if err := installBinary(dir, t.Name, binData); err != nil {
		return "", err
	}
	return version, nil
}

// installBinary writes data to a temp file in dir, marks it executable,
// then renames it into place — the rename is atomic on every platform this
// project targets, so a reader never observes a partially-written binary.
func installBinary(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpPath, filepath.Join(dir, binaryFilename(name)))
}

// warmUpHTTPXModel forces httpx's separate, ~93MB first-invocation
// Wappalyzer model-file download (docs/04-environment-and-testing.md's
// already-documented gotcha) to happen now, during this explicit setup
// step, instead of surprising someone mid-recon later. Runs against a
// local, loopback-only httptest server — never a real external host, same
// "no live/external target for internal operations" discipline this
// project's own test suite already follows. Best-effort: a failure here
// only logs via progress, it never fails Install overall — the model file
// will simply download on first real use instead, exactly like today.
func warmUpHTTPXModel(ctx context.Context, httpxPath string, progress func(tool, message string)) {
	progress("httpx", "warming up tech-detect model (first-run ~93MB download)")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	warmCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(warmCtx, httpxPath, "-silent", "-tech-detect", "-u", srv.URL)
	if err := cmd.Run(); err != nil {
		progress("httpx", "model warm-up skipped (non-fatal): "+err.Error())
	}
}
