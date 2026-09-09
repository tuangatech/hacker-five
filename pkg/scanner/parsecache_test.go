package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const pcNucleiWordpress = `id: pc-nuclei-wp
info:
  name: pc nuclei wp
  severity: high
  tags: wordpress,cms
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["x"]
`

const pcNucleiExposure = `id: pc-nuclei-exposure
info:
  name: pc nuclei exposure
  severity: medium
  tags: exposure,config
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["x"]
`

const pcNucleiWordpressSub = `id: pc-nuclei-wp-sub
info:
  name: pc nuclei wp sub
  severity: low
  tags: wordpress,panel
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers:
      - type: word
        words: ["x"]
`

const pcNativeWordpress = `id: pc-native-wp
info:
  name: pc native wp
  severity: info
tags:
  - wordpress
requests:
  - path: "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["x"]
`

const pcNativeMisc = `id: pc-native-misc
info:
  name: pc native misc
  severity: info
tags:
  - misc
requests:
  - path: "{{BaseURL}}/"
    matchers:
      - type: word
        words: ["x"]
`

// mkParseCacheCorpus writes a small mixed-format corpus (one file in a
// subdirectory, to exercise recursive walk + relative-path handling) and
// returns its root.
func mkParseCacheCorpus(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(body), 0o644))
	}
	write("a.yaml", pcNucleiWordpress)
	write("b.yaml", pcNucleiExposure)
	write("nested/c.yaml", pcNucleiWordpressSub)
	write("n1.yaml", pcNativeWordpress)
	write("n2.yaml", pcNativeMisc)
	return dir
}

// loadWithCapturedLog builds an Engine for cfg, captures every warnf line,
// runs loadTemplates, and returns the loaded IDs (nuclei then native) plus
// the joined log.
func loadWithCapturedLog(t *testing.T, cfg Config) (nucleiIDs, nativeIDs []string, log string) {
	t.Helper()
	require.NoError(t, cfg.Validate())
	e := New(cfg)
	var sb strings.Builder
	e.WithLogCallback(func(_, msg string) { sb.WriteString(msg); sb.WriteByte('\n') })
	nt, vt := e.loadTemplates()
	for _, x := range nt {
		nucleiIDs = append(nucleiIDs, x.ID)
	}
	for _, x := range vt {
		nativeIDs = append(nativeIDs, x.ID)
	}
	return nucleiIDs, nativeIDs, sb.String()
}

func baseParseCacheCfg(dir string) Config {
	return Config{
		Targets:       []string{"https://example.com"},
		TemplatePaths: []string{dir},
		Tags:          []string{"wordpress"},
		Detector:      "misconfig",
		Concurrency:   5,
		RateLimit:     50,
		Timeout:       5 * time.Second,
	}
}

// TestParseCache_MissThenHit_SameResult is the core LT-106 guarantee: the
// second load resolves the tag scope straight from the sidecar (no full
// corpus parse) and returns exactly the same templates as the first,
// full-parse load.
func TestParseCache_MissThenHit_SameResult(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := mkParseCacheCorpus(t)
	cfg := baseParseCacheCfg(dir)

	n1, v1, log1 := loadWithCapturedLog(t, cfg)
	assert.ElementsMatch(t, []string{"pc-nuclei-wp", "pc-nuclei-wp-sub"}, n1)
	assert.ElementsMatch(t, []string{"pc-native-wp"}, v1)
	assert.NotContains(t, log1, "parse cache hit", "first load has no sidecar yet")

	n2, v2, log2 := loadWithCapturedLog(t, cfg)
	assert.ElementsMatch(t, n1, n2, "cache-hit load must return the same nuclei templates as the full parse")
	assert.ElementsMatch(t, v1, v2, "cache-hit load must return the same native templates as the full parse")
	assert.Contains(t, log2, "parse cache hit", "second load must come from the sidecar")
}

// TestParseCache_FingerprintInvalidation: editing any template file changes
// the directory fingerprint, so the next load is a full parse again — and
// picks up the edit (here, a new wordpress tag on a file that didn't match
// before).
func TestParseCache_FingerprintInvalidation(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := mkParseCacheCorpus(t)
	cfg := baseParseCacheCfg(dir)

	_, _, _ = loadWithCapturedLog(t, cfg)          // warm the cache
	_, _, hitLog := loadWithCapturedLog(t, cfg)    // confirm it's warm
	require.Contains(t, hitLog, "parse cache hit")

	// Re-tag b.yaml so it now matches "wordpress", and bump its mtime well
	// clear of the original so a coarse-resolution filesystem still sees it.
	bPath := filepath.Join(dir, "b.yaml")
	retagged := strings.Replace(pcNucleiExposure, "tags: exposure,config", "tags: exposure,wordpress", 1)
	require.NoError(t, os.WriteFile(bPath, []byte(retagged), 0o644))
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(bPath, future, future))

	n3, _, log3 := loadWithCapturedLog(t, cfg)
	assert.NotContains(t, log3, "parse cache hit", "a changed file must invalidate the fingerprint")
	assert.Contains(t, n3, "pc-nuclei-exposure", "the full re-parse must see b.yaml's new wordpress tag")
}

// TestParseCache_DisabledByEnv: with the kill switch set, nothing is read or
// written and every load is a full parse.
func TestParseCache_DisabledByEnv(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv(parseCacheDisableEnv, "1")
	dir := mkParseCacheCorpus(t)
	cfg := baseParseCacheCfg(dir)

	_, _, log1 := loadWithCapturedLog(t, cfg)
	_, _, log2 := loadWithCapturedLog(t, cfg)
	assert.NotContains(t, log1, "parse cache")
	assert.NotContains(t, log2, "parse cache hit")

	cachePath, err := parseCachePath(dir)
	require.NoError(t, err)
	_, statErr := os.Stat(cachePath)
	assert.True(t, os.IsNotExist(statErr), "no sidecar should be written when the cache is disabled")
}

// TestParseCache_NotUsedWithoutTagScope: a full corpus run (no --tags, no
// derived scope) can't use the cache to narrow — but it still warms it.
func TestParseCache_NotUsedWithoutTagScope(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := mkParseCacheCorpus(t)
	cfg := baseParseCacheCfg(dir)
	cfg.Tags = nil
	cfg.AllTemplates = true

	n1, _, log1 := loadWithCapturedLog(t, cfg)
	assert.Subset(t, n1, []string{"pc-nuclei-wp", "pc-nuclei-exposure", "pc-nuclei-wp-sub"}, "no tag scope -> every nuclei template loads")
	assert.NotContains(t, log1, "parse cache hit")

	cachePath, err := parseCachePath(dir)
	require.NoError(t, err)
	_, statErr := os.Stat(cachePath)
	assert.NoError(t, statErr, "a full parse still writes the sidecar for a later scoped run")
}

func TestFingerprintTemplateDir_StableAndSensitive(t *testing.T) {
	dir := mkParseCacheCorpus(t)

	fp1, err := fingerprintTemplateDir(dir)
	require.NoError(t, err)
	fp2, err := fingerprintTemplateDir(dir)
	require.NoError(t, err)
	assert.Equal(t, fp1, fp2, "fingerprint must be stable for an unchanged directory")

	extra := filepath.Join(dir, "extra.yaml")
	require.NoError(t, os.WriteFile(extra, []byte(pcNativeMisc), 0o644))
	fp3, err := fingerprintTemplateDir(dir)
	require.NoError(t, err)
	assert.NotEqual(t, fp1, fp3, "adding a file must change the fingerprint")

	require.NoError(t, os.Remove(extra))
	fp4, err := fingerprintTemplateDir(dir)
	require.NoError(t, err)
	assert.Equal(t, fp1, fp4, "removing that file must restore the original fingerprint")
}

func TestSelectCachedByTags(t *testing.T) {
	entries := []parseCacheEntry{
		{ID: "a", Path: "a.yaml", Format: "nuclei", Tags: "wordpress,cms"},
		{ID: "b", Path: "b.yaml", Format: "nuclei", Tags: "exposure,config"},
		{ID: "c", Path: "nested/c.yaml", Format: "nuclei", Tags: "WordPress,panel"}, // case-insensitive match
		{ID: "n", Path: "n1.yaml", Format: "native", Tags: "wordpress"},
	}

	nucleiPaths, nativePaths, ok := selectCachedByTags(entries, []string{"wordpress"})
	require.True(t, ok)
	assert.ElementsMatch(t, []string{"a.yaml", "nested/c.yaml"}, nucleiPaths)
	assert.ElementsMatch(t, []string{"n1.yaml"}, nativePaths)

	// An entry with no recorded path forces a full parse (ok == false).
	bad := append([]parseCacheEntry{}, entries...)
	bad = append(bad, parseCacheEntry{ID: "z", Path: "", Format: "nuclei", Tags: "wordpress"})
	_, _, ok = selectCachedByTags(bad, []string{"wordpress"})
	assert.False(t, ok, "a matched entry with an empty path must abandon the fast path")
}

func TestReadParseCache_RejectsWrongDir(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dirA := mkParseCacheCorpus(t)
	require.NoError(t, writeParseCache(dirA, "fp-A", []parseCacheEntry{{ID: "x", Path: "a.yaml", Format: "nuclei", Tags: "t"}}))

	got, err := readParseCache(dirA)
	require.NoError(t, err)
	assert.Equal(t, "fp-A", got.Fingerprint)

	// Hand-craft a sidecar whose Dir field points elsewhere, at dirA's cache
	// path, and confirm readParseCache rejects it.
	p, err := parseCachePath(dirA)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, []byte(`{"dir":"/some/other/place","fingerprint":"fp-A","entries":[]}`), 0o644))
	_, err = readParseCache(dirA)
	assert.Error(t, err, "a sidecar recorded for a different dir must be rejected")
}
