package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// TestTemplateDirFingerprintCache_GetSet is the LT-197-residual cache type's
// own contract: a miss returns ok=false, a set makes the next get for the
// same key a hit, and the zero value (no explicit construction) is usable —
// New relies on this for every Engine that gets its own private instance.
func TestTemplateDirFingerprintCache_GetSet(t *testing.T) {
	var c TemplateDirFingerprintCache
	_, ok := c.get("/some/dir")
	assert.False(t, ok, "an empty cache must miss")

	c.set("/some/dir", "fp-1")
	got, ok := c.get("/some/dir")
	require.True(t, ok)
	assert.Equal(t, "fp-1", got)

	_, ok = c.get("/other/dir")
	assert.False(t, ok, "a different key must still miss")
}

// TestTemplateDirFingerprintCache_ConcurrentAccess exercises the mutex under
// `go test -race`: Engine.Run dispatches multiple targets against the same
// shared corpus dir concurrently (cfg.Concurrency), so concurrent get/set
// against one cache instance must never race.
func TestTemplateDirFingerprintCache_ConcurrentAccess(t *testing.T) {
	var c TemplateDirFingerprintCache
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dir := fmt.Sprintf("/dir/%d", i%5)
			c.set(dir, fmt.Sprintf("fp-%d", i))
			c.get(dir)
		}(i)
	}
	wg.Wait()
}

// TestEngineFingerprintDir_CachesWithinOneEngine is LT-197's own logged
// residual (docs/follow-up.md): a second call against the same dir, on the
// same Engine, must not re-walk the directory. Proven behaviorally rather
// than by call-counting: the corpus dir is removed between the two calls —
// a real re-walk would fail with the directory gone, so the second call
// only succeeds (with the identical fingerprint) if it came from the cache.
func TestEngineFingerprintDir_CachesWithinOneEngine(t *testing.T) {
	dir := mkParseCacheCorpus(t)
	e := New(baseParseCacheCfg(dir))

	fp1, err := e.fingerprintDir(dir)
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(dir))

	fp2, err := e.fingerprintDir(dir)
	require.NoError(t, err, "a cache hit must not re-walk the now-missing directory")
	assert.Equal(t, fp1, fp2)
}

// TestEngineFingerprintDir_RelativeAndAbsoluteSpellingsShareOneEntry proves
// the filepath.Abs cache-key normalization: two calls for the same
// directory, one via a relative path and one via its absolute form, must
// coalesce into a single cache entry.
func TestEngineFingerprintDir_RelativeAndAbsoluteSpellingsShareOneEntry(t *testing.T) {
	dir := mkParseCacheCorpus(t)
	abs, err := filepath.Abs(dir)
	require.NoError(t, err)

	e := New(baseParseCacheCfg(dir))
	fp1, err := e.fingerprintDir(dir)
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(dir))

	fp2, err := e.fingerprintDir(abs)
	require.NoError(t, err, "the absolute spelling must hit the entry the relative call already cached")
	assert.Equal(t, fp1, fp2)
}

// TestEngineFingerprintDir_SharedCacheAcrossEngines is the cross-Engine half
// of the fix: pkg/planexec.RunPlan constructs a brand new Engine per leaf
// dispatch (planexec/executor.go), so an Engine-private cache alone can't
// help an orchestrator run spanning many leaves against the same dir. A
// caller-supplied Config.TemplateDirFingerprints (pkg/orchestrator sets one
// once per agent Run, mirroring ExecOptions.CorpusHostState's LT-166
// pattern) must be visible to a second, independently-constructed Engine.
func TestEngineFingerprintDir_SharedCacheAcrossEngines(t *testing.T) {
	dir := mkParseCacheCorpus(t)
	shared := &TemplateDirFingerprintCache{}

	cfg1 := baseParseCacheCfg(dir)
	cfg1.TemplateDirFingerprints = shared
	e1 := New(cfg1)
	fp1, err := e1.fingerprintDir(dir)
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(dir))

	cfg2 := baseParseCacheCfg(dir)
	cfg2.TemplateDirFingerprints = shared
	e2 := New(cfg2)
	fp2, err := e2.fingerprintDir(dir)
	require.NoError(t, err, "a second Engine sharing the same cache instance must see the first Engine's entry")
	assert.Equal(t, fp1, fp2)
}

// TestEngineFingerprintDir_DefaultIsPerEngineNotShared pins the opposite,
// unchanged default: when Config.TemplateDirFingerprints is left nil (every
// caller but pkg/orchestrator today — hackerfive scan/webui/MCP), each
// Engine gets its own fresh, unshared cache, exactly as before this fix.
func TestEngineFingerprintDir_DefaultIsPerEngineNotShared(t *testing.T) {
	dir := mkParseCacheCorpus(t)

	e1 := New(baseParseCacheCfg(dir))
	_, err := e1.fingerprintDir(dir)
	require.NoError(t, err)

	require.NoError(t, os.RemoveAll(dir))

	e2 := New(baseParseCacheCfg(dir))
	_, err = e2.fingerprintDir(dir)
	assert.Error(t, err, "a fresh Engine with no shared cache must re-walk and fail against the now-missing directory")
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

// TestSelectCachedByIDs is LT-197's counterpart to TestSelectCachedByTags:
// an id:-based lookup, all-or-nothing.
func TestSelectCachedByIDs(t *testing.T) {
	entries := []parseCacheEntry{
		{ID: "a", Path: "a.yaml", Format: "nuclei", Tags: "wordpress,cms"},
		{ID: "b", Path: "b.yaml", Format: "nuclei", Tags: "exposure,config"},
		{ID: "n", Path: "n1.yaml", Format: "native", Tags: "wordpress"},
		{ID: "id-only", Path: "d.yaml", Format: "nuclei"}, // no Tags — still id-selectable
	}

	nucleiPaths, nativePaths, all := selectCachedByIDs(entries, map[string]bool{"a": true, "n": true})
	require.True(t, all)
	assert.ElementsMatch(t, []string{"a.yaml"}, nucleiPaths)
	assert.ElementsMatch(t, []string{"n1.yaml"}, nativePaths)

	// An id-only entry (from LT-197's merge path, never a real full parse) is
	// still a valid hit — Tags/Severity being blank doesn't disqualify an
	// ID-keyed lookup the way it would a tag-keyed one.
	nucleiPaths, _, all = selectCachedByIDs(entries, map[string]bool{"id-only": true})
	require.True(t, all)
	assert.Equal(t, []string{"d.yaml"}, nucleiPaths)

	// Any wanted id missing from entries (or recorded with an empty path)
	// means the whole lookup is not a hit — never a partial result.
	_, _, all = selectCachedByIDs(entries, map[string]bool{"a": true, "never-seen": true})
	assert.False(t, all, "a wanted id with no entry must abandon the fast path entirely, not return a partial hit")

	entriesWithEmptyPath := append([]parseCacheEntry{}, entries...)
	entriesWithEmptyPath = append(entriesWithEmptyPath, parseCacheEntry{ID: "z", Path: "", Format: "nuclei"})
	_, _, all = selectCachedByIDs(entriesWithEmptyPath, map[string]bool{"z": true})
	assert.False(t, all, "an entry with no recorded path is the same as not having it")

	_, _, all = selectCachedByIDs(entries, nil)
	assert.False(t, all, "an empty want is never a hit — nothing to select")
}

// TestMergeIDOnlyEntries confirms LT-197's write path never downgrades an
// existing tag-usable entry and only adds coverage for a genuinely new id.
func TestMergeIDOnlyEntries(t *testing.T) {
	existing := []parseCacheEntry{
		{ID: "a", Path: "a.yaml", Format: "nuclei", Tags: "wordpress,cms", Severity: "high"},
	}

	merged, changed := mergeIDOnlyEntries(existing, map[string]string{
		"a": "a-wrong-path.yaml", // already present — must be left exactly as-is
		"b": "b.yaml",            // new — added id-only
	})
	require.True(t, changed)
	require.Len(t, merged, 2)
	byID := map[string]parseCacheEntry{}
	for _, e := range merged {
		byID[e.ID] = e
	}
	assert.Equal(t, "a.yaml", byID["a"].Path, "an existing entry's path/tags must never be overwritten by an id-only merge")
	assert.Equal(t, "wordpress,cms", byID["a"].Tags)
	assert.Equal(t, "b.yaml", byID["b"].Path)
	assert.Empty(t, byID["b"].Tags, "an id-only entry carries no tags — it's only ever id-selectable")

	_, changed = mergeIDOnlyEntries(merged, map[string]string{"a": "a.yaml", "b": "b.yaml"})
	assert.False(t, changed, "every id already covered — nothing to add")
}

// TestParseCache_IDIndex_MissThenHitForADifferentID is LT-197's core
// guarantee: a specific-template leaf's cold load (id "a") persists an
// id-only index as a side effect, and a *different* specific-template leaf
// (id "b", same dir, never itself requested before) then hits that index —
// not a fresh walk — and still returns the exact template a full parse
// would.
func TestParseCache_IDIndex_MissThenHitForADifferentID(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := mkParseCacheCorpus(t)
	cfgFor := func(id string) Config {
		return Config{
			Targets: []string{"https://example.com"}, TemplateID: id, Detector: "misconfig",
			Concurrency: 5, RateLimit: 50, Timeout: 5 * time.Second, TemplatePaths: []string{dir},
		}
	}

	n1, _, log1 := loadWithCapturedLog(t, cfgFor("pc-nuclei-wp"))
	assert.Equal(t, []string{"pc-nuclei-wp"}, n1)
	assert.NotContains(t, log1, "id index hit", "first load for any id in this dir has no index yet")

	n2, _, log2 := loadWithCapturedLog(t, cfgFor("pc-nuclei-exposure"))
	assert.Equal(t, []string{"pc-nuclei-exposure"}, n2, "a cache hit must still return the id actually requested, not the first leaf's")
	assert.Contains(t, log2, "id index hit", "a different id, same dir, must resolve from the index left by the first load")
}

// TestLoadTemplates_IDCacheEligible_SkipsNativeLoad_FallsBackIfActuallyNeeded
// is LT-197's safety net: the id-cache-eligible path deliberately never
// calls native.LoadDirDetailed (empirically the larger of the two costs this
// item fixes) on the assumption a TemplateID-narrowed leaf is always a
// synced-corpus (nuclei) id, never a native one. If that assumption is ever
// wrong, nucleiIDsCovered's existing fallback must still find the template —
// this pins that a TemplateID matching a *native* template's id still
// resolves correctly, just via the slower full-parse fallback instead of the
// fast path, rather than silently missing it.
func TestLoadTemplates_IDCacheEligible_SkipsNativeLoad_FallsBackIfActuallyNeeded(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := mkParseCacheCorpus(t)
	cfg := Config{
		Targets: []string{"https://example.com"}, TemplateID: "pc-native-wp", Detector: "misconfig",
		Concurrency: 5, RateLimit: 50, Timeout: 5 * time.Second, TemplatePaths: []string{dir},
	}

	nucleiIDs, nativeIDs, log := loadWithCapturedLog(t, cfg)
	assert.Empty(t, nucleiIDs)
	assert.Equal(t, []string{"pc-native-wp"}, nativeIDs, "a TemplateID that is actually a native template's id must still be found")
	assert.Contains(t, log, "did not account for every requested id", "must go through the F4 fallback, not silently miss it")
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
