package scanner

// Self-maintaining parsed-corpus cache (docs/follow-up.md LT-106, the load
// half).
//
// Loading the ~9.6k-file synced nuclei corpus is minutes of wall-clock
// before the first request: every file is YAML-decoded and its
// matchers/extractors DSL-type-checked (loader.go's validate). A tag filter
// then discards most of them — but only *after* that full parse, so
// narrowing a scan by --tags/--detector never sped up loading, only
// dispatch.
//
// This cache closes that gap. After any full parse, the scanner writes a
// sidecar recording every template's id, tags, severity, format and
// dir-relative path, keyed by a fingerprint of the directory (every
// template file's relative path + size + mtime). On the next run, if the
// fingerprint still matches, a tag-scoped load resolves the wanted tags to a
// file list straight from the sidecar and parses only those files
// (nuclei.LoadFiles / native.LoadFiles) — the ~1.6k that can match, not the
// full ~9.6k.
//
// It is a pure optimisation, never a behaviour change: a fingerprint match
// means the exact same set of files exists unchanged, so every file's tags:
// block — and therefore the tag-match decision — is identical to when the
// sidecar was built from an authoritative full parse. Any mismatch (missing
// sidecar, changed fingerprint, an entry with no recorded path, a parse
// error on a listed file) falls back to the full parse and rewrites the
// sidecar. The engine also re-runs filterNucleiByTags/filterNativeByTags on
// whatever the fast path returns, so the cache can only ever narrow the
// candidate set, never widen it past what a fresh parse would keep.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tuangatech/hacker-five/pkg/template/native"
	"github.com/tuangatech/hacker-five/pkg/template/nuclei"
)

// parseCacheFormatVersion prefixes every fingerprint so a change to the
// sidecar schema or fingerprint algorithm auto-invalidates every existing
// file without needing a migration.
const parseCacheFormatVersion = "hf-parsecache-v1"

// parseCacheDisableEnv, set to 1/true/yes, turns the LT-106 parse cache off
// entirely — every load does a full parse, nothing is read or written. The
// escape hatch if the cache is ever suspected of masking a corpus change.
const parseCacheDisableEnv = "HACKERFIVE_DISABLE_PARSE_CACHE"

func parseCacheDisabled() bool {
	switch strings.TrimSpace(strings.ToLower(os.Getenv(parseCacheDisableEnv))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// parseCacheEntry is one template's cached metadata — everything the tag
// filter and dispatch-priority sort need, plus the path to parse on a hit.
type parseCacheEntry struct {
	ID       string `json:"id"`
	Path     string `json:"path"` // relative to the cached dir, forward-slash
	Format   string `json:"format"` // "nuclei" | "native"
	Tags     string `json:"tags"`   // comma-separated (nuclei Info.Tags shape; native Tags joined)
	Severity string `json:"severity"`
}

// parseCacheFile is the on-disk sidecar. Dir is stored so a hash collision
// or a repurposed cache path is caught on read.
type parseCacheFile struct {
	Dir         string            `json:"dir"`
	Fingerprint string            `json:"fingerprint"`
	GeneratedAt time.Time         `json:"generated_at"`
	Entries     []parseCacheEntry `json:"entries"`
}

// parseCacheEnabled is flipped off (once, with a warning) if the user cache
// dir can't be resolved — then every lookup and store is a silent no-op and
// the engine just does full parses as before.
func parseCachePath(dir string) (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolving user cache dir: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", dir, err)
	}
	sum := sha256.Sum256([]byte(abs))
	name := hex.EncodeToString(sum[:])[:16] + ".json"
	cacheDir := filepath.Join(base, "hackerfive", "parsecache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", cacheDir, err)
	}
	return filepath.Join(cacheDir, name), nil
}

// fingerprintTemplateDir hashes the identity of every .yaml/.yml file under
// dir — relative path, size, mtime — in the deterministic lexical order
// WalkDir yields. Adding, removing, or touching any template file changes
// the result; a content edit that preserves both size and mtime does not
// (the same, accepted, limitation every mtime-based build cache carries).
// This walk is the price paid on every run to decide whether the cache is
// usable: a stat-only pass over ~9.6k files, milliseconds, versus the
// minutes a full parse costs.
func fingerprintTemplateDir(dir string) (string, error) {
	h := sha256.New()
	// sha256's Write never errors (hash.Hash contract); the _, _ = discards
	// keep errcheck quiet without a nolint.
	_, _ = fmt.Fprintln(h, parseCacheFormatVersion)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00%d\n", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// readParseCache loads and validates the sidecar for dir: it must exist,
// parse, and be for this exact dir. A returned error (of any kind) means the
// caller should treat the cache as absent and do a full parse.
func readParseCache(dir string) (*parseCacheFile, error) {
	path, err := parseCachePath(dir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pc parseCacheFile
	if err := json.Unmarshal(data, &pc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if pc.Dir != abs {
		return nil, fmt.Errorf("parse cache %s is for %q, not %q", path, pc.Dir, abs)
	}
	return &pc, nil
}

// writeParseCache stores entries for dir under fingerprint. Best-effort:
// a write failure (read-only cache dir, disk full) is returned for the
// caller to log, never to abort the scan.
func writeParseCache(dir, fingerprint string, entries []parseCacheEntry) error {
	path, err := parseCachePath(dir)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	data, err := json.MarshalIndent(parseCacheFile{
		Dir:         abs,
		Fingerprint: fingerprint,
		GeneratedAt: time.Now().UTC(),
		Entries:     entries,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling parse cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}

// parseCacheEntriesFor builds the sidecar entry list for a dir from an
// authoritative full parse (nt/vt) plus a cheap id->path peek pass. An entry
// whose id the peek couldn't place gets an empty Path; storeParseCache still
// records it, and a later hit that needs that entry falls back to a full
// parse because of the empty path.
func parseCacheEntriesFor(dir string, nt []*nuclei.Template, vt []*native.Template) ([]parseCacheEntry, error) {
	idToPath, err := nuclei.PeekDirIDs(dir)
	if err != nil {
		return nil, err
	}
	entries := make([]parseCacheEntry, 0, len(nt)+len(vt))
	for _, t := range nt {
		entries = append(entries, parseCacheEntry{
			ID: t.ID, Path: idToPath[t.ID], Format: "nuclei",
			Tags: t.Info.Tags, Severity: t.Info.Severity,
		})
	}
	for _, t := range vt {
		entries = append(entries, parseCacheEntry{
			ID: t.ID, Path: idToPath[t.ID], Format: "native",
			Tags: strings.Join(t.Tags, ","), Severity: t.Info.Severity,
		})
	}
	return entries, nil
}

// selectCachedByTags splits a sidecar's entries into the dir-relative paths
// to parse for each format, keeping only entries whose tags intersect want
// (OR match, normalised identically to filterNucleiByTags via tagSet /
// normalizeTag). ok is false when any selected entry has no recorded path —
// the signal to abandon the fast path and do a full parse.
func selectCachedByTags(entries []parseCacheEntry, want []string) (nucleiPaths, nativePaths []string, ok bool) {
	set := tagSet(want)
	for _, e := range entries {
		matched := false
		for _, tag := range strings.Split(e.Tags, ",") {
			if set[normalizeTag(tag)] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if e.Path == "" {
			return nil, nil, false
		}
		switch e.Format {
		case "native":
			nativePaths = append(nativePaths, e.Path)
		default:
			nucleiPaths = append(nucleiPaths, e.Path)
		}
	}
	return nucleiPaths, nativePaths, true
}
