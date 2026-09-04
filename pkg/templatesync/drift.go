package templatesync

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// indexDriftRatio: an index more than this many times the real on-disk
// template-file count is flagged as drifted. Some legitimate slack is
// expected (a helpers/ wordlist directory sits alongside http/, a template
// counted in the index may have since failed to parse) — this is meant to
// catch "wildly stale" (the real scenario this guards against: a
// 7,716-entry index against an empty synced directory), not nitpick a
// handful of difference.
const indexDriftRatio = 2.0

// CountTemplateFiles counts .yaml/.yml files under dir, recursively — a
// cheap file-count, not a full parse. Deliberately not List/LoadDirDetailed,
// which parse every template's YAML for real (a genuine cost against a
// 9,000+-template corpus) — a drift check only needs "roughly how many
// files are actually there," not an exact, format-validated count.
func CountTemplateFiles(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml":
			count++
		}
		return nil
	})
	return count, err
}

// IndexDriftWarning returns a non-empty warning when indexCount (the number
// of entries templates/index.json claims) looks wildly stale against
// diskCount (CountTemplateFiles against the same directory the index was
// generated from) — empty string means no warning is warranted. Callers
// that can't determine diskCount at all (e.g. the synced directory was never
// created) should pass 0, which always warns whenever indexCount > 0.
func IndexDriftWarning(indexCount, diskCount int) string {
	if indexCount == 0 {
		return ""
	}
	if diskCount == 0 {
		return fmt.Sprintf("warning: templates/index.json lists %d templates but the synced template directory has none on disk — run 'hackerfive templates sync' then 'hackerfive templates index' to refresh", indexCount)
	}
	if float64(indexCount) > float64(diskCount)*indexDriftRatio {
		return fmt.Sprintf("warning: templates/index.json lists %d templates but only %d template files exist on disk — the index looks stale; re-run 'hackerfive templates index'", indexCount, diskCount)
	}
	return ""
}
