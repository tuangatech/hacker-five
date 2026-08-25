package native

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzNativeLoadDir mirrors pkg/template/nuclei's FuzzNucleiLoadDir for the
// native format — malformed/edge-case YAML must never panic LoadDir, only
// produce a load error (the correct outcome for malformed input).
func FuzzNativeLoadDir(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not yaml at all"))
	f.Add([]byte("id: x\ninfo:\n  name: x\nrequests:\n  - path: \"{{BaseURL}}\"\n"))
	f.Add([]byte("id: x\ntags: [idor]\nrequests:\n  - path: \"{{BaseURL}}/{{RangeInt(1|100)}}\"\n"))
	f.Add([]byte("id: x\ninfo: [broken\n"))
	f.Add([]byte("{{{{{{"))
	f.Add([]byte("id: x\nrequests:\n  - path: \"{{BaseURL}}\"\n    condition: \"(((\"\n"))
	f.Add([]byte("\x00\x01\x02binary garbage\xff\xfe"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "fuzz.yaml"), data, 0o644); err != nil {
			t.Skip()
		}
		LoadDir(dir) // must not panic; errors are expected/correct for malformed input
	})
}
