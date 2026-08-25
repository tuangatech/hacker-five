package nuclei

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzNucleiLoadDir exercises LoadDir with malformed/edge-case template YAML.
// The scanner parses arbitrary third-party template files (community
// templates, not just ones this project wrote), which is its own attack
// surface, not just the target's — same rationale as
// pkg/scanner/httpclient's FuzzResponseParsing. Only checks LoadDir never
// panics; a parse/validation error is the expected, correct outcome for
// malformed input, not a failure.
func FuzzNucleiLoadDir(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("not yaml at all"))
	f.Add([]byte("id: x\ninfo:\n  name: x\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}\"]\n"))
	f.Add([]byte("id: x\ninfo: [broken\n"))
	f.Add([]byte("{{{{{{"))
	f.Add([]byte("id: x\nhttp:\n  - matchers:\n      - type: dsl\n        dsl: [\"((((\"]\n"))
	f.Add([]byte("\x00\x01\x02binary garbage\xff\xfe"))
	f.Add([]byte("id: x\n" + repeatString("nested:\n  ", 500) + "value: 1\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "fuzz.yaml"), data, 0o644); err != nil {
			t.Skip()
		}
		LoadDir(dir) // must not panic; errors are expected/correct for malformed input
	})
}

func repeatString(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}
