package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNew_DomainsAndCIDRs(t *testing.T) {
	s, err := New([]string{
		"# a comment",
		"",
		"example.com",
		"*.example.org",
		"10.0.0.0/8",
	})
	if err != nil {
		t.Fatalf("New returned an error: %v", err)
	}

	cases := []struct {
		target string
		want   bool
	}{
		{"https://example.com/path", true},
		{"https://sub.example.org/path", true},
		{"https://example.org/path", true}, // bare domain matches its own "*."-prefixed entry
		{"http://10.1.2.3/", true},
		{"https://not-in-scope.com/", false},
	}
	for _, c := range cases {
		if got := s.Allowed(c.target); got != c.want {
			t.Errorf("Allowed(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestNew_EmptyEntries_DeniesEverything(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New returned an error: %v", err)
	}
	if s.Allowed("https://anything.example.com/") {
		t.Fatal("expected an empty Scope to allow nothing")
	}
}

func TestParse_MatchesNewOnTheSameEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.txt")
	content := "# comment\n\nexample.com\n*.example.org\n10.0.0.0/8\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture scope file: %v", err)
	}

	fromFile, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	fromEntries, err := New([]string{"# comment", "", "example.com", "*.example.org", "10.0.0.0/8"})
	if err != nil {
		t.Fatalf("New returned an error: %v", err)
	}

	target := "https://sub.example.org/path"
	if fromFile.Allowed(target) != fromEntries.Allowed(target) {
		t.Fatalf("Parse and New disagree on %q: file=%v entries=%v", target, fromFile.Allowed(target), fromEntries.Allowed(target))
	}
}
