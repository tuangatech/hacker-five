package templatesync

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestWriteIndexThenLoadIndex_RoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.json")
	entries := []Entry{
		{ID: "t1", Name: "Template One", Format: "nuclei", Severity: "medium", Tags: []string{"misconfig"}, Source: "bundled"},
		{ID: "t2", Name: "Template Two", Format: "native", Severity: "high", Tags: []string{"idor"}, Source: "synced"},
	}

	if err := WriteIndex(path, entries); err != nil {
		t.Fatalf("WriteIndex: %v", err)
	}

	got, err := LoadIndex(path)
	if err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
	for i, e := range entries {
		if !reflect.DeepEqual(got[i], e) {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], e)
		}
	}
}

func TestLoadIndex_MissingFile_ReturnsError(t *testing.T) {
	_, err := LoadIndex(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected an error for a missing index file — callers degrade gracefully on this error, but LoadIndex itself must still report it")
	}
}
