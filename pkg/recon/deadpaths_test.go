package recon

import (
	"reflect"
	"sort"
	"testing"
)

func TestReconResult_DeadPaths(t *testing.T) {
	rr := &ReconResult{
		Endpoints: []EndpointFact{
			{URL: "https://ex.com/gone", Method: "GET", StatusCode: 404},
			{URL: "https://ex.com/gone/", Method: "GET", StatusCode: 404},   // trailing slash → same normalized path, deduped
			{URL: "https://ex.com/here", Method: "GET", StatusCode: 200},    // not a 404
			{URL: "https://ex.com/nohead", Method: "HEAD", StatusCode: 404}, // wrong method
			{URL: "https://ex.com/alsogone", StatusCode: 404},              // method unspecified → counts
			{URL: "://bad", Method: "GET", StatusCode: 404},                // unparseable → skipped
		},
	}

	got := rr.DeadPaths()
	sort.Strings(got)
	want := []string{"/alsogone", "/gone"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DeadPaths() = %v, want %v", got, want)
	}
}

func TestReconResult_DeadPaths_NilAndEmpty(t *testing.T) {
	var nilRR *ReconResult
	if got := nilRR.DeadPaths(); got != nil {
		t.Fatalf("nil ReconResult DeadPaths() = %v, want nil", got)
	}
	if got := (&ReconResult{}).DeadPaths(); got != nil {
		t.Fatalf("empty ReconResult DeadPaths() = %v, want nil", got)
	}
}

func TestNormalizeDeadPath(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/a/", "/a"},
		{"/a/b//", "/a/b"},
		{"a/b", "/a/b"},
	} {
		if got := normalizeDeadPath(c.in); got != c.want {
			t.Errorf("normalizeDeadPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
