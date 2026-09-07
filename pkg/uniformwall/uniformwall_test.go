package uniformwall

import "testing"

func TestLooksLikeKnownBlockPage(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"akamai edgesuite marker", `<TITLE>Access Denied</TITLE> ref errors.edgesuite.net/18.abc`, true},
		{"plain 404", `<html><title>404 - Page Not Found</title></html>`, false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LooksLikeKnownBlockPage([]byte(c.body)); got != c.want {
				t.Fatalf("LooksLikeKnownBlockPage(%q) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}

func TestObservation_StorageOrigin(t *testing.T) {
	for _, c := range []struct {
		server string
		want   bool
	}{
		{"UploadServer", true},
		{"AmazonS3", true},
		{"cloudflare", false},
		{"nginx", false},
		{"", false},
	} {
		if got := (Observation{ServerHeader: c.server}).StorageOrigin(); got != c.want {
			t.Errorf("StorageOrigin(Server: %q) = %v, want %v", c.server, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	htmlShell := Observation{Status: 200, BodyLen: 1500, ContentType: "text/html; charset=utf-8"}
	cases := []struct {
		name   string
		canary Observation
		root   *Observation
		want   Verdict
	}{
		{
			name:   "normal host: canary 404",
			canary: Observation{Status: 404, BodyLen: 200, ContentType: "text/html"},
			root:   &Observation{Status: 200, BodyLen: 40000, ContentType: "text/html"},
			want:   VerdictNone,
		},
		{
			name:   "akamai block page on canary",
			canary: Observation{Status: 403, BodyLen: 400, ContentType: "text/html", Body: []byte("reference errors.edgesuite.net")},
			want:   VerdictWAFBlock,
		},
		{
			name:   "bare 403 canary, no marker",
			canary: Observation{Status: 403, BodyLen: 400, ContentType: "text/html"},
			want:   VerdictWAFBlock,
		},
		{
			name:   "429 canary",
			canary: Observation{Status: 429, BodyLen: 50, ContentType: "text/plain"},
			want:   VerdictWAFBlock,
		},
		{
			name:   "200 canary shape-identical to root: SPA catch-all",
			canary: htmlShell,
			root:   &htmlShell,
			want:   VerdictCatchall,
		},
		{
			name:   "200 canary from a storage origin: bucket catch-all",
			canary: Observation{Status: 200, BodyLen: 746, ContentType: "text/html", ServerHeader: "UploadServer"},
			root:   nil,
			want:   VerdictCatchall,
		},
		{
			name:   "200 canary, root is real distinct content",
			canary: Observation{Status: 200, BodyLen: 1500, ContentType: "text/html"},
			root:   &Observation{Status: 200, BodyLen: 90000, ContentType: "text/html"},
			want:   VerdictNone,
		},
		{
			name:   "200 canary, root differs in content type",
			canary: Observation{Status: 200, BodyLen: 1500, ContentType: "text/html"},
			root:   &Observation{Status: 200, BodyLen: 1500, ContentType: "application/json"},
			want:   VerdictNone,
		},
		{
			name:   "block page shows only on root",
			canary: Observation{Status: 200, BodyLen: 10, ContentType: "text/html"},
			root:   &Observation{Status: 403, BodyLen: 400, Body: []byte("errors.edgesuite.net")},
			want:   VerdictWAFBlock,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(c.canary, c.root); got != c.want {
				t.Fatalf("Classify() = %q, want %q", got, c.want)
			}
		})
	}
}
