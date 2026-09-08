package recon

import "testing"

func TestNormalizeHostname(t *testing.T) {
	cases := []struct {
		in     string
		wantOK bool
		want   string
	}{
		// valid
		{"sinchi01.nettix.com.pe", true, "sinchi01.nettix.com.pe"},
		{"  WWW.Example.COM  ", true, "www.example.com"},
		{"host.example.com.", true, "host.example.com"}, // trailing FQDN dot
		{"*.nettix.com.pe", true, "nettix.com.pe"},      // wildcard label stripped
		{"a-b.c-d.example.io", true, "a-b.c-d.example.io"},

		// the LT-112 case: an FTP multiline-greeting prefix scraped as a host
		{"220-sinchi01.nettix.com.pe", false, ""},
		{"550-mail.example.com", false, ""},

		// other malformed input
		{"", false, ""},
		{"localhost", false, ""},        // no dot
		{"nettix.com.123", false, ""},   // numeric TLD
		{"-lead.example.com", false, ""},
		{"trail-.example.com", false, ""},
		{"has space.example.com", false, ""},
		{"under_score.example.com", false, ""},
		{"http://x.example.com", false, ""}, // scheme leaked in
		{"x.example.com/path", false, ""},   // path leaked in
	}
	for _, c := range cases {
		got, ok := normalizeHostname(c.in)
		if ok != c.wantOK {
			t.Errorf("normalizeHostname(%q) ok = %v, want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && got != c.want {
			t.Errorf("normalizeHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLooksLikeProtocolBanner(t *testing.T) {
	for _, s := range []string{"220-sinchi01", "421-foo", "999-x"} {
		if !looksLikeProtocolBanner(s) {
			t.Errorf("looksLikeProtocolBanner(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"22-foo", "2200-foo", "abc-foo", "foo", "12a-foo", "220foo"} {
		if looksLikeProtocolBanner(s) {
			t.Errorf("looksLikeProtocolBanner(%q) = true, want false", s)
		}
	}
}
