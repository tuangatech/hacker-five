package recon

import "testing"

func TestServerProductVersion(t *testing.T) {
	cases := []struct {
		name        string
		header      string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"nginx with patch version", "nginx/1.25.3", "Nginx", "1.25.3", true},
		{"apache with trailing comment", "Apache/2.4.41 (Ubuntu)", "Apache", "2.4.41", true},
		{"apache short version", "Apache/2.2.34", "Apache", "2.2.34", true},
		{"iis", "Microsoft-IIS/10.0", "IIS", "10.0", true},
		{"case-insensitive product", "NGINX/1.20.1", "Nginx", "1.20.1", true},
		{"no version at all", "nginx", "", "", false},
		{"unrecognized product", "openresty/1.21.4", "", "", false},
		{"cdn-branded, not a real server product", "cloudflare", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			name, version, ok := serverProductVersion(c.header)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if name != c.wantName || version != c.wantVersion {
				t.Fatalf("got (%q, %q), want (%q, %q)", name, version, c.wantName, c.wantVersion)
			}
		})
	}
}

func TestHeaderValue_CaseInsensitive(t *testing.T) {
	headers := map[string]string{"Server": "nginx/1.25.3"}
	if got := headerValue(headers, "server"); got != "nginx/1.25.3" {
		t.Fatalf("got %q", got)
	}
	if got := headerValue(headers, "SERVER"); got != "nginx/1.25.3" {
		t.Fatalf("got %q", got)
	}
	if got := headerValue(nil, "server"); got != "" {
		t.Fatalf("got %q, want empty for nil headers", got)
	}
}
