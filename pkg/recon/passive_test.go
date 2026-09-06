package recon

import "testing"

func TestRobotsDisallowsAll(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"blanket disallow", "User-agent: *\nDisallow: /\n", true},
		{"blanket disallow with comment and blank lines", "# robots\n\nUser-agent: *\n\nDisallow: /\n", true},
		{"specific path only", "User-agent: *\nDisallow: /admin/\n", false},
		{"disallow-all but for a named bot only", "User-agent: BadBot\nDisallow: /\n", false},
		{"allow all (empty disallow)", "User-agent: *\nDisallow:\n", false},
		{"no robots directives", "Sitemap: https://x.example/sitemap.xml\n", false},
		{"star group then reset to named bot", "User-agent: *\nAllow: /\n\nUser-agent: Bot\nDisallow: /\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := robotsDisallowsAll(tc.body); got != tc.want {
				t.Fatalf("robotsDisallowsAll(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
