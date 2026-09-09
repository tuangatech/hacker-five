package scanner

import "testing"

func TestEffectiveTargetConcurrency(t *testing.T) {
	cases := []struct {
		name                                        string
		configured, rateLimit, nucleiCount, targets int
		want                                        int
	}{
		{
			name: "large corpus, many targets, default rate: capped to the per-target share",
			// 8 nettix hosts, --rate-limit 10, ~3745-template corpus (LT-114's
			// exact scenario) -> 10/5 = 2 targets at a time.
			configured: 25, rateLimit: 10, nucleiCount: 3745, targets: 8, want: 2,
		},
		{
			name:       "large corpus, higher rate: share widens",
			configured: 25, rateLimit: 50, nucleiCount: 9652, targets: 8, want: 10,
		},
		{
			name: "share exceeds configured: configured still wins (never raises concurrency)",
			// 100/5 = 20 >= configured 8, so no reduction.
			configured: 8, rateLimit: 100, nucleiCount: 9652, targets: 8, want: 8,
		},
		{
			name:       "sub-threshold corpus: not touched even at a thin rate",
			configured: 25, rateLimit: 10, nucleiCount: 499, targets: 8, want: 25,
		},
		{
			name:       "native-only run (zero nuclei templates): not touched",
			configured: 25, rateLimit: 10, nucleiCount: 0, targets: 8, want: 25,
		},
		{
			name:       "single target: nothing to share the bucket with",
			configured: 25, rateLimit: 10, nucleiCount: 9652, targets: 1, want: 25,
		},
		{
			name:       "very low rate: share floors at 1, never 0",
			configured: 25, rateLimit: 3, nucleiCount: 9652, targets: 8, want: 1,
		},
		{
			name:       "configured below 1 is clamped up to 1",
			configured: 0, rateLimit: 10, nucleiCount: 9652, targets: 8, want: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := effectiveTargetConcurrency(c.configured, c.rateLimit, c.nucleiCount, c.targets)
			if got != c.want {
				t.Errorf("effectiveTargetConcurrency(%d, %d, %d, %d) = %d, want %d",
					c.configured, c.rateLimit, c.nucleiCount, c.targets, got, c.want)
			}
		})
	}
}
