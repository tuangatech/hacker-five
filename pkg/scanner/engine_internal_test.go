package scanner

import (
	"testing"
	"time"
)

// TestRoundScanDuration pins the magnitude-matched precision the
// scan-completion log line uses: whole minutes past 10m, whole seconds past
// 1m, 100ms below that (so unit-test-scale scans still print a useful value).
func TestRoundScanDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{18*time.Minute + 25*time.Second + 522*time.Millisecond, 18 * time.Minute},
		{10 * time.Minute, 10 * time.Minute},
		{9*time.Minute + 40*time.Second, 9*time.Minute + 40*time.Second}, // 1m..10m: to the second
		{1*time.Minute + 300*time.Millisecond, 1 * time.Minute},
		{2*time.Minute + 600*time.Millisecond, 2*time.Minute + 1*time.Second}, // .Round rounds the half up
		{45*time.Second + 40*time.Millisecond, 45 * time.Second},
		{1234 * time.Millisecond, 1200 * time.Millisecond},
		{20 * time.Millisecond, 0},
	}
	for _, c := range cases {
		if got := roundScanDuration(c.in); got != c.want {
			t.Errorf("roundScanDuration(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}
