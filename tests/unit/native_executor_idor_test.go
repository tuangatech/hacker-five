package unit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/template/native"
)

// TestNativeExecutorIDOR reuses the exact fixture/server plumbing from
// detector_idor_test.go (loadIDORFixture, newFixtureServer, the same
// idor_*.json fixtures) but drives them through a parsed native.Template +
// native.Executor.Run instead of idor.Detector.Run directly — proving "one
// algorithm, two entry points" per docs/10-implementation-plan-ph1b.md Step 3.
func TestNativeExecutorIDOR(t *testing.T) {
	cases := []struct {
		name           string
		fixture        string
		heuristicOnly  bool
		wantFindings   int
		wantConfidence string
	}{
		{name: "clean baseline, no leak", fixture: "idor_clean_baseline.json", wantFindings: 0},
		{name: "classic IDOR", fixture: "idor_classic.json", wantFindings: 1, wantConfidence: "high"},
		{name: "server error, not a leak", fixture: "idor_server_error.json", wantFindings: 0},
		{name: "heuristic mode, differing content", fixture: "idor_heuristic_differing.json", heuristicOnly: true, wantFindings: 1, wantConfidence: "low"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := loadIDORFixture(t, tc.fixture)
			srv := newFixtureServer(t, fx)
			defer srv.Close()

			client := httpclient.New(httpclient.Config{
				Timeout:             5 * time.Second,
				MaxRedirects:        5,
				MaxIdleConnsPerHost: 10,
			})
			tmpl := &native.Template{
				ID:   "test-idor",
				Tags: []string{"idor"},
				Requests: []native.Request{
					{Path: fmt.Sprintf("{{BaseURL}}/api/users/{{RangeInt(1|%d)}}", fx.NumIDs)},
				},
			}

			ownerToken := fx.OwnerToken
			if tc.heuristicOnly {
				ownerToken = ""
			}

			findings, err := native.New(client).Run(context.Background(), srv.URL, tmpl, ownerToken, fx.OtherToken)
			require.NoError(t, err)
			require.Len(t, findings, tc.wantFindings)

			for _, f := range findings {
				assert.Equal(t, "idor", f.Type)
				if tc.wantConfidence != "" {
					assert.Equal(t, tc.wantConfidence, f.Confidence)
				}
			}
		})
	}
}

// TestNativeExecutorIDOR_SkipsWhenBothTokensEmpty locks in Step 3's Context
// #6 fix: an idor-tagged native template reached via --templates while
// --detector isn't idor (so Config.Validate() never required a token)
// shouldn't silently fire fully unauthenticated.
func TestNativeExecutorIDOR_SkipsWhenBothTokensEmpty(t *testing.T) {
	fx := loadIDORFixture(t, "idor_classic.json")
	srv := newFixtureServer(t, fx)
	defer srv.Close()

	client := httpclient.New(httpclient.Config{Timeout: 5 * time.Second, MaxRedirects: 5, MaxIdleConnsPerHost: 10})
	tmpl := &native.Template{
		ID:   "test-idor",
		Tags: []string{"idor"},
		Requests: []native.Request{
			{Path: fmt.Sprintf("{{BaseURL}}/api/users/{{RangeInt(1|%d)}}", fx.NumIDs)},
		},
	}

	findings, err := native.New(client).Run(context.Background(), srv.URL, tmpl, "", "")
	require.NoError(t, err)
	assert.Empty(t, findings)
}
