package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// fixtureResponse is one canned (status, body) pair served by the mock server.
type fixtureResponse struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// idorFixture maps (ID, token role) pairs to canned responses, per
// docs/09-implementation-plan-ph1.md's tests/fixtures/responses/idor_*.json
// convention. Overrides win over the role's default for a given ID.
type idorFixture struct {
	Description    string                     `json:"description"`
	NumIDs         int                        `json:"num_ids"`
	OwnerToken     string                     `json:"owner_token"`
	OtherToken     string                     `json:"other_token"`
	OwnerDefault   fixtureResponse            `json:"owner_default"`
	OtherDefault   fixtureResponse            `json:"other_default"`
	OwnerOverrides map[string]fixtureResponse `json:"owner_overrides"`
	OtherOverrides map[string]fixtureResponse `json:"other_overrides"`
}

func loadIDORFixture(t *testing.T, name string) idorFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "responses", name))
	require.NoError(t, err)
	var fx idorFixture
	require.NoError(t, json.Unmarshal(data, &fx))
	return fx
}

// newFixtureServer serves fixtureResponses keyed by the request's trailing ID
// path segment and its Authorization header's token role.
func newFixtureServer(t *testing.T, fx idorFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := path.Base(r.URL.Path)
		auth := r.Header.Get("Authorization")

		var resp fixtureResponse
		switch auth {
		case "Bearer " + fx.OwnerToken:
			resp = fx.OwnerDefault
			if override, ok := fx.OwnerOverrides[id]; ok {
				resp = override
			}
		case "Bearer " + fx.OtherToken:
			resp = fx.OtherDefault
			if override, ok := fx.OtherOverrides[id]; ok {
				resp = override
			}
		default:
			resp = fixtureResponse{Status: http.StatusUnauthorized, Body: `{"error":"no token"}`}
		}

		w.WriteHeader(resp.Status)
		_, _ = w.Write([]byte(resp.Body))
	}))
}

func TestIDORDetector(t *testing.T) {
	cases := []struct {
		name           string
		fixture        string
		heuristicOnly  bool // pass "" for ownerToken, forcing heuristic mode regardless of the fixture's tokens
		wantFindings   int
		wantConfidence string // asserted on every finding, when non-empty
	}{
		{name: "clean baseline, no leak", fixture: "idor_clean_baseline.json", wantFindings: 0},
		{name: "classic IDOR", fixture: "idor_classic.json", wantFindings: 1, wantConfidence: "high"},
		{name: "server error, not a leak", fixture: "idor_server_error.json", wantFindings: 0},
		{name: "broken endpoint, not IDOR", fixture: "idor_broken_endpoint.json", wantFindings: 0},
		{name: "insufficient samples falls back to heuristic", fixture: "idor_insufficient_samples.json", wantFindings: 0},
		{name: "no consistent denial pattern falls back to heuristic", fixture: "idor_no_consistent_pattern.json", wantFindings: 10, wantConfidence: "low"},
		{name: "heuristic mode, uniform content", fixture: "idor_heuristic_uniform.json", heuristicOnly: true, wantFindings: 0},
		{name: "heuristic mode, differing content", fixture: "idor_heuristic_differing.json", heuristicOnly: true, wantFindings: 1, wantConfidence: "low"},
		{name: "heuristic mode, legitimately varied public content", fixture: "idor_heuristic_varied.json", heuristicOnly: true, wantFindings: 4, wantConfidence: "low"},
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
			strategy := idor.SequentialIntStrategy{Start: 1, End: fx.NumIDs}
			detector := idor.New(client, strategy)

			ownerToken := fx.OwnerToken
			if tc.heuristicOnly {
				ownerToken = ""
			}

			findings, err := detector.Run(context.Background(), srv.URL+"/api/users/{{id}}", ownerToken, fx.OtherToken)
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

// TestIDORDetector_AuthHeaderOption proves idor.WithAuthHeader controls which
// header carries the token and how its value is shaped — the mechanism
// docs/10-implementation-plan-ph1b.md's Future Enhancement #6 adds to unlock
// vAPI ("Authorization-Token: base64(user:pass)", no "Bearer" prefix) as a
// second real IDOR target beyond crAPI's plain Bearer-token scheme.
func TestIDORDetector_AuthHeaderOption(t *testing.T) {
	const token = "sometoken"

	cases := []struct {
		name        string
		opts        []idor.Option
		wantHeader  string
		wantValue   string
		otherHeader string // asserted absent (empty) when non-empty
	}{
		{
			name:       "no options: default Authorization: Bearer <token>",
			opts:       nil,
			wantHeader: "Authorization",
			wantValue:  "Bearer " + token,
		},
		{
			name:       "vAPI shape: custom header, no Bearer prefix",
			opts:       []idor.Option{idor.WithAuthHeader("Authorization-Token", "{token}")},
			wantHeader: "Authorization-Token",
			wantValue:  token,
		},
		{
			name:        "partial override: name only, format stays default",
			opts:        []idor.Option{idor.WithAuthHeader("X-Auth", "")},
			wantHeader:  "X-Auth",
			wantValue:   "Bearer " + token,
			otherHeader: "Authorization",
		},
		{
			name:       "partial override: format only, name stays default",
			opts:       []idor.Option{idor.WithAuthHeader("", "Token {token}")},
			wantHeader: "Authorization",
			wantValue:  "Token " + token,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotValue string
			var gotOtherAbsent bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotValue = r.Header.Get(tc.wantHeader)
				if tc.otherHeader != "" {
					gotOtherAbsent = r.Header.Get(tc.otherHeader) == ""
				}
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"denied"}`))
			}))
			defer srv.Close()

			client := httpclient.New(httpclient.Config{
				Timeout:             5 * time.Second,
				MaxRedirects:        5,
				MaxIdleConnsPerHost: 10,
			})
			strategy := idor.SequentialIntStrategy{Start: 1, End: 1}
			detector := idor.New(client, strategy, tc.opts...)

			// Heuristic mode (single token) is enough here — this test only
			// inspects the outgoing request header, not detection logic.
			_, err := detector.Run(context.Background(), srv.URL+"/api/users/{{id}}", token, "")
			require.NoError(t, err)

			assert.Equal(t, tc.wantValue, gotValue)
			if tc.otherHeader != "" {
				assert.True(t, gotOtherAbsent, "expected %s header to be absent", tc.otherHeader)
			}
		})
	}
}

// TestIDORDetector_TemplatePreview proves WithTemplatePreview fires exactly
// one extra preflight GET, logged (not a Finding), before Run's real loop —
// docs/14-implementation-plan-ph5.md Step 7's fix for "a wrong
// EndpointTemplate silently yields zero findings with no validation catching
// it." Disabled (the default) produces no preview log line at all.
func TestIDORDetector_TemplatePreview(t *testing.T) {
	fx := loadIDORFixture(t, "idor_classic.json")
	srv := newFixtureServer(t, fx)
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
	strategy := idor.SequentialIntStrategy{Start: 1, End: fx.NumIDs}

	t.Run("enabled: exactly one info-level preview log line", func(t *testing.T) {
		var logs []string
		detector := idor.New(client, strategy,
			idor.WithTemplatePreview(true),
			idor.WithLogCallback(func(level, msg string) { logs = append(logs, level+": "+msg) }),
		)

		_, err := detector.Run(context.Background(), srv.URL+"/api/users/{{id}}", fx.OwnerToken, fx.OtherToken)
		require.NoError(t, err)

		require.Len(t, logs, 1)
		assert.Contains(t, logs[0], "info:")
		assert.Contains(t, logs[0], "idor preview:")
		assert.Contains(t, logs[0], "status")
	})

	t.Run("disabled (default): no preview log line", func(t *testing.T) {
		var logs []string
		detector := idor.New(client, strategy,
			idor.WithLogCallback(func(level, msg string) { logs = append(logs, level+": "+msg) }),
		)

		_, err := detector.Run(context.Background(), srv.URL+"/api/users/{{id}}", fx.OwnerToken, fx.OtherToken)
		require.NoError(t, err)

		assert.Empty(t, logs)
	})
}
