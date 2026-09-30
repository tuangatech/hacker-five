package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
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

// TestIDORDetector_RandomUUIDStrategy_Hit covers LT-95 (docs/follow-up.md):
// a UUID-keyed BOLA (e.g. crAPI's vehicle/{vehicleId}/location) is
// unreachable by SequentialIntStrategy's int-only range. Here both accounts
// can access the seed vehicle's location while every random filler UUID is
// correctly denied — RandomUUIDStrategy's fillers establish the "denied"
// baseline exactly as an int-range scan would, and the one real seed sample
// deviates from it.
func TestIDORDetector_RandomUUIDStrategy_Hit(t *testing.T) {
	const seedID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, seedID) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"lat":1.23,"lon":4.56}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
	strategy := idor.RandomUUIDStrategy{Seed: seedID, FillerCount: 20}
	detector := idor.New(client, strategy)

	findings, err := detector.Run(context.Background(), srv.URL+"/vehicle/{{id}}/location", "owner-token", "other-token")
	require.NoError(t, err)

	require.Len(t, findings, 1)
	assert.Equal(t, "idor", findings[0].Type)
	assert.Equal(t, "high", findings[0].Confidence)
}

// TestIDORDetector_RandomUUIDStrategy_NoFinding_ProperlyProtected is the
// same seed/filler shape, but otherToken is correctly denied at the seed ID
// too — a properly-authorized endpoint must not flag.
func TestIDORDetector_RandomUUIDStrategy_NoFinding_ProperlyProtected(t *testing.T) {
	const seedID = "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if path.Base(r.URL.Path) == seedID && r.Header.Get("Authorization") == "Bearer owner-token" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"lat":1.23,"lon":4.56}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
	strategy := idor.RandomUUIDStrategy{Seed: seedID, FillerCount: 20}
	detector := idor.New(client, strategy)

	findings, err := detector.Run(context.Background(), srv.URL+"/vehicle/{{id}}/location", "owner-token", "other-token")
	require.NoError(t, err)
	assert.Empty(t, findings)
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

// TestIDORDetector_PublicPaginationDenylist covers LT-198 (docs/follow-up.md):
// single-token heuristic mode fired 19 near-identical findings across a public
// blog's pagination/post URLs (WordPress ?p= / ?paged= / /page/<n>) live on
// nettix.com.pe. That content is public by design — there is no authorization
// boundary for the heuristic to have found bypassed — so a differing-content
// signal there is noise, not IDOR. The denylist suppresses such a deviation
// only when the sample is a public 2xx; a non-2xx differential on the same
// parameter is still surfaced, and the suppression is deliberately narrow.
func TestIDORDetector_PublicPaginationDenylist(t *testing.T) {
	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
	strategy := idor.SequentialIntStrategy{Start: 1, End: 5}

	// uniquePerIDServer returns a distinct-length 200 body for every id (well
	// beyond Signature's 5% body-size tolerance), so plain heuristic mode would
	// otherwise flag every deviation from the majority.
	uniquePerIDServer := func(idFrom func(r *http.Request) string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := idFrom(r)
			n := 1
			if len(id) > 0 {
				n = int(id[0]-'0') + 1
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("public-blog-content ", n*20)))
		}))
	}
	queryP := func(r *http.Request) string { return r.URL.Query().Get("p") }
	pathID := func(r *http.Request) string { return path.Base(r.URL.Path) }

	t.Run("?p=<n> public posts suppressed", func(t *testing.T) {
		srv := uniquePerIDServer(queryP)
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/?p={{id}}", "", "")
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("/page/<n> pretty pagination suppressed", func(t *testing.T) {
		srv := uniquePerIDServer(pathID)
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/page/{{id}}", "", "")
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("non-denylist param still flagged (suppression stays narrow)", func(t *testing.T) {
		srv := uniquePerIDServer(pathID)
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/api/orders/{{id}}", "", "")
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("non-2xx differential on a denylist param is kept", func(t *testing.T) {
		// Uniform public 200 for every id except id=3, which is 403 — a real
		// access differential the denylist must not swallow.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("p") == "3" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"forbidden"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("uniform public listing page"))
		}))
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/?p={{id}}", "", "")
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "403", findings[0].Evidence["status"])
	})
}

// TestIDORDetector_PublicCMSContentSuppression covers LT-199 (docs/follow-up.md):
// single-token heuristic mode flooded ~30 findings across a public DokuWiki's
// `doku.php?id=<page>` URLs live on wiki.nettix.com.pe — every wiki page
// legitimately differs in size/content, which the bare signature diff cannot
// tell apart from an access-control differential, and DokuWiki content is public
// by design (no per-user boundary). The fix recognizes the CMS front-controller
// script (`doku.php`) rather than denylisting `id` itself: `id` is *the*
// canonical IDOR parameter, so an `id`-keyed enumeration on any other path must
// still flag, and a non-2xx differential on the wiki (a DokuWiki ACL) is kept.
func TestIDORDetector_PublicCMSContentSuppression(t *testing.T) {
	client := httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
	strategy := idor.SequentialIntStrategy{Start: 1, End: 5}

	// queryIDServer returns a distinct-length 200 body per `?id=<n>` (well beyond
	// Signature's 5% body-size tolerance), like a wiki serving different pages.
	queryIDServer := func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Query().Get("id")
			n := 1
			if len(id) > 0 {
				n = int(id[0]-'0') + 1
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("public-wiki-page-content ", n*20)))
		}))
	}

	t.Run("doku.php?id=<page> public wiki suppressed", func(t *testing.T) {
		srv := queryIDServer()
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/lib/exe/doku.php?id={{id}}", "", "")
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("numeric path segment under a DokuWiki code dir suppressed", func(t *testing.T) {
		// /lib/plugins/captcha/<n>: a distinct public 200 per trailing segment,
		// live-observed on a public DokuWiki right after LT-199.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := int(r.URL.Path[len(r.URL.Path)-1]-'0') + 1
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("public-wiki-page-content ", n*20)))
		}))
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/lib/plugins/captcha/{{id}}", "", "")
		require.NoError(t, err)
		assert.Empty(t, findings)
	})

	t.Run("numeric path segment outside a CMS code dir still flagged", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.URL.Path[len(r.URL.Path)-1] - '0'
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("record-body ", (int(id)+1)*20)))
		}))
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/api/orders/{{id}}", "", "")
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("id on a non-CMS path still flagged (id is never denylisted)", func(t *testing.T) {
		srv := queryIDServer()
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/api/resource?id={{id}}", "", "")
		require.NoError(t, err)
		assert.NotEmpty(t, findings)
	})

	t.Run("non-2xx differential on the CMS script is kept", func(t *testing.T) {
		// Uniform public 200 for every page except id=3, which is 403 — a real
		// DokuWiki-ACL differential the suppression must not swallow.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("id") == "3" {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("access denied"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("uniform public wiki page"))
		}))
		defer srv.Close()
		findings, err := idor.New(client, strategy).Run(context.Background(), srv.URL+"/lib/exe/doku.php?id={{id}}", "", "")
		require.NoError(t, err)
		require.Len(t, findings, 1)
		assert.Equal(t, "403", findings[0].Evidence["status"])
	})
}
