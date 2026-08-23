//go:build integration

// Package integration holds tests that run against a live vulnerable target
// rather than mocks, gated behind the "integration" build tag.
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// newCRAPIDetector builds the same client/strategy/endpoint shape both
// TestIDORAgainstCRAPI and TestIDORAgainstCRAPI_NoFalsePositive use, so a
// live positive and a live negative run stay identical apart from the token
// under test.
func newCRAPIDetector(baseURL string) (*idor.Detector, string) {
	client := httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))

	strategy := idor.SequentialIntStrategy{Start: 1, End: 100}
	detector := idor.New(client, strategy)

	// GetReportView (services/workshop/crapi/mechanic/views.py) fetches a
	// ServiceRequest by numeric id with no ownership check beyond requiring
	// any valid JWT — a real BOLA. Requires at least one report to already
	// exist (submitted via the "Contact Mechanic" flow in crAPI's web UI, or
	// its unauthenticated GET .../mechanic/receive_report endpoint) — a
	// fresh, never-used crAPI instance has none, and the scan finds nothing.
	endpointTemplate := baseURL + "/workshop/api/mechanic/mechanic_report?report_id={{id}}"
	return detector, endpointTemplate
}

// TestIDORAgainstCRAPI runs the real IDOR detector against a live crAPI
// instance. It's opt-in: skipped unless CRAPI_BASE_URL and both account
// tokens are set (see tests/integration/scripts/crapi_setup.sh). Per
// docs/09-implementation-plan-ph1.md's integration test setup, crAPI is a
// separate target reached only over HTTP — never given filesystem/exec
// access to HackerFive.
func TestIDORAgainstCRAPI(t *testing.T) {
	baseURL := os.Getenv("CRAPI_BASE_URL")
	ownerToken := os.Getenv("CRAPI_OWNER_TOKEN")
	otherToken := os.Getenv("CRAPI_OTHER_TOKEN")
	if baseURL == "" || ownerToken == "" || otherToken == "" {
		t.Skip("set CRAPI_BASE_URL, CRAPI_OWNER_TOKEN, and CRAPI_OTHER_TOKEN to run this test (see tests/integration/scripts/crapi_setup.sh)")
	}

	detector, endpointTemplate := newCRAPIDetector(baseURL)
	findings, err := detector.Run(context.Background(), endpointTemplate, ownerToken, otherToken)
	require.NoError(t, err)

	require.NotEmpty(t, findings, "expected at least one IDOR finding against crAPI's mechanic-report endpoint")
	for _, f := range findings {
		assert.Equal(t, "idor", f.Type)
		assert.Equal(t, "high", f.Confidence)
	}
}

// TestIDORAgainstCRAPI_NoFalsePositive is the negative-control counterpart to
// TestIDORAgainstCRAPI: it swaps otherToken for a syntactically-invalid one,
// so every ID (including the real report from the positive test) comes back
// 401 for otherToken instead of 200. The baseline established from those 401s
// is itself the "denied" signature, so the real report's ID is never
// Bypassed — this asserts the detector doesn't mistake a uniformly-broken
// account for a uniform absence of a leak (see detector.go's
// s.otherSig.StatusCode != http.StatusOK guard). Only CRAPI_BASE_URL and
// CRAPI_OWNER_TOKEN are required — the invalid token stands in for
// CRAPI_OTHER_TOKEN on purpose.
func TestIDORAgainstCRAPI_NoFalsePositive(t *testing.T) {
	baseURL := os.Getenv("CRAPI_BASE_URL")
	ownerToken := os.Getenv("CRAPI_OWNER_TOKEN")
	if baseURL == "" || ownerToken == "" {
		t.Skip("set CRAPI_BASE_URL and CRAPI_OWNER_TOKEN to run this test (see tests/integration/scripts/crapi_setup.sh)")
	}

	detector, endpointTemplate := newCRAPIDetector(baseURL)
	findings, err := detector.Run(context.Background(), endpointTemplate, ownerToken, "not-a-real-token")
	require.NoError(t, err)

	assert.Empty(t, findings, "an invalid otherToken must not be reported as an IDOR finding")
}
