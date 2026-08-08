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

	client := httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))

	strategy := idor.SequentialIntStrategy{Start: 1, End: 100}
	detector := idor.New(client, strategy)

	endpointTemplate := baseURL + "/identity/api/v2/user/dashboard/{{id}}"
	findings, err := detector.Run(context.Background(), endpointTemplate, ownerToken, otherToken)
	require.NoError(t, err)

	require.NotEmpty(t, findings, "expected at least one IDOR finding against crAPI's dashboard endpoint")
	for _, f := range findings {
		assert.Equal(t, "idor", f.Type)
		assert.Equal(t, "high", f.Confidence)
	}
}
