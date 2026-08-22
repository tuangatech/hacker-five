//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/misconfig"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// TestMisconfigDVWA runs the misconfiguration detector against a live DVWA
// instance. Opt-in: skipped unless DVWA_BASE_URL is set (see
// docs/04-environment-and-testing.md for bringing DVWA up via Docker).
func TestMisconfigDVWA(t *testing.T) {
	baseURL := os.Getenv("DVWA_BASE_URL")
	if baseURL == "" {
		t.Skip("set DVWA_BASE_URL to run this test, e.g. http://localhost")
	}

	client := httpclient.New(httpclient.Config{
		Timeout:             10 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	}, httpclient.WithRetry(3, 500*time.Millisecond))

	detector := misconfig.New(client)
	findings, err := detector.Run(context.Background(), baseURL, "")
	require.NoError(t, err)

	require.NotEmpty(t, findings, "expected at least one misconfiguration finding against DVWA")
	for _, f := range findings {
		require.Equal(t, "misconfig", f.Type)
	}
}
