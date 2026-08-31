package unit

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/oob"
)

// TestOOBClient_SelfIssuedCallback_RealServer proves pkg/oob works
// standalone against a real self-hosted Interactsh-protocol server —
// docs/91-research-recon-phase.md's R1b DoD bullet ("OOB callback
// infrastructure... generates a correlation URL and confirms a self-issued
// test callback is received — standalone, not yet wired into any
// detector"). Skips (not fails) unless OOB_SERVER_URL is set, same
// skip-not-fail convention as every other live-target test in this repo
// (e.g. tests/integration).
func TestOOBClient_SelfIssuedCallback_RealServer(t *testing.T) {
	serverURL := os.Getenv("OOB_SERVER_URL")
	if serverURL == "" {
		t.Skip("OOB_SERVER_URL not set — skipping (see docs/20-setup-testing-targets-macos.md §6)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := oob.NewClient(ctx, &http.Client{Timeout: 10 * time.Second}, serverURL)
	require.NoError(t, err)
	defer client.Deregister(context.Background())

	host, nonce := client.NewPayloadHost()
	payloadURL := "http://" + host + "/oob-self-test-probe"

	// This is the "self-issued" half: the test process itself (on the host's
	// own network, per docs/20-setup-testing-targets-macos.md §6's own
	// caveat about Dockerized targets not sharing that network) makes the
	// outbound request a real vulnerable target would otherwise have to make
	// for this callback to ever fire.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, payloadURL, nil)
	require.NoError(t, err)
	resp, doErr := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if doErr == nil {
		_ = resp.Body.Close()
	}
	// doErr is expected here in the general case (nothing serves that host
	// beyond the OOB server recording the connection attempt) — what matters
	// is Poll observing the interaction below, not this response.

	var interactions []oob.Interaction
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		interactions, err = client.Poll(ctx)
		require.NoError(t, err)
		if len(interactions) > 0 {
			break
		}
		time.Sleep(1 * time.Second)
	}

	require.NotEmpty(t, interactions, "expected the self-issued request to %s to show up via Poll within the test's timeout", payloadURL)

	found := false
	for _, it := range interactions {
		if strings.Contains(it.FullID, nonce) || strings.Contains(it.UniqueID, nonce) {
			found = true
			break
		}
	}
	require.True(t, found, "no received interaction correlated back to this probe's nonce %q: %+v", nonce, interactions)
}
