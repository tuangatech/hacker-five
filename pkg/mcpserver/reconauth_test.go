package mcpserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// LT-187: only the operator's environment turns authenticated recon on, and a
// switch that is on without a token says recon was NOT authenticated.
func TestReconAuthParts(t *testing.T) {
	t.Setenv("HACKERFIVE_AUTH_TOKEN", "")

	t.Setenv(reconAuthEnv, "")
	mws, opts, note := reconAuthParts("http://x.test", "tok")
	assert.Empty(t, mws)
	assert.Empty(t, opts)
	assert.Empty(t, note, "with the operator switch off, a token supplied to plan must not reach recon")

	t.Setenv(reconAuthEnv, "1")
	mws, opts, note = reconAuthParts("http://x.test", "tok")
	require.Len(t, mws, 1)
	require.Len(t, opts, 1)
	assert.Contains(t, note, "recon-auth: recon requests to http://x.test carry the Authorization header")
	assert.NotContains(t, note, "tok", "the note never carries the token")

	t.Setenv("HACKERFIVE_AUTH_TOKEN", "from-env")
	mws, _, _ = reconAuthParts("http://x.test", "")
	assert.Len(t, mws, 1, "the token falls back to HACKERFIVE_AUTH_TOKEN")

	t.Setenv("HACKERFIVE_AUTH_TOKEN", "")
	mws, opts, note = reconAuthParts("http://x.test", "")
	assert.Empty(t, mws)
	assert.Empty(t, opts)
	assert.Contains(t, note, "recon ran unauthenticated")
}
