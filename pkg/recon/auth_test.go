package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCredential(t *testing.T) {
	c, err := NewCredential("app.example.com:8443", "tok", "", "")
	require.NoError(t, err)
	assert.Equal(t, "https://app.example.com:8443", c.Origin, "a scheme-less target gets https, as recon does")
	assert.Equal(t, map[string]string{"Authorization": "Bearer tok"}, c.Header)

	c, err = NewCredential("http://127.0.0.1:8888", "tok", "Cookie", "session={token}")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"Cookie": "session=tok"}, c.Header, "a cookie session is just another header name and format")
	assert.Equal(t, []string{"Cookie"}, c.HeaderNames())
	assert.NotContains(t, c.Note(), "tok", "the note names the header, never the token")
	assert.Contains(t, c.Note(), "http://127.0.0.1:8888")

	_, err = NewCredential("http://x", "", "", "")
	assert.ErrorContains(t, err, "needs an owner token")
	_, err = NewCredential("http://x", "tok", "", "Bearer")
	assert.ErrorContains(t, err, "{token}")
}
