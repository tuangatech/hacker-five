package unit

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scanner/vars"
)

// TestVarsRender_HyphenatedPlaceholder locks in a fix found while wiring up
// interactsh_ OOB support: placeholderPattern's original \w+ pattern cannot
// match a hyphen, so real Nuclei's own {{interactsh-url}} variable (the one
// common built-in with a hyphen in its name) used to pass straight through
// Render untouched — no error, just a request that sent the literal text
// "{{interactsh-url}}" instead of a real probe host.
func TestVarsRender_HyphenatedPlaceholder(t *testing.T) {
	out, err := vars.Render("cb={{interactsh-url}}", vars.Context{Vars: map[string]string{"interactsh-url": "abc123.oast.test"}})
	require.NoError(t, err)
	assert.Equal(t, "cb=abc123.oast.test", out)
}

// TestVarsRender_RootURLAliasesBaseURL and TestVarsRender_HostAliasesHostname
// lock in RootURL/Host support, also found missing while measuring how many
// real interactsh_-referencing synced-corpus templates would actually
// render end-to-end (docs/follow-up.md's OOB item) — both are common real
// Nuclei built-ins this project's Render had no case for at all, previously
// failing as "undefined variable".
func TestVarsRender_RootURLAliasesBaseURL(t *testing.T) {
	out, err := vars.Render("{{RootURL}}/x", vars.Context{BaseURL: "https://example.com"})
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/x", out)
}

func TestVarsRender_HostAliasesHostname(t *testing.T) {
	out, err := vars.Render("Host: {{Host}}", vars.Context{Hostname: "example.com:8443"})
	require.NoError(t, err)
	assert.Equal(t, "Host: example.com:8443", out)
}

// TestVarsRender_StillRejectsUndefinedPlaceholder guards against the
// hyphen-widening above accidentally turning Render permissive — an
// actually-undefined variable must still be a hard error, hyphen in the
// name or not.
func TestVarsRender_StillRejectsUndefinedPlaceholder(t *testing.T) {
	_, err := vars.Render("{{totally-undefined-thing}}", vars.Context{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "totally-undefined-thing")
}
