package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRootCmd_RegistersEverySubcommand(t *testing.T) {
	cmd := newRootCmd()

	want := []string{"scan", "templates", "serve", "report", "recon", "plan", "mcp-serve"}
	var got []string
	for _, child := range cmd.Commands() {
		got = append(got, child.Name())
	}
	for _, name := range want {
		assert.Contains(t, got, name)
	}
}

func TestNewRootCmd_PersistentFlagsRegisteredWithDefaults(t *testing.T) {
	cmd := newRootCmd()

	proxy := cmd.PersistentFlags().Lookup("proxy")
	require.NotNil(t, proxy, "--proxy must be registered")
	assert.Equal(t, "", proxy.DefValue)

	timeout := cmd.PersistentFlags().Lookup("timeout")
	require.NotNil(t, timeout, "--timeout must be registered")
	assert.Equal(t, "30s", timeout.DefValue)

	output := cmd.PersistentFlags().Lookup("output")
	require.NotNil(t, output, "--output/-o must be registered")
	assert.Equal(t, "o", output.Shorthand)
}

func TestNewRootCmd_UseAndVersionSet(t *testing.T) {
	cmd := newRootCmd()
	assert.Equal(t, "hackerfive", cmd.Use)
	assert.NotEmpty(t, cmd.Version, "Version must be non-empty to enable Cobra's built-in --version flag")
	assert.True(t, cmd.SilenceUsage)
}
