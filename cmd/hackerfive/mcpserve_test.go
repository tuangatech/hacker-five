package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/mcpserver"
)

func TestResolveAgency(t *testing.T) {
	cases := []struct {
		in      string
		want    mcpserver.Agency
		wantErr bool
	}{
		{"", mcpserver.AgencyFull, false},
		{"full", mcpserver.AgencyFull, false},
		{"FULL", mcpserver.AgencyFull, false},
		{"readonly", mcpserver.AgencyReadOnly, false},
		{"read-only", mcpserver.AgencyReadOnly, false},
		{" ReadOnly ", mcpserver.AgencyReadOnly, false},
		{"rw", "", true},
		{"admin", "", true},
	}
	for _, c := range cases {
		got, err := resolveAgency(c.in)
		if c.wantErr {
			require.Error(t, err, "input %q", c.in)
			continue
		}
		require.NoError(t, err, "input %q", c.in)
		assert.Equal(t, c.want, got, "input %q", c.in)
	}
}

func TestNewMCPServeCmd_AgencyFlagRegistered(t *testing.T) {
	cmd := newMCPServeCmd()
	f := cmd.Flags().Lookup("agency")
	require.NotNil(t, f, "--agency must be registered")
	assert.Equal(t, "", f.DefValue, "empty default resolves to full")
}
