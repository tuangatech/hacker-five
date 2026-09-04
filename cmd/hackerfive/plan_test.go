package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

func TestNewPlanCmd_MissingTarget_ReturnsError(t *testing.T) {
	cmd := newPlanCmd(&rootFlags{})
	cmd.SetArgs([]string{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--targets is required")
}

func TestNewPlanCmd_InvalidDepth_ReturnsError(t *testing.T) {
	cmd := newPlanCmd(&rootFlags{})
	cmd.SetArgs([]string{"--targets", "http://example.com", "--recon-depth", "bogus"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--recon-depth must be")
}

func TestNewPlanCmd_InvalidScopeFile_ReturnsError(t *testing.T) {
	cmd := newPlanCmd(&rootFlags{})
	cmd.SetArgs([]string{"--targets", "http://example.com", "--scope", filepath.Join(t.TempDir(), "does-not-exist.txt")})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing --scope")
}

// TestNewPlanCmd_HappyPath_MissingTemplateIndexDegradesToWarning drives the
// full recon+decision-engine pipeline against a local httptest.Server (same
// isolation as recon_test.go's equivalent — see
// isolateFromInstalledReconBinaries's own doc comment), using
// --recon-depth passive to skip the shelled active-probe binaries too, and
// a deliberately-missing --template-index to exercise the documented
// "missing index degrades to skipping template-tag matching, not a hard
// failure" path rather than requiring a real templates/index.json fixture.
func TestNewPlanCmd_HappyPath_MissingTemplateIndexDegradesToWarning(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cmd := newPlanCmd(&rootFlags{})
	cmd.SetArgs([]string{
		"--targets", srv.URL,
		"--recon-depth", "passive",
		"--scope", writeScopeFile(t, srv.URL),
		"--template-index", filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	require.NoError(t, cmd.Execute())
	assert.Contains(t, errOut.String(), "template-tag matching skipped")

	var tree agenttask.PlanTree
	require.NoError(t, json.Unmarshal(out.Bytes(), &tree))
}

func TestNewPlanCmd_OutputFlag_WritesToFile(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	outPath := filepath.Join(t.TempDir(), "plan.json")
	flags := &rootFlags{output: outPath}
	cmd := newPlanCmd(flags)
	cmd.SetArgs([]string{
		"--targets", srv.URL,
		"--recon-depth", "passive",
		"--scope", writeScopeFile(t, srv.URL),
		"--template-index", filepath.Join(t.TempDir(), "does-not-exist.json"),
	})

	require.NoError(t, cmd.Execute())

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)
	var tree agenttask.PlanTree
	require.NoError(t, json.Unmarshal(data, &tree))
}

func TestNewPlanCmd_FlagDefaults(t *testing.T) {
	cmd := newPlanCmd(&rootFlags{})

	depth := cmd.Flags().Lookup("recon-depth")
	require.NotNil(t, depth)
	assert.Equal(t, "active", depth.DefValue)

	idx := cmd.Flags().Lookup("template-index")
	require.NotNil(t, idx)
	assert.Equal(t, "templates/index.json", idx.DefValue)
}
