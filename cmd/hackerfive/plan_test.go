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

// TestNewPlanCmd_NoScopeFile_ReturnsError confirms P2-6's hard-fail
// (docs/follow-up.md): plan wraps recon's own discovery, so unlike scan's
// exact --targets list, it can silently wander into whatever recon finds —
// refuses outright unless --scope or --allow-no-scope is given.
func TestNewPlanCmd_NoScopeFile_ReturnsError(t *testing.T) {
	cmd := newPlanCmd(&rootFlags{})
	cmd.SetArgs([]string{"--targets", "http://example.com"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--scope is required")
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

	llmAssist := cmd.Flags().Lookup("llm-assist")
	require.NotNil(t, llmAssist)
	assert.Equal(t, "false", llmAssist.DefValue, "P2-4: zero LLM calls must stay the default, matching plan's own no-agent-required proof")
}

// TestNewPlanCmd_LLMAssist_NoTierConfigured_DegradesToEscalationWarning
// confirms P2-4's --llm-assist flag doesn't hard-fail the whole command when
// no LLM tier is reachable (llmfallback.New() returning ErrNoTierAvailable
// degrades every unresolved leaf to an escalation, same as every other
// caller of ResolveTreeLeaves) — forceNoLLMTier makes that deterministic
// regardless of what's actually running on the test machine.
func TestNewPlanCmd_LLMAssist_NoTierConfigured_DegradesToEscalationWarning(t *testing.T) {
	isolateFromInstalledReconBinaries(t)
	forceNoLLMTier(t)
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
		"--llm-assist",
	})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	require.NoError(t, cmd.Execute())

	var tree agenttask.PlanTree
	require.NoError(t, json.Unmarshal(out.Bytes(), &tree))
}

// forceNoLLMTier makes llmfallback.New() deterministically fail (fb == nil,
// ErrNoTierAvailable) regardless of what's actually running on the test
// machine — same technique pkg/webui/handlers_plan_test.go and
// pkg/mcpserver/tools_triage_test.go already use.
func forceNoLLMTier(t *testing.T) {
	t.Helper()
	t.Setenv("HACKERFIVE_LOCAL_MODEL_URL", "http://127.0.0.1:1/unreachable")
	t.Setenv("OPENROUTER_API_KEY", "")
}
