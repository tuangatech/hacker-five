package webui

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLaunchSubmissionRequest builds a POST /scans *http.Request from form,
// already form-parsed — the same construction
// TestParseLaunchSubmission_SSRFOOBServers_DefaultAndClearable uses.
func newLaunchSubmissionRequest(t *testing.T, form url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	return req
}

// TestParseLaunchSubmission_UseLLMAgent_Parsed confirms the two new
// checkboxes (docs/93 M4) parse the same "on"/absent convention as every
// other launch-form checkbox, independently of each other.
func TestParseLaunchSubmission_UseLLMAgent_Parsed(t *testing.T) {
	req := newLaunchSubmissionRequest(t, url.Values{
		"target":                  {"https://example.com"},
		"authorized":              {"on"},
		"use_llm_agent":           {"on"},
		"allow_llm_agent_scripts": {"on"},
	})

	got, _, _, errs := parseLaunchSubmission(req)
	require.Empty(t, errs)
	assert.True(t, got.UseLLMAgent)
	assert.True(t, got.AllowLLMAgentScripts)
}

// TestParseLaunchSubmission_UseLLMAgent_DefaultsOff confirms both checkboxes
// default false when absent — the independently-scoped opt-in posture
// AllowWrites already uses.
func TestParseLaunchSubmission_UseLLMAgent_DefaultsOff(t *testing.T) {
	req := newLaunchSubmissionRequest(t, url.Values{"target": {"https://example.com"}, "authorized": {"on"}})

	got, _, _, errs := parseLaunchSubmission(req)
	require.Empty(t, errs)
	assert.False(t, got.UseLLMAgent)
	assert.False(t, got.AllowLLMAgentScripts)
}

// TestRunLaunchAgentJob_NoLLMConfigured_FailsCleanly is
// pkg/orchestrator.Run's hard-requirement surfaced through the Web UI:
// unlike the plain scan/plan flow's --llm-assist (which degrades), an
// agent-mode job with no LLM tier configured fails outright — before any
// recon/network activity, so this test needs no live target.
func TestRunLaunchAgentJob_NoLLMConfigured_FailsCleanly(t *testing.T) {
	forceNoLLMTier(t)
	job := newTestJob("job1")
	job.SetRunning()

	runLaunchAgentJob(job, LaunchFormData{Target: "https://example.com", UseLLMAgent: true, RateLimit: 10, Concurrency: 10})

	snap := job.Snapshot()
	assert.Equal(t, StatusFailed, snap.Status)
	require.NotEmpty(t, snap.Logs)
	found := false
	for _, l := range snap.Logs {
		if strings.Contains(l.Msg, "LLM tier") {
			found = true
		}
	}
	assert.True(t, found, "expected a log line explaining the missing LLM tier, got: %+v", snap.Logs)
}

// TestStartLaunch_UseLLMAgent_RoutesToAgentJob confirms the "Use LLM agent"
// checkbox on the real POST /scans path actually reaches runLaunchAgentJob
// (not the checked-detector-tab flow) — forceNoLLMTier makes this
// deterministic and fast (no live recon needed, since the LLM-tier check
// happens before any network activity).
func TestStartLaunch_UseLLMAgent_RoutesToAgentJob(t *testing.T) {
	forceNoLLMTier(t)
	ts, _ := newTestServerHandlers(t)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	form := url.Values{
		"csrf_token":    {csrfVal},
		"target":        {"https://example.com"},
		"authorized":    {"on"},
		"use_llm_agent": {"on"},
	}
	resp, err := client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	redirect := resp.Header.Get("HX-Push-Url")
	require.Regexp(t, `^/scans/[0-9a-f]+$`, redirect)

	require.Eventually(t, func() bool {
		r, err := client.Get(ts.URL + redirect)
		if err != nil {
			return false
		}
		b, err := io.ReadAll(r.Body)
		_ = r.Body.Close()
		return err == nil && strings.Contains(string(b), "LLM tier")
	}, 5*time.Second, 50*time.Millisecond, "expected the agent job to fail fast on a missing LLM tier")
}
