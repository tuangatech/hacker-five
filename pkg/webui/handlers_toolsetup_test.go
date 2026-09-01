package webui

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/toolsync"
)

func TestNewReconForm_ShowsToolSetupPanel_NoneInstalled(t *testing.T) {
	ts := newTestServer(t) // isolates DefaultInstallDir to an empty temp dir

	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	html := string(body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, html, "Recon Tools")
	for _, tool := range toolsync.Tools {
		assert.Contains(t, html, tool.Name)
	}
	assert.Contains(t, html, "Setup now")
}

// TestSetupTools_FailsCleanly_Renders200NotError points Install at a server
// that 404s every release-metadata request — every tool fails to install,
// same as a real offline/rate-limited run would — and confirms the handler
// still follows syncTemplates' own "a failed operation is a valid,
// successfully-processed result" design (handlers_templates.go), not a
// 4xx/5xx.
func TestSetupTools_FailsCleanly_Renders200NotError(t *testing.T) {
	ts := newTestServer(t)

	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(failSrv.Close)
	restore := toolsync.SetGitHubAPIBaseForTesting(failSrv.URL)
	t.Cleanup(restore)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	resp, err := client.PostForm(ts.URL+"/recon/setup", url.Values{"csrf_token": {csrfVal}})
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode, "a failed install is still a successfully-processed request — it must not be a 4xx/5xx")
	assert.Contains(t, string(body), "Setup failed")
	for _, tool := range toolsync.Tools {
		assert.Contains(t, string(body), tool.Name, "every tool's own failure should be visible, not swallowed into a generic message")
	}
}

func TestSetupTools_MissingCSRFCookie_Rejected(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.PostForm(ts.URL+"/recon/setup", url.Values{"csrf_token": {"whatever"}})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.NoError(t, resp.Body.Close())
}
