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
)

func TestDashboard_NoScansYet(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "No scans yet")
}

// startTestScan drives the same GET-CSRF/POST-form flow
// TestEndToEnd_StartScan_ProducesRealFindings uses, returning the job's ID
// from the HX-Push-Url response header.
func startTestScan(t *testing.T, client *http.Client, ts *httptest.Server, targetURL string) string {
	t.Helper()

	resp, err := client.Get(ts.URL + "/scans/new")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	jar, ok := client.Jar.(*cookiejar.Jar)
	require.True(t, ok)
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	form := url.Values{
		"csrf_token": {csrfVal},
		"targets":    {targetURL},
		"detector":   {"misconfig"},
		"authorized": {"on"},
	}
	resp, err = client.PostForm(ts.URL+"/scans", form)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)

	jobURL := resp.Header.Get("HX-Push-Url")
	require.NotEmpty(t, jobURL)
	id := jobURL[len("/scans/"):]
	require.NotEmpty(t, id)
	return id
}

func TestDashboardAndScanHistory_ListStartedScans(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(target.Close)

	ts := newTestServer(t)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	firstID := startTestScan(t, client, ts, target.URL)
	secondID := startTestScan(t, client, ts, target.URL)

	dashResp, err := http.Get(ts.URL + "/")
	require.NoError(t, err)
	dashBody, err := io.ReadAll(dashResp.Body)
	require.NoError(t, err)
	require.NoError(t, dashResp.Body.Close())
	assert.Contains(t, string(dashBody), firstID)
	assert.Contains(t, string(dashBody), secondID)
	// most-recent-first: secondID's row must appear before firstID's
	assert.Less(t, indexOf(t, string(dashBody), secondID), indexOf(t, string(dashBody), firstID))

	histResp, err := http.Get(ts.URL + "/scans")
	require.NoError(t, err)
	histBody, err := io.ReadAll(histResp.Body)
	require.NoError(t, err)
	require.NoError(t, histResp.Body.Close())
	assert.Contains(t, string(histBody), firstID)
	assert.Contains(t, string(histBody), secondID)
}

func indexOf(t *testing.T, haystack, needle string) int {
	t.Helper()
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	t.Fatalf("expected %q to contain %q", haystack, needle)
	return -1
}
