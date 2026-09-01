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

func TestScanHistory_NoScansYet(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(ts.URL + "/scans")
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

	resp, err := client.Get(ts.URL + "/")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	jar, ok := client.Jar.(*cookiejar.Jar)
	require.True(t, ok)
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	form := url.Values{
		"csrf_token":    {csrfVal},
		"target":        {targetURL},
		"run_misconfig": {"on"},
		"authorized":    {"on"},
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

func TestScanHistory_ListStartedScansMostRecentFirst(t *testing.T) {
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

	histResp, err := http.Get(ts.URL + "/scans")
	require.NoError(t, err)
	histBody, err := io.ReadAll(histResp.Body)
	require.NoError(t, err)
	require.NoError(t, histResp.Body.Close())
	assert.Contains(t, string(histBody), firstID)
	assert.Contains(t, string(histBody), secondID)
	// most-recent-first: secondID's row must appear before firstID's
	assert.Less(t, indexOf(t, string(histBody), secondID), indexOf(t, string(histBody), firstID))
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
