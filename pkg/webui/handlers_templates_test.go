package webui

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

// seedSyncedTemplate writes one real, loadable nuclei-format template into
// this test's synced-templates directory — the location
// templatesync.DefaultSyncDir() resolves to once newTestServer(t) has set
// XDG_CONFIG_HOME, so defaultWebTemplateDirsWithLabels' os.Stat check picks
// it up and labels it "synced". This sidesteps ./templates/ (the "bundled"
// dir), which is a relative path that resolves against `go test`'s
// per-package working directory, not the repo root — so it never actually
// contains real content under test, unlike a real running binary.
func seedSyncedTemplate(t *testing.T, id, tag string) {
	t.Helper()
	dir, err := templatesync.DefaultSyncDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	content := "id: " + id + "\ninfo:\n  name: " + id + "\n  severity: info\n  tags: " + tag + "\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/\"]\n    matchers:\n      - type: word\n        words: [\"ok\"]\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(content), 0o644))
}

func TestTemplatesPage_ListsSyncedEntries(t *testing.T) {
	ts := newTestServer(t)
	seedSyncedTemplate(t, "seeded-check", "exposed-panels")

	resp, err := http.Get(ts.URL + "/templates")
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), "seeded-check")
	assert.Contains(t, string(body), "synced", "the synced directory's entries must carry the synced source label")
}

func TestTemplateTable_TagFilter_NarrowsResults(t *testing.T) {
	ts := newTestServer(t)
	seedSyncedTemplate(t, "seeded-check", "exposed-panels")

	all, err := http.Get(ts.URL + "/templates/table")
	require.NoError(t, err)
	allBody, err := io.ReadAll(all.Body)
	require.NoError(t, err)
	require.NoError(t, all.Body.Close())
	assert.Contains(t, string(allBody), "seeded-check", "unfiltered table must show the seeded entry")

	filtered, err := http.Get(ts.URL + "/templates/table?" + url.Values{"tags": {"definitely-not-a-real-tag-xyz"}}.Encode())
	require.NoError(t, err)
	filteredBody, err := io.ReadAll(filtered.Body)
	require.NoError(t, err)
	require.NoError(t, filtered.Body.Close())

	assert.Equal(t, http.StatusOK, filtered.StatusCode)
	assert.NotContains(t, string(filteredBody), "seeded-check", "an unmatched tag filter must exclude the seeded entry")
	assert.Contains(t, string(filteredBody), "No templates match")
}

// TestSyncTemplates_GitNotFound_RendersFriendlyMessage confirms
// templatesync.ErrGitNotFound is translated into the #sync-status fragment's
// text, not left to bubble as an unhandled 500 — the exact requirement
// docs/12-implementation-plan-ph3.md's handlers_templates.go note states.
func TestSyncTemplates_GitNotFound_RendersFriendlyMessage(t *testing.T) {
	ts := newTestServer(t)
	t.Setenv("PATH", "") // same technique pkg/templatesync/sync_test.go's TestSync_GitNotFound uses

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	getResp, err := client.Get(ts.URL + "/templates")
	require.NoError(t, err)
	require.NoError(t, getResp.Body.Close())
	csrfVal := cookieValue(t, jar, ts.URL, csrfCookieName)
	require.NotEmpty(t, csrfVal)

	resp, err := client.PostForm(ts.URL+"/templates/sync", url.Values{"csrf_token": {csrfVal}})
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, http.StatusOK, resp.StatusCode, "a failed sync is still a successfully-processed request — it must not be a 4xx/5xx")
	assert.Contains(t, string(body), "git is not installed")
	assert.NotContains(t, string(body), "exec:", "must not leak the raw exec.LookPath error text")
}

func TestSyncTemplates_MissingCSRFCookie_Rejected(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.PostForm(ts.URL+"/templates/sync", url.Values{"csrf_token": {"whatever"}})
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}
