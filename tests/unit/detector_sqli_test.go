package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/sqli"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func newSQLiClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

// TestSQLiErrorBased_Hit mirrors a classic concatenated-query endpoint: any
// value containing a quote breaks the surrounding SQL and the app lets the
// driver's own error message through.
func TestSQLiErrorBased_Hit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, `'"`) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Warning: mysqli_fetch_array(): You have an error in your SQL syntax; check the manual"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Product 5: Widget</body></html>"))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient())
	targets := []sqli.Target{{URL: srv.URL + "?id=5", Params: []string{"id"}}}
	findings, err := detector.Run(context.Background(), targets, "")
	require.NoError(t, err)

	got := withPrefix(findings, "sqli-error-id")
	require.Len(t, got, 1)
	assert.Equal(t, "sqli", got[0].Type)
	assert.Equal(t, "high", got[0].Confidence)
	assert.Equal(t, "MySQL/MariaDB", got[0].Evidence["dbms"])
}

// TestSQLiErrorBased_SafeEndpoint_NoFinding: the app escapes/parameterizes
// the value — a quote never reaches the driver, so no error signature ever
// appears, matching or not.
func TestSQLiErrorBased_SafeEndpoint_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Product page</body></html>"))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient())
	targets := []sqli.Target{{URL: srv.URL + "?id=5", Params: []string{"id"}}}
	findings, err := detector.Run(context.Background(), targets, "")
	require.NoError(t, err)
	assert.Empty(t, withPrefix(findings, "sqli-error-id"))
}

// TestSQLiErrorBased_ErrorPageAlwaysPresent_NoFinding: a decoy where the
// app's baseline response *already* happens to carry a string matching one
// of errorPatterns (e.g. a support page mentioning MySQL) — must not be
// flagged, since the same signature is present with or without the payload.
func TestSQLiErrorBased_ErrorPageAlwaysPresent_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Help: check the manual that corresponds to your MySQL server version for migration tips"))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient())
	targets := []sqli.Target{{URL: srv.URL + "?id=5", Params: []string{"id"}}}
	findings, err := detector.Run(context.Background(), targets, "")
	require.NoError(t, err)
	assert.Empty(t, withPrefix(findings, "sqli-error-id"))
}

// TestSQLiBooleanBased_Hit mirrors a classic blind boolean endpoint: the
// value flows into a numeric WHERE clause with no visible error, but a
// false condition returns an empty result set.
func TestSQLiBooleanBased_Hit(t *testing.T) {
	fullPage := "<html><body>" + strings.Repeat("Product 5: Widget. ", 20) + "</body></html>"
	emptyPage := "<html><body>No results found</body></html>"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(id, "1=2") {
			_, _ = w.Write([]byte(emptyPage))
			return
		}
		_, _ = w.Write([]byte(fullPage))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient())
	targets := []sqli.Target{{URL: srv.URL + "?id=5", Params: []string{"id"}}}
	findings, err := detector.Run(context.Background(), targets, "")
	require.NoError(t, err)

	got := withPrefix(findings, "sqli-boolean-id-numeric")
	require.Len(t, got, 1)
	assert.Equal(t, "medium", got[0].Confidence)
}

// TestSQLiBooleanBased_ParamHasNoEffect_NoFinding: the param doesn't reach
// any query logic at all — every variant (baseline, true, false) returns
// the identical page. Must not be flagged: true==false, no divergence.
func TestSQLiBooleanBased_ParamHasNoEffect_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Static homepage content, unaffected by id</body></html>"))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient())
	targets := []sqli.Target{{URL: srv.URL + "?id=5", Params: []string{"id"}}}
	findings, err := detector.Run(context.Background(), targets, "")
	require.NoError(t, err)
	assert.Empty(t, withPrefix(findings, "sqli-boolean"))
}

// TestSQLiBooleanBased_ExactLookupNotSQL_NoFinding: a decoy where the param
// is looked up against an exact key (e.g. a map), not concatenated into
// SQL — appending *any* suffix (true or false) breaks the lookup entirely,
// so the "true" probe already diverges from baseline and the check
// correctly declines to compare further.
func TestSQLiBooleanBased_ExactLookupNotSQL_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "5" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Product 5: Widget</body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient())
	targets := []sqli.Target{{URL: srv.URL + "?id=5", Params: []string{"id"}}}
	findings, err := detector.Run(context.Background(), targets, "")
	require.NoError(t, err)
	assert.Empty(t, withPrefix(findings, "sqli-boolean"))
}

// TestSQLiDetector_MultipleParams_EachTestedIndependently confirms a target
// carrying two candidate params produces findings keyed to the right one.
func TestSQLiDetector_MultipleParams_EachTestedIndependently(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.ContainsAny(r.URL.Query().Get("vuln_id"), `'"`) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("PostgreSQL ERROR: pg_query() failed"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>fine</body></html>"))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient())
	targets := []sqli.Target{{URL: srv.URL + "?vuln_id=1&safe_id=2", Params: []string{"vuln_id", "safe_id"}}}
	findings, err := detector.Run(context.Background(), targets, "")
	require.NoError(t, err)

	assert.Len(t, withPrefix(findings, "sqli-error-vuln-id"), 1)
	assert.Empty(t, withPrefix(findings, "sqli-error-safe-id"))
}

// TestSQLiDetector_AuthHeaderOption proves a configured auth header/token
// is actually sent on every probe request, same convention as
// TestIDORDetector_AuthHeaderOption/TestSSRF's equivalent.
func TestSQLiDetector_AuthHeaderOption(t *testing.T) {
	var sawAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = append(sawAuth, r.Header.Get("X-Api-Key"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	detector := sqli.New(newSQLiClient(), sqli.WithAuthHeader("X-Api-Key", "{token}"))
	targets := []sqli.Target{{URL: srv.URL + "?id=5", Params: []string{"id"}}}
	_, err := detector.Run(context.Background(), targets, "secret-token")
	require.NoError(t, err)

	require.NotEmpty(t, sawAuth)
	for _, v := range sawAuth {
		assert.Equal(t, "secret-token", v)
	}
}
