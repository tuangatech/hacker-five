package hackerone

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New("token-id", "token-secret", WithBaseURL(srv.URL)), srv
}

func TestListWeaknesses_SendsBasicAuthAndDecodesResponse(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, "token-id", username)
		assert.Equal(t, "token-secret", password)
		assert.Equal(t, "/programs/acme/weaknesses", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		_, _ = w.Write([]byte(`{"data":[{"id":"66","type":"weakness","attributes":{"name":"Cross-site Scripting (XSS)","external_id":"79"}}]}`))
	})

	weaknesses, err := client.ListWeaknesses(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, weaknesses, 1)
	assert.Equal(t, Weakness{ID: "66", Name: "Cross-site Scripting (XSS)", ExternalID: "79"}, weaknesses[0])
}

func TestListStructuredScopes_DecodesResponse(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/programs/acme/structured_scopes", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":[{"id":"123","type":"structured-scope","attributes":{"asset_identifier":"example.com","asset_type":"URL","eligible_for_submission":true,"eligible_for_bounty":true,"instruction":"prod only","max_severity":"critical"}}]}`))
	})

	scopes, err := client.ListStructuredScopes(context.Background(), "acme")
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	assert.Equal(t, Scope{
		ID: "123", AssetIdentifier: "example.com", AssetType: "URL",
		EligibleForSubmission: true, EligibleForBounty: true,
		Instruction: "prod only", MaxSeverity: "critical",
	}, scopes[0])
}

func TestCreateReportIntent_SendsExpectedBodyAndDecodesState(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/report_intents", r.URL.Path)

		var req reportIntentCreateRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "report-intent", req.Data.Type)
		assert.Equal(t, "acme", req.Data.Attributes.TeamHandle)
		assert.Equal(t, "high", req.Data.Attributes.SeverityRating)
		assert.Equal(t, "66", req.Data.Attributes.WeaknessID)
		assert.Equal(t, "123", req.Data.Attributes.StructuredScopeID)

		_, _ = w.Write([]byte(`{"data":{"id":"999","type":"report-intent","attributes":{"state":"pending"}}}`))
	})

	id, state, err := client.CreateReportIntent(context.Background(), ReportIntentInput{
		TeamHandle:               "acme",
		Title:                    "SSRF in webhook param",
		VulnerabilityInformation: "details",
		SeverityRating:           "high",
		WeaknessID:               "66",
		StructuredScopeID:        "123",
	})
	require.NoError(t, err)
	assert.Equal(t, "999", id)
	assert.Equal(t, "pending", state)
}

func TestCreateReportIntent_RejectsMissingRequiredFields(t *testing.T) {
	client := New("id", "secret")
	_, _, err := client.CreateReportIntent(context.Background(), ReportIntentInput{TeamHandle: "acme"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required field")
}

func TestSubmitReportIntent_PostsToSubmitPath(t *testing.T) {
	called := false
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/report_intents/999/submit", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})

	err := client.SubmitReportIntent(context.Background(), "999")
	require.NoError(t, err)
	assert.True(t, called)
}

func TestDo_NonSuccessStatusReturnsError(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"weakness_id is invalid"}]}`))
	})

	_, _, err := client.CreateReportIntent(context.Background(), ReportIntentInput{
		TeamHandle: "acme", Title: "t", VulnerabilityInformation: "v",
		SeverityRating: "high", WeaknessID: "0", StructuredScopeID: "0",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "422")
}
