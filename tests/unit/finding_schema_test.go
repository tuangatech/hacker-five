package unit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/detectors/authbypass"
	"github.com/tuangatech/hacker-five/pkg/detectors/idor"
	"github.com/tuangatech/hacker-five/pkg/detectors/misconfig"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func compileFindingSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaPath, err := filepath.Abs(filepath.Join("..", "..", "docs", "schema", "finding.schema.json"))
	require.NoError(t, err)
	schema, err := jsonschema.Compile(schemaPath)
	require.NoError(t, err)
	return schema
}

// assertRoundTrips validates each finding against the frozen schema, then
// proves the schema-shaped wire format loses nothing by marshaling and
// unmarshaling it back into a fresh detectors.Finding and comparing to the
// original.
func assertRoundTrips(t *testing.T, schema *jsonschema.Schema, findings []detectors.Finding) {
	t.Helper()
	require.NotEmpty(t, findings, "test setup should have produced at least one real finding")

	for _, original := range findings {
		raw, err := json.Marshal(original)
		require.NoError(t, err)

		var asAny any
		require.NoError(t, json.Unmarshal(raw, &asAny))
		assert.NoError(t, schema.Validate(asAny), "finding %q must satisfy docs/schema/finding.schema.json: %s", original.ID, raw)

		var roundTripped detectors.Finding
		require.NoError(t, json.Unmarshal(raw, &roundTripped))
		assert.Equal(t, original, roundTripped, "finding %q must round-trip through the frozen schema without loss", original.ID)
	}
}

// TestFindingSchema_RejectsInvalidSeverity proves the validator is actually
// wired up (not vacuously passing every input) by feeding it a Finding whose
// severity isn't one of the frozen enum's four values.
func TestFindingSchema_RejectsInvalidSeverity(t *testing.T) {
	schema := compileFindingSchema(t)

	invalid := detectors.Finding{
		ID:          "test-1",
		Type:        "misconfig",
		Severity:    "apocalyptic", // not in the frozen enum
		Confidence:  "high",
		Target:      "http://example.test",
		Description: "deliberately invalid for this test",
		Evidence:    map[string]string{"note": "x"},
	}
	raw, err := json.Marshal(invalid)
	require.NoError(t, err)
	var asAny any
	require.NoError(t, json.Unmarshal(raw, &asAny))

	assert.Error(t, schema.Validate(asAny))
}

func newSchemaTestClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

// TestFindingSchema_RoundTripsIDORFinding runs the real idor detector
// (idor.SequentialIntStrategy + the existing idor_classic.json fixture and
// its loadIDORFixture/newFixtureServer helpers from detector_idor_test.go,
// same package) to get a real "idor-" Finding, not a fabricated literal.
func TestFindingSchema_RoundTripsIDORFinding(t *testing.T) {
	schema := compileFindingSchema(t)

	fx := loadIDORFixture(t, "idor_classic.json")
	srv := newFixtureServer(t, fx)
	defer srv.Close()

	client := newSchemaTestClient()
	strategy := idor.SequentialIntStrategy{Start: 1, End: fx.NumIDs}
	detector := idor.New(client, strategy)

	findings, err := detector.Run(context.Background(), srv.URL+"/api/users/{{id}}", fx.OwnerToken, fx.OtherToken)
	require.NoError(t, err)

	assertRoundTrips(t, schema, findings)
}

// TestFindingSchema_RoundTripsMisconfigFinding runs the real misconfig
// detector against a bare server that returns 200 with no security headers,
// producing real "misconfig-missing-header-*" findings.
func TestFindingSchema_RoundTripsMisconfigFinding(t *testing.T) {
	schema := compileFindingSchema(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	detector := misconfig.New(newSchemaTestClient())
	findings, err := detector.Run(context.Background(), srv.URL, "")
	require.NoError(t, err)

	findings = withPrefix(findings, "misconfig-missing-header-")
	assertRoundTrips(t, schema, findings)
}

// TestFindingSchema_RoundTripsAuthbypassFinding runs the real authbypass
// detector's checkMissingAuth path (via Run) against a protected path that
// accepts unauthenticated requests, producing a real
// "authbypass-missing-auth-*" finding.
func TestFindingSchema_RoundTripsAuthbypassFinding(t *testing.T) {
	schema := compileFindingSchema(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/protected" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("secret data"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	detector := authbypass.New(newSchemaTestClient())
	findings, err := detector.Run(context.Background(), srv.URL, "owner-token", "other-token", []string{"/protected"})
	require.NoError(t, err)

	findings = withPrefix(findings, "authbypass-missing-auth-")
	assertRoundTrips(t, schema, findings)
}
