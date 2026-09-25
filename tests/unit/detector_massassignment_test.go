package unit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/massassignment"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func newMassAssignmentClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

const massAssignmentToken = "owner-token"

// massAssignmentStore is a tiny in-memory model a fixture PATCH handler
// writes to and a fixture GET handler reads back from — every field value
// is stringified for a simple, dependency-free equality/contains check.
type massAssignmentStore map[string]string

func (s massAssignmentStore) applyBody(r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	for k, v := range body {
		s[k] = fmt.Sprintf("%v", v)
	}
}

func (s massAssignmentStore) writeJSON(w http.ResponseWriter) {
	b, _ := json.Marshal(s)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// TestMassAssignment_Hit_CanaryPersistsThroughIndependentRead: the write
// endpoint has no field allow-list — whatever probe field the detector adds
// survives to a *separate* GET, confirming persistence rather than merely
// the write's own echo.
func TestMassAssignment_Hit_CanaryPersistsThroughIndependentRead(t *testing.T) {
	store := massAssignmentStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			store.applyBody(r)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"updated"}`))
		case http.MethodGet:
			store.writeJSON(w)
		}
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users/me",
		Method: "PATCH",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "massassignment", f.Type)
	assert.Equal(t, "medium", f.Severity)
	assert.Equal(t, "high", f.Confidence)
	assert.NotEmpty(t, f.Evidence["canary_field"])
	assert.NotEmpty(t, f.Evidence["canary_value"])
	assert.Equal(t, "200", f.Evidence["write_status"])
	assert.Equal(t, "200", f.Evidence["verify_status"])
}

// TestMassAssignment_ProperlyAllowListed_NoFinding: the backend ignores any
// field it doesn't recognize — the canary never appears in an independent
// read, so no finding fires.
func TestMassAssignment_ProperlyAllowListed_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"updated"}`))
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"alice"}`))
		}
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users/me",
		Method: "PATCH",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestMassAssignment_WriteEchoesButNeverPersists_NoFinding is the core
// false-positive guardrail: a write response can echo the whole request
// body (including the canary) right back without ever having actually
// stored it — the detector must never trust that, only the independent
// follow-up read.
func TestMassAssignment_WriteEchoesButNeverPersists_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			body, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body) // echoes the request straight back — misleading
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"alice"}`)) // never actually stored the canary
		}
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users/me",
		Method: "PATCH",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestMassAssignment_AllowMutatingFalse_NoRequestsSent: the gate must stop
// the detector before a single request is sent.
func TestMassAssignment_AllowMutatingFalse_NoRequestsSent(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users/me",
		Method: "PATCH",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, false)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, int32(0), calls.Load())
}

// TestMassAssignment_MissingToken_NoOp: no auth token means the whole run is
// a no-op, no requests sent — there is no unauthenticated mode.
func TestMassAssignment_MissingToken_NoOp(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users/me",
		Method: "PATCH",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, "", true)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, int32(0), calls.Load())
}

// TestMassAssignment_WrongMethod_Skipped: v1 only covers PUT/PATCH
// self-update endpoints — a POST-create target is refused, no requests sent.
func TestMassAssignment_WrongMethod_Skipped(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users",
		Method: "POST",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, int32(0), calls.Load())
}

// TestMassAssignment_EmptyBody_Skipped: no legitimate body means no request
// to attach a probe field to — refuse rather than guess one.
func TestMassAssignment_EmptyBody_Skipped(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{URL: srv.URL + "/users/me", Method: "PATCH"}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, int32(0), calls.Load())
}

// TestMassAssignment_SeparateVerifyURL: when the write and read paths
// differ, VerifyURL is honored instead of defaulting to URL.
func TestMassAssignment_SeparateVerifyURL(t *testing.T) {
	store := massAssignmentStore{}
	mux := http.NewServeMux()
	mux.HandleFunc("/users/update", func(w http.ResponseWriter, r *http.Request) {
		store.applyBody(r)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/users/me", func(w http.ResponseWriter, r *http.Request) {
		store.writeJSON(w)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:       srv.URL + "/users/update",
		Method:    "PATCH",
		Body:      map[string]any{"name": "alice"},
		VerifyURL: srv.URL + "/users/me",
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "massassignment", findings[0].Type)
}

// TestMassAssignment_FindingIDIsSanitized guards against a raw URL leaking
// unsanitized into Finding.ID.
func TestMassAssignment_FindingIDIsSanitized(t *testing.T) {
	store := massAssignmentStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			store.applyBody(r)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			store.writeJSON(w)
		}
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users/me?refresh=1",
		Method: "PATCH",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.False(t, strings.ContainsAny(findings[0].ID, "/?&=:"), "Finding.ID must not carry raw URL separators: %q", findings[0].ID)
}

// TestMassAssignment_TokenReachesBothWriteAndVerify confirms the auth token
// is sent on the mutating write AND the independent verify GET — a missing
// header on either side would silently break the whole check.
func TestMassAssignment_TokenReachesBothWriteAndVerify(t *testing.T) {
	var badAuth atomic.Bool
	store := massAssignmentStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+massAssignmentToken {
			badAuth.Store(true)
		}
		switch r.Method {
		case http.MethodPatch:
			store.applyBody(r)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			store.writeJSON(w)
		}
	}))
	defer srv.Close()

	detector := massassignment.New(newMassAssignmentClient())
	targets := []massassignment.Target{{
		URL:    srv.URL + "/users/me",
		Method: "PATCH",
		Body:   map[string]any{"name": "alice"},
	}}
	findings, err := detector.Run(context.Background(), targets, massAssignmentToken, true)
	require.NoError(t, err)
	assert.False(t, badAuth.Load(), "auth token must be sent on both the write and the verify GET")
	assert.Len(t, findings, 1)
}
