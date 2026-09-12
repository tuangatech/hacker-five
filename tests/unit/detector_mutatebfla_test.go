package unit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors/mutatebfla"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

func newMutateBFLAClient() *httpclient.Client {
	return httpclient.New(httpclient.Config{
		Timeout:             5 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 10,
	})
}

const (
	mutateBFLAOwnerToken = "owner-token"
	mutateBFLAOtherToken = "other-token"
)

// TestMutateBFLA_Hit_RealDeletionConfirmed: otherToken's DELETE genuinely
// removes the resource — a follow-up GET as owner confirms the marker is
// really gone, not merely a status-code inference.
func TestMutateBFLA_Hit_RealDeletionConfirmed(t *testing.T) {
	var deleted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if deleted.Load() {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("not found"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"video-42","title":"my vacation"}`))
		case http.MethodDelete:
			deleted.Store(true)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"deleted"}`))
		}
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/42", Marker: "video-42"}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, true)
	require.NoError(t, err)

	require.Len(t, findings, 1)
	f := findings[0]
	assert.Equal(t, "mutatebfla", f.Type)
	assert.Equal(t, "critical", f.Severity)
	assert.Equal(t, "high", f.Confidence)
	assert.Equal(t, "200", f.Evidence["baseline_status"])
	assert.Equal(t, "404", f.Evidence["after_status"])
}

// TestMutateBFLA_ProperlyProtected_NoFinding: the app correctly rejects
// otherToken's DELETE and never actually deletes anything.
func TestMutateBFLA_ProperlyProtected_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"video-42"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		}
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/42", Marker: "video-42"}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestMutateBFLA_MisleadingStatus_NoFinding is the detector's core
// false-positive guardrail: a backend can return a "success" status for a
// DELETE that didn't actually delete anything (a real, observed failure
// mode) — the detector must never take that status code as proof.
func TestMutateBFLA_MisleadingStatus_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// Always still present — the DELETE never actually did anything,
			// despite what it claims below.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"video-42"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"deleted"}`)) // misleading — nothing really happened
		}
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/42", Marker: "video-42"}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestMutateBFLA_BaselineMissingMarker_Skipped: the detector must never
// mutate a resource whose baseline it can't itself confirm via Marker — and
// must never even attempt the DELETE in that case.
func TestMutateBFLA_BaselineMissingMarker_Skipped(t *testing.T) {
	var deleteCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"some-other-video"}`)) // marker never present
		case http.MethodDelete:
			deleteCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/42", Marker: "video-42"}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, int32(0), deleteCalls.Load(), "must never fire the DELETE against an unconfirmed baseline")
}

// TestMutateBFLA_AllowMutatingFalse_NoRequestsSent: the gate must stop the
// detector before a single request is sent, not just before a finding.
func TestMutateBFLA_AllowMutatingFalse_NoRequestsSent(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/42", Marker: "video-42"}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, false)
	require.NoError(t, err)
	assert.Empty(t, findings)
	assert.Equal(t, int32(0), calls.Load())
}

// TestMutateBFLA_MissingToken_NoOp: there is no single-account mode — either
// token missing means the whole run is a no-op, no requests sent.
func TestMutateBFLA_MissingToken_NoOp(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/42", Marker: "video-42"}}

	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, "", true)
	require.NoError(t, err)
	assert.Empty(t, findings)

	findings, err = detector.Run(context.Background(), targets, "", mutateBFLAOtherToken, true)
	require.NoError(t, err)
	assert.Empty(t, findings)

	assert.Equal(t, int32(0), calls.Load())
}

// TestMutateBFLA_SeparateVerifyURL_ListEndpoint mirrors crAPI's own split
// shape: DELETE .../video/delete/{id} has no GET-by-id sibling, so the
// caller points VerifyURL at the owner's own list endpoint instead, with
// Marker set to the resource's ID substring.
func TestMutateBFLA_SeparateVerifyURL_ListEndpoint(t *testing.T) {
	var deleted atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/videos", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if deleted.Load() {
			_, _ = w.Write([]byte(`{"videos":[{"id":"7"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"videos":[{"id":"7"},{"id":"video-42"}]}`))
	})
	mux.HandleFunc("/video/delete/42", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		deleted.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{
		DeleteURL: srv.URL + "/video/delete/42",
		VerifyURL: srv.URL + "/videos",
		Marker:    "video-42",
	}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, true)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "mutatebfla", findings[0].Type)
}

// TestMutateBFLA_TokenPropagation confirms the owner token reaches every GET
// (both baseline and after) and the other token reaches only the DELETE —
// swapped or missing auth on either side would corrupt every comparison
// (this is exactly the shape of bug the sqli detector's own auth-header test
// caught).
func TestMutateBFLA_TokenPropagation(t *testing.T) {
	var deleted atomic.Bool
	var badAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodGet:
			if auth != "Bearer "+mutateBFLAOwnerToken {
				badAuth.Store(true)
			}
			if deleted.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("video-42"))
		case http.MethodDelete:
			if auth != "Bearer "+mutateBFLAOtherToken {
				badAuth.Store(true)
			}
			deleted.Store(true)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/42", Marker: "video-42"}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, true)
	require.NoError(t, err)
	assert.False(t, badAuth.Load(), "owner token must be sent on both GETs, other token only on the DELETE")
	assert.Len(t, findings, 1)
}

// TestMutateBFLA_FindingIDIsSanitized guards against a raw URL (with slashes
// and query separators) leaking unsanitized into Finding.ID.
func TestMutateBFLA_FindingIDIsSanitized(t *testing.T) {
	var deleted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if deleted.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("video-42"))
		case http.MethodDelete:
			deleted.Store(true)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	detector := mutatebfla.New(newMutateBFLAClient())
	targets := []mutatebfla.Target{{DeleteURL: srv.URL + "/video/delete/42?confirm=1", Marker: "video-42"}}
	findings, err := detector.Run(context.Background(), targets, mutateBFLAOwnerToken, mutateBFLAOtherToken, true)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.False(t, strings.ContainsAny(findings[0].ID, "/?&=:"), "Finding.ID must not carry raw URL separators: %q", findings[0].ID)
}
