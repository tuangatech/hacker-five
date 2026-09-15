package webui

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/scriptexec"
)

// TestRequestScriptApproval_ApprovedUnblocksWithTrue is the docs/93 M4
// contract's golden path: RequestScriptApproval blocks until
// ResolveScriptApproval is called, then returns exactly the decision it was
// given.
func TestRequestScriptApproval_ApprovedUnblocksWithTrue(t *testing.T) {
	job := newTestJob("job1")

	type outcome struct {
		approved bool
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		approved, err := job.RequestScriptApproval(context.Background(), scriptexec.ScriptRequest{Language: scriptexec.LangPython, Source: "print(1)"}, scriptexec.PrecheckResult{})
		done <- outcome{approved, err}
	}()

	require.Eventually(t, func() bool { return job.ResolveScriptApproval(true) }, time.Second, time.Millisecond, "no pending approval to resolve")

	select {
	case got := <-done:
		require.NoError(t, got.err)
		assert.True(t, got.approved)
	case <-time.After(time.Second):
		t.Fatal("RequestScriptApproval never unblocked")
	}
}

// TestRequestScriptApproval_Rejected mirrors the approved case for the
// reject path.
func TestRequestScriptApproval_Rejected(t *testing.T) {
	job := newTestJob("job1")

	done := make(chan bool, 1)
	go func() {
		approved, _ := job.RequestScriptApproval(context.Background(), scriptexec.ScriptRequest{Language: scriptexec.LangShell, Source: "echo hi"}, scriptexec.PrecheckResult{})
		done <- approved
	}()

	require.Eventually(t, func() bool { return job.ResolveScriptApproval(false) }, time.Second, time.Millisecond, "no pending approval to resolve")

	select {
	case approved := <-done:
		assert.False(t, approved)
	case <-time.After(time.Second):
		t.Fatal("RequestScriptApproval never unblocked")
	}
}

// TestRequestScriptApproval_ContextCanceled confirms the kill switch
// (Job.Cancel, which cancels job.Ctx()) also unblocks a pending script
// approval rather than leaving the agent run's goroutine hung forever with
// no human ever responding.
func TestRequestScriptApproval_ContextCanceled(t *testing.T) {
	job := newTestJob("job1")
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		_, err := job.RequestScriptApproval(ctx, scriptexec.ScriptRequest{Language: scriptexec.LangPython, Source: "print(1)"}, scriptexec.PrecheckResult{})
		done <- err
	}()

	require.Eventually(t, func() bool {
		job.mu.Lock()
		defer job.mu.Unlock()
		return job.pendingScript != nil
	}, time.Second, time.Millisecond, "approval never became pending")

	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("RequestScriptApproval never unblocked on context cancellation")
	}
}

// TestResolveScriptApproval_NothingPending_ReturnsFalse: a duplicate submit
// or a submit after the request already resolved must not panic or block —
// just report nothing was done.
func TestResolveScriptApproval_NothingPending_ReturnsFalse(t *testing.T) {
	job := newTestJob("job1")
	assert.False(t, job.ResolveScriptApproval(true))
}

// TestRequestScriptApproval_SnapshotReflectsPendingState confirms a page
// reload while an approval is in flight sees the pending card too, not just
// a live SSE client (Job.Snapshot's PendingScriptApproval field).
func TestRequestScriptApproval_SnapshotReflectsPendingState(t *testing.T) {
	job := newTestJob("job1")

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = job.RequestScriptApproval(context.Background(), scriptexec.ScriptRequest{Language: scriptexec.LangPython, Source: "print('hi')"}, scriptexec.PrecheckResult{Reasons: []string{"uses urllib"}})
	}()

	require.Eventually(t, func() bool {
		return job.Snapshot().PendingScriptApproval != nil
	}, time.Second, time.Millisecond)

	snap := job.Snapshot().PendingScriptApproval
	assert.True(t, snap.Pending)
	assert.Equal(t, "python", snap.Language)
	assert.Contains(t, snap.Source, "print")
	assert.Equal(t, []string{"uses urllib"}, snap.Reasons)

	job.ResolveScriptApproval(true)
	<-done

	assert.Nil(t, job.Snapshot().PendingScriptApproval)
}

// TestAgentScriptApproval_Approve exercises the HTTP handler end to end: a
// POST with action=approve resolves a pending RequestScriptApproval call
// with true.
func TestAgentScriptApproval_Approve(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJob("job1")
	h.store.Add(job)

	done := make(chan bool, 1)
	go func() {
		approved, _ := job.RequestScriptApproval(context.Background(), scriptexec.ScriptRequest{Language: scriptexec.LangPython, Source: "print(1)"}, scriptexec.PrecheckResult{})
		done <- approved
	}()
	require.Eventually(t, func() bool { return job.Snapshot().PendingScriptApproval != nil }, time.Second, time.Millisecond)

	resp := postWithCSRFForm(t, ts, "/scans/job1/agent-script", url.Values{"action": {"approve"}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	select {
	case approved := <-done:
		assert.True(t, approved)
	case <-time.After(time.Second):
		t.Fatal("POST /agent-script never unblocked RequestScriptApproval")
	}
}

// TestAgentScriptApproval_Reject mirrors the approve case.
func TestAgentScriptApproval_Reject(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	job := newTestJob("job1")
	h.store.Add(job)

	done := make(chan bool, 1)
	go func() {
		approved, _ := job.RequestScriptApproval(context.Background(), scriptexec.ScriptRequest{Language: scriptexec.LangShell, Source: "echo hi"}, scriptexec.PrecheckResult{})
		done <- approved
	}()
	require.Eventually(t, func() bool { return job.Snapshot().PendingScriptApproval != nil }, time.Second, time.Millisecond)

	resp := postWithCSRFForm(t, ts, "/scans/job1/agent-script", url.Values{"action": {"reject"}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	select {
	case approved := <-done:
		assert.False(t, approved)
	case <-time.After(time.Second):
		t.Fatal("POST /agent-script never unblocked RequestScriptApproval")
	}
}

// TestAgentScriptApproval_NothingPending_StillNoContent: no in-flight
// RequestScriptApproval call — the handler must not error.
func TestAgentScriptApproval_NothingPending_StillNoContent(t *testing.T) {
	ts, h := newTestServerHandlers(t)
	h.store.Add(newTestJob("job1"))

	resp := postWithCSRFForm(t, ts, "/scans/job1/agent-script", url.Values{"action": {"approve"}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
}

// TestAgentScriptApproval_UnknownJob404s
func TestAgentScriptApproval_UnknownJob404s(t *testing.T) {
	ts, _ := newTestServerHandlers(t)
	resp := postWithCSRFForm(t, ts, "/scans/nope/agent-script", url.Values{"action": {"approve"}})
	require.NoError(t, resp.Body.Close())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
