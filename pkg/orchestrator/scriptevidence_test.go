package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// reconfirmTestTimeout is the per-request timeout every test in this file
// gives httpclient.Config.Timeout — zero would make context.WithTimeout
// expire immediately (client.go applies it via context.WithTimeout in Do,
// not http.Client.Timeout), which is not what these tests are exercising.
const reconfirmTestTimeout = 5 * time.Second

// TestReconfirmCandidate_ConfirmedOnMatchingStatus proves the happy path:
// a candidate whose re-issued request really returns the stated
// confirm_status becomes a real Finding, with Evidence naming the
// independent-reconfirmation mechanism (not the sandbox's own report).
func TestReconfirmCandidate_ConfirmedOnMatchingStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	cfg := Config{Target: srv.URL, BaseScanConfig: scanner.Config{Timeout: reconfirmTestTimeout}}
	c := scriptFindingCandidate{
		Method:        "GET",
		URL:           srv.URL + "/admin",
		Type:          "authbypass",
		Severity:      "high",
		ConfirmStatus: http.StatusForbidden,
	}

	f, note := reconfirmCandidate(context.Background(), cfg, c)
	if f == nil {
		t.Fatalf("got nil Finding, note=%q, want a confirmed Finding", note)
	}
	if !strings.Contains(note, "confirmed") {
		t.Errorf("got note %q, want it to say confirmed", note)
	}
	if f.Confidence != "high" {
		t.Errorf("got Confidence=%q, want high (this package's own re-check, not the sandbox's report)", f.Confidence)
	}
	if f.Evidence["confirmation_method"] == "" || strings.Contains(f.Evidence["confirmation_method"], "sandbox") == false {
		t.Errorf("got Evidence[confirmation_method]=%q, want it to name the independent re-issue, not the sandbox", f.Evidence["confirmation_method"])
	}
}

// TestReconfirmCandidate_ConfirmedOnMatchingSubstring covers the
// confirm_contains condition path, independent of confirm_status.
func TestReconfirmCandidate_ConfirmedOnMatchingSubstring(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"secret":"sk_live_12345"}`))
	}))
	defer srv.Close()

	cfg := Config{Target: srv.URL, BaseScanConfig: scanner.Config{Timeout: reconfirmTestTimeout}}
	c := scriptFindingCandidate{
		Method:          "GET",
		URL:             srv.URL + "/debug",
		ConfirmContains: "sk_live_",
	}

	f, note := reconfirmCandidate(context.Background(), cfg, c)
	if f == nil {
		t.Fatalf("got nil Finding, note=%q, want a confirmed Finding", note)
	}
	if !strings.Contains(f.Evidence["response_snippet"], "sk_live_") {
		t.Errorf("got response_snippet=%q, want it to contain the confirmed substring", f.Evidence["response_snippet"])
	}
}

// TestReconfirmCandidate_NotConfirmedWhenResponseDoesNotMatch proves a
// candidate whose re-issued response doesn't actually satisfy its own
// stated condition is dropped, not shipped on the strength of the script's
// claim alone.
func TestReconfirmCandidate_NotConfirmedWhenResponseDoesNotMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{Target: srv.URL, BaseScanConfig: scanner.Config{Timeout: reconfirmTestTimeout}}
	c := scriptFindingCandidate{
		Method:        "GET",
		URL:           srv.URL + "/admin",
		ConfirmStatus: http.StatusForbidden,
	}

	f, note := reconfirmCandidate(context.Background(), cfg, c)
	if f != nil {
		t.Fatalf("got a Finding, want nil — the re-issued response (200) didn't match confirm_status (403)")
	}
	if !strings.Contains(note, "not confirmed") {
		t.Errorf("got note %q, want it to say not confirmed", note)
	}
}

// TestReconfirmCandidate_DropsWithoutFalsifiableCondition is LT-160 item 1's
// central invariant: a candidate that names no confirm_status/confirm_contains
// at all must never be trusted into a Finding purely because the script
// claimed something happened.
func TestReconfirmCandidate_DropsWithoutFalsifiableCondition(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{Target: srv.URL, BaseScanConfig: scanner.Config{Timeout: reconfirmTestTimeout}}
	c := scriptFindingCandidate{Method: "GET", URL: srv.URL + "/admin"}

	f, note := reconfirmCandidate(context.Background(), cfg, c)
	if f != nil {
		t.Fatal("got a Finding, want nil — no confirm_status/confirm_contains given")
	}
	if !strings.Contains(note, "refusing to trust") {
		t.Errorf("got note %q, want it to explain the refusal", note)
	}
}

// TestReconfirmCandidate_DropsOutOfScope proves a candidate can never point
// a "confirmed" Finding at a host the run wasn't authorized to look at, even
// if the re-issued response would otherwise satisfy its own condition.
func TestReconfirmCandidate_DropsOutOfScope(t *testing.T) {
	cfg := Config{Target: "https://example.test"}
	c := scriptFindingCandidate{
		Method:        "GET",
		URL:           "https://attacker-controlled.test/admin",
		ConfirmStatus: 200,
	}

	f, note := reconfirmCandidate(context.Background(), cfg, c)
	if f != nil {
		t.Fatal("got a Finding, want nil — target host is out of scope")
	}
	if !strings.Contains(note, "not in scope") {
		t.Errorf("got note %q, want it to say not in scope", note)
	}
}

// TestReconfirmCandidate_HonorsRealScopeFile proves inScope defers to
// cfg.BaseScanConfig.Scope (the same *scope.Scope B4's scope-creep gate
// checks scan.leaf dispatches against) when one is configured, rather than
// only ever falling back to an exact host match against cfg.Target.
func TestReconfirmCandidate_HonorsRealScopeFile(t *testing.T) {
	sc, err := scope.New([]string{"*.example.test"})
	if err != nil {
		t.Fatalf("scope.New: %v", err)
	}
	cfg := Config{Target: "https://seed.example.test", BaseScanConfig: scanner.Config{Scope: sc, Timeout: reconfirmTestTimeout}}

	inScopeCandidate := scriptFindingCandidate{Method: "GET", URL: "https://other.example.test/admin", ConfirmStatus: 200}
	if _, note := reconfirmCandidate(context.Background(), cfg, inScopeCandidate); strings.Contains(note, "not in scope") {
		t.Errorf("got note %q, want a subdomain covered by the scope file to pass the scope check (it will still fail to connect, which is fine)", note)
	}

	outOfScopeCandidate := scriptFindingCandidate{Method: "GET", URL: "https://evil.test/admin", ConfirmStatus: 200}
	if f, note := reconfirmCandidate(context.Background(), cfg, outOfScopeCandidate); f != nil || !strings.Contains(note, "not in scope") {
		t.Errorf("got f=%v note=%q, want nil Finding and a not-in-scope note", f, note)
	}
}

// TestReconfirmCandidate_MutatingMethodRequiresAllowWrites proves a POST/PUT/
// etc. candidate is dropped unless the run's own --allow-writes is set —
// reusing scan's existing gate rather than adding a new one, per CLAUDE.md's
// "any new mutating capability needs its own equally-scoped flag" rule
// (this isn't a new capability, it's the same scan's AllowWrites already in
// effect).
func TestReconfirmCandidate_MutatingMethodRequiresAllowWrites(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	c := scriptFindingCandidate{Method: "POST", URL: srv.URL + "/coupons", ConfirmStatus: http.StatusCreated}

	cfg := Config{Target: srv.URL, BaseScanConfig: scanner.Config{Timeout: reconfirmTestTimeout}}
	f, note := reconfirmCandidate(context.Background(), cfg, c)
	if f != nil {
		t.Fatal("got a Finding, want nil — mutating method without --allow-writes")
	}
	if !strings.Contains(note, "--allow-writes") {
		t.Errorf("got note %q, want it to name --allow-writes", note)
	}
	if gotMethod != "" {
		t.Fatalf("got request actually sent (method=%q), want the mutating request never issued at all without --allow-writes", gotMethod)
	}

	cfg.BaseScanConfig.AllowWrites = true
	f, note = reconfirmCandidate(context.Background(), cfg, c)
	if f == nil {
		t.Fatalf("got nil Finding, note=%q, want a confirmed Finding once --allow-writes is set", note)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("got method=%q, want POST actually re-issued", gotMethod)
	}
}

// TestReconfirmScriptCandidates_ParsesSentinelLinesOnly proves the stdout
// scanner only reacts to HACKERFIVE_FINDING_CANDIDATE lines, tolerates
// interleaved ordinary output, and reports a per-line note (including for
// malformed JSON) without ever panicking or aborting the whole batch on one
// bad line.
func TestReconfirmScriptCandidates_ParsesSentinelLinesOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	stdout := strings.Join([]string{
		"probing endpoints...",
		fmt.Sprintf(`HACKERFIVE_FINDING_CANDIDATE: {"method":"GET","url":%q,"confirm_status":403}`, srv.URL+"/admin"),
		"some other debug line",
		"HACKERFIVE_FINDING_CANDIDATE: {not json",
		"done",
	}, "\n")

	cfg := Config{Target: srv.URL, BaseScanConfig: scanner.Config{Timeout: reconfirmTestTimeout}}
	findings, notes := reconfirmScriptCandidates(context.Background(), cfg, stdout)

	if len(findings) != 1 {
		t.Fatalf("got %d finding(s), want exactly 1", len(findings))
	}
	if len(notes) != 2 {
		t.Fatalf("got %d note(s), want exactly 2 (one per candidate line, ordinary output ignored)", len(notes))
	}
	var sawConfirmed, sawInvalidJSON bool
	for _, n := range notes {
		if strings.Contains(n, "confirmed") {
			sawConfirmed = true
		}
		if strings.Contains(n, "invalid JSON") {
			sawInvalidJSON = true
		}
	}
	if !sawConfirmed || !sawInvalidJSON {
		t.Fatalf("got notes=%v, want one confirmed note and one invalid-JSON note", notes)
	}
}

// TestReconfirmScriptCandidates_NoSentinelLinesReturnsNothing confirms a
// script that never proposes a candidate produces neither findings nor
// notes.
func TestReconfirmScriptCandidates_NoSentinelLinesReturnsNothing(t *testing.T) {
	findings, notes := reconfirmScriptCandidates(context.Background(), Config{}, "just some output\nnothing special\n")
	if len(findings) != 0 || len(notes) != 0 {
		t.Fatalf("got findings=%v notes=%v, want both empty", findings, notes)
	}
}
