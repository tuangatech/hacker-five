package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

// TestResolveMissingLeafField_DeterministicSingleCandidate_AutoFillsAndApplies
// is LT-138 item 1's fix (docs/follow-up.md): a scan.leaf dispatch blocked on
// idor's EndpointTemplate must get a real chance at fieldsuggest.Deterministic's
// existing single-candidate auto-fill (already unconditional in
// pkg/mcpserver/pkg/webui) instead of staying permanently unresolvable.
func TestResolveMissingLeafField_DeterministicSingleCandidate_AutoFillsAndApplies(t *testing.T) {
	leaf := &agenttask.PlanNode{ID: "leaf1", Target: "https://example.test", Detector: "idor", Status: agenttask.StatusPending}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	fresh := &recon.ReconResult{Endpoints: []recon.EndpointFact{{URL: "https://example.test/orders/42", StatusCode: 200}}}
	cfg := Config{Recon: &fakeRecon{result: fresh}, ReconTimeout: 5 * time.Second}

	filled, note, applied := resolveMissingLeafField(context.Background(), cfg, tree, leaf)
	if !applied {
		t.Fatalf("got applied=false, note=%q, want a single deterministic candidate to auto-apply", note)
	}
	if filled.EndpointTemplate != "/orders/{{id}}" {
		t.Fatalf("got EndpointTemplate=%q, want the recon-derived candidate", filled.EndpointTemplate)
	}
	if !strings.Contains(note, "auto-filled") {
		t.Fatalf("got note %q, want it to say auto-filled", note)
	}
}

// TestResolveMissingLeafField_GenuineMiss_ResolvedViaI4ButNeverAutoApplied
// covers the 0-candidate case: I4 (cfg.Client.ResolveField) is actually
// called and its cost tracked, but — matching pkg/mcpserver's own
// applyFieldSuggestion precedent — the resolved value is only ever surfaced
// in the note, never applied to execution.
func TestResolveMissingLeafField_GenuineMiss_ResolvedViaI4ButNeverAutoApplied(t *testing.T) {
	leaf := &agenttask.PlanNode{ID: "leaf1", Target: "https://example.test", Detector: "idor", Status: agenttask.StatusPending}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	// No id-shaped endpoints at all — idor's real 0-candidate miss case.
	fresh := &recon.ReconResult{Endpoints: []recon.EndpointFact{{URL: "https://example.test/about", StatusCode: 200}}}
	client := &fakeLLMClient{resolveFieldDecision: llmfallback.FieldDecision{SuggestedValue: "/orders/{{id}}", Rationale: "guessed from an OpenResty tech fact"}, resolveFieldCost: 0.01}
	cfg := Config{Recon: &fakeRecon{result: fresh}, ReconTimeout: 5 * time.Second, Client: client}

	filled, note, applied := resolveMissingLeafField(context.Background(), cfg, tree, leaf)
	if applied {
		t.Fatalf("got applied=true, want false — an I4-resolved miss must never auto-apply to execution")
	}
	if filled.EndpointTemplate != "" {
		t.Fatalf("got EndpointTemplate=%q, want it left blank — I4's guess must not reach scanner.Config", filled.EndpointTemplate)
	}
	if client.resolveFieldCalls != 1 {
		t.Fatalf("got %d ResolveField call(s), want exactly 1", client.resolveFieldCalls)
	}
	if !strings.Contains(note, "/orders/{{id}}") || !strings.Contains(note, "not auto-applied") {
		t.Fatalf("got note %q, want it to surface I4's suggestion and say it wasn't auto-applied", note)
	}
	if tree.SpendSoFar() < 0.01-1e-9 {
		t.Fatalf("got SpendSoFar=%.4f, want >= 0.01 — I4's cost must be tracked against the tree's spend ceiling", tree.SpendSoFar())
	}
}

// TestResolveMissingLeafField_I4EscalatesToHuman covers the escalation branch
// of the genuine-miss path.
func TestResolveMissingLeafField_I4EscalatesToHuman(t *testing.T) {
	leaf := &agenttask.PlanNode{ID: "leaf1", Target: "https://example.test", Detector: "idor", Status: agenttask.StatusPending}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	fresh := &recon.ReconResult{Endpoints: []recon.EndpointFact{{URL: "https://example.test/about", StatusCode: 200}}}
	client := &fakeLLMClient{resolveFieldDecision: llmfallback.FieldDecision{EscalateToHuman: "no candidate looks safe to guess"}}
	cfg := Config{Recon: &fakeRecon{result: fresh}, ReconTimeout: 5 * time.Second, Client: client}

	_, note, applied := resolveMissingLeafField(context.Background(), cfg, tree, leaf)
	if applied {
		t.Fatal("got applied=true, want false")
	}
	if !strings.Contains(note, "escalated to human") {
		t.Fatalf("got note %q, want it to mention the escalation", note)
	}
}

// TestResolveMissingLeafField_ReconProbeFails surfaces a failed recon probe
// as a note rather than silently swallowing it.
func TestResolveMissingLeafField_ReconProbeFails(t *testing.T) {
	leaf := &agenttask.PlanNode{ID: "leaf1", Target: "https://example.test", Detector: "idor", Status: agenttask.StatusPending}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	cfg := Config{Recon: &fakeRecon{err: context.DeadlineExceeded}, ReconTimeout: 5 * time.Second}

	_, note, applied := resolveMissingLeafField(context.Background(), cfg, tree, leaf)
	if applied {
		t.Fatal("got applied=true, want false")
	}
	if !strings.Contains(note, "field-miss probe failed") {
		t.Fatalf("got note %q, want it to explain the recon failure", note)
	}
}

// TestDispatchScanLeaf_MissingIdorField_DeterministicCandidateUnblocksRetry
// is the end-to-end proof: a scan.leaf dispatch that would otherwise be
// permanently skipped for a missing EndpointTemplate now gets a real recon
// probe, an auto-filled candidate, and a genuine retried dispatch against a
// real HTTP server — LT-138 item 1's whole point (docs/follow-up.md).
func TestDispatchScanLeaf_MissingIdorField_DeterministicCandidateUnblocksRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	leaf := &agenttask.PlanNode{ID: "leaf1", Target: srv.URL, Detector: "idor", Status: agenttask.StatusPending}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	var findings []detectors.Finding

	fresh := &recon.ReconResult{Endpoints: []recon.EndpointFact{{URL: srv.URL + "/orders/42", StatusCode: 200}}}
	cfg := Config{
		BaseScanConfig: scanner.Config{Concurrency: 1, RateLimit: 10, Timeout: 5 * time.Second},
		Recon:          &fakeRecon{result: fresh},
		ReconTimeout:   5 * time.Second,
	}

	summary, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf", NodeID: "leaf1"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if strings.Contains(summary, "no --endpoint given") {
		t.Fatalf("got summary %q, want the missing-field skip resolved before returning", summary)
	}
	if !strings.Contains(summary, "auto-filled") {
		t.Fatalf("got summary %q, want it to note the deterministic auto-fill", summary)
	}
	if !strings.Contains(summary, "finding(s)") {
		t.Fatalf("got summary %q, want the retried dispatch to have actually run", summary)
	}
	if leaf.Status != agenttask.StatusDone {
		t.Fatalf("got leaf status %q, want %q — the retried dispatch should have completed it", leaf.Status, agenttask.StatusDone)
	}
}

// TestDispatchScanLeaf_NonFieldMissDetector_SkipReturnedUnchanged proves the
// retry machinery never engages for a detector fieldsuggest.Deterministic
// doesn't cover (misconfig has no required-field concept at all) — a skip
// for any other reason passes through exactly as before.
func TestDispatchScanLeaf_NonFieldMissDetector_SkipReturnedUnchanged(t *testing.T) {
	leaf := &agenttask.PlanNode{ID: "leaf1", Target: "https://example.test", Detector: "businesslogic", Status: agenttask.StatusPending}
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Children: []*agenttask.PlanNode{leaf}}}
	var findings []detectors.Finding
	fr := &fakeRecon{}
	cfg := Config{BaseScanConfig: scanner.Config{Concurrency: 1, RateLimit: 10, Timeout: 5 * time.Second}, Recon: fr, ReconTimeout: 5 * time.Second}

	summary, err := dispatch(context.Background(), cfg, tree, &findings, llmfallback.Action{Kind: "scan.leaf", NodeID: "leaf1"})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !strings.Contains(summary, "skipped:") {
		t.Fatalf("got summary %q, want a skip (businesslogic requires --allow-writes)", summary)
	}
	if fr.calls != 0 {
		t.Fatalf("got %d recon call(s), want 0 — businesslogic isn't in fieldMissDetectors, no probe should ever fire", fr.calls)
	}
}
