package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// TestRun_ModelFailsRepeatedly_DegradesInsteadOfErroring guards LT-173: two
// consecutive failed decision calls used to end the run with an error (exit 1)
// and 13 leaves untouched. Now the model is dropped, the leaves that need no
// decision still run, and the run ends cleanly with the reason recorded.
func TestRun_ModelFailsRepeatedly_DegradesInsteadOfErroring(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{
		actions:  []llmfallback.Action{{Kind: "stop"}},
		failErr:  errors.New("context deadline exceeded"),
		failLeft: 1 << 20, // every call fails
	}
	cfg := fastLaneConfig(srv, client)
	cfg.FastLane = false // the lane is off: only the degrade path may run the leaf
	var logged []string
	cfg.OnLog = func(_, msg string) { logged = append(logged, msg) }

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run must degrade, not fail: %v", err)
	}
	if client.failed != MaxConsecutiveLLMFailures {
		t.Fatalf("model asked %d time(s), want exactly %d before it is given up on", client.failed, MaxConsecutiveLLMFailures)
	}
	if result.Degraded == "" || !strings.Contains(result.Degraded, "context deadline exceeded") {
		t.Fatalf("Degraded = %q, want the reason recorded", result.Degraded)
	}
	if result.FastLaneTurns != 1 {
		t.Fatalf("FastLaneTurns = %d, want 1: the parameter-free leaf still runs without the model", result.FastLaneTurns)
	}
	for _, leaf := range agenttask.Leaves(result.Tree.Root) {
		if leaf.Status != agenttask.StatusDone {
			t.Errorf("leaf %s status = %s, want done (it needed no decision)", leaf.ID, leaf.Status)
		}
	}
	if !strings.Contains(strings.Join(logged, "\n"), "degraded:") {
		t.Errorf("the degradation must be logged, got %q", logged)
	}
}

// A leaf that does need a decision (an authenticated-route authbypass leaf) is
// the thing a degraded run cannot do; it must be counted, not silently dropped.
func TestRun_Degraded_CountsLeavesThatNeededADecision(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{actions: []llmfallback.Action{{Kind: "stop"}}, failErr: errors.New("boom"), failLeft: 1 << 20}
	cfg := fastLaneConfig(srv, client)
	cfg.Recon = &fakeRecon{result: &recon.ReconResult{
		Target: srv.URL,
		Endpoints: []recon.EndpointFact{
			{URL: srv.URL + "/", StatusCode: 200, Source: "httpx"},
			{URL: srv.URL + "/api/private", Method: "GET", Source: "api-spec", AuthRequired: true},
		},
	}}

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	pending := 0
	for _, leaf := range agenttask.Leaves(result.Tree.Root) {
		if leaf.Status == agenttask.StatusPending || leaf.Status == agenttask.StatusUnresolved {
			pending++
		}
	}
	if pending == 0 {
		t.Skip("fixture assumption broke: no decision-needing leaf was produced; the count below would be vacuous")
	}
	if !strings.Contains(result.Degraded, "left undispatched") || strings.Contains(result.Degraded, " 0 leaf/leaves") {
		t.Fatalf("Degraded = %q, want a non-zero undispatched count (%d leaf/leaves still pending)", result.Degraded, pending)
	}
}

// One transient failure costs a retry, not the model for the rest of the run.
func TestRun_SingleTransientModelFailure_IsRetriedNotDegraded(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{
		actions:  []llmfallback.Action{{Kind: "registry.lookup", Rationale: "look"}, {Kind: "stop", Rationale: "done"}},
		failErr:  errors.New("transient"),
		failLeft: 1,
	}
	cfg := fastLaneConfig(srv, client)
	cfg.FastLane = false
	cfg.MinIterations = 1

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Degraded != "" {
		t.Fatalf("Degraded = %q, want empty: one failure then success is a healthy run", result.Degraded)
	}
	if client.failed != 1 || client.calls == 0 {
		t.Fatalf("failed=%d calls=%d, want the failure followed by real decisions", client.failed, client.calls)
	}
}

// Failures must reset on success: failure, success, failure is not "two in a row".
func TestRun_NonConsecutiveModelFailuresDoNotDegrade(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{
		actions:    []llmfallback.Action{{Kind: "registry.lookup"}, {Kind: "registry.lookup"}, {Kind: "stop"}},
		failErr:    errors.New("transient"),
		failEveryN: 2, // calls 2, 4, ...: fail, ok, fail, ok
	}
	cfg := fastLaneConfig(srv, client)
	cfg.FastLane = false
	cfg.MinIterations = 2

	result, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Degraded != "" {
		t.Fatalf("Degraded = %q: alternating failures must not add up to a degradation", result.Degraded)
	}
}

// A cancelled run is not a model outage and must still be an error.
func TestRun_ModelErrorWithCancelledContext_StillErrors(t *testing.T) {
	srv := fastLaneTargetServer(t)
	client := &fakeLLMClient{actions: []llmfallback.Action{{Kind: "stop"}}, failErr: context.Canceled, failLeft: 1 << 20}
	ctx, cancel := context.WithCancel(context.Background())
	cfg := fastLaneConfig(srv, client)
	cfg.FastLane = false
	cfg.Recon = &cancellingRecon{cancel: cancel, result: cfg.Recon.(*fakeRecon).result}

	if _, err := Run(ctx, cfg); err == nil {
		t.Fatal("a cancelled context must end the run with an error, not be reported as a model outage")
	}
}
