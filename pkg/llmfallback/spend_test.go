package llmfallback

import (
	"context"
	"strings"
	"testing"
)

func TestGlobalSpendCeiling_DefaultAndEnvOverride(t *testing.T) {
	t.Setenv(envGlobalSpendCeiling, "")
	if got := GlobalSpendCeilingUSD(); got != defaultGlobalSpendCeilingUSD {
		t.Fatalf("got %v, want default %v", got, defaultGlobalSpendCeilingUSD)
	}

	t.Setenv(envGlobalSpendCeiling, "0.50")
	if got := GlobalSpendCeilingUSD(); got != 0.50 {
		t.Fatalf("got %v, want 0.50 from env override", got)
	}
}

func TestGlobalSpend_AccumulatesAcrossAddCalls(t *testing.T) {
	resetGlobalSpendForTest()
	addGlobalSpend(0.10)
	addGlobalSpend(0.25)
	if got := GlobalSpendSoFar(); got < 0.34 || got > 0.36 {
		t.Fatalf("got %v, want ~0.35", got)
	}
}

func TestGlobalSpend_ZeroCeilingNeverExceeded(t *testing.T) {
	resetGlobalSpendForTest()
	t.Setenv(envGlobalSpendCeiling, "0")
	addGlobalSpend(1000)
	if globalSpendExceeded() {
		t.Fatal("a zero/unset ceiling must never report exceeded")
	}
}

// TestComplete_FrontierTier_RefusesWhenGlobalCeilingAlreadyExceeded is the
// real integration point: complete must refuse a frontier-tier call before
// ever making a network request once the process-lifetime ceiling is
// already spent — proven here by never configuring a reachable OpenRouter
// endpoint at all; if the guard didn't fire first, this test would hang or
// fail on a real network call instead of returning immediately.
func TestComplete_FrontierTier_RefusesWhenGlobalCeilingAlreadyExceeded(t *testing.T) {
	resetGlobalSpendForTest()
	t.Setenv(envGlobalSpendCeiling, "0.10")
	addGlobalSpend(0.10) // already at the ceiling

	c := &Client{openRouterKey: "dummy-key", openRouterModel: "test-model"}
	_, cost, err := c.complete(context.Background(), tierFrontier, "system", "user")
	if err == nil {
		t.Fatal("expected an error once the global spend ceiling is already reached")
	}
	if !strings.Contains(err.Error(), "spend ceiling") {
		t.Fatalf("got %q, want a spend-ceiling-shaped error", err.Error())
	}
	if cost != 0 {
		t.Fatalf("cost = %v, want 0 (no call was made)", cost)
	}
}
