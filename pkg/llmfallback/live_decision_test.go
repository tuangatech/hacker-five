package llmfallback

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/tuangatech/hacker-five/pkg/agenttask"
)

// TestLive_DecisionEnvelope compares the decision call as it was (no cap, no
// reasoning control) with LT-173's envelope against whatever model the
// environment is configured for. It exists because `reasoning` support is
// per-model: the request field may be ignored, may be honored, or may starve
// the answer of tokens — none of which a unit test can tell. Skipped unless
// HACKERFIVE_LIVE_LLM=1 (it spends a few cents); it reports, it does not gate.
func TestLive_DecisionEnvelope(t *testing.T) {
	if os.Getenv("HACKERFIVE_LIVE_LLM") != "1" {
		t.Skip("HACKERFIVE_LIVE_LLM != 1 — live model probe skipped")
	}
	c, err := New()
	if err != nil {
		t.Skipf("no LLM tier: %v", err)
	}
	t.Logf("model: %s", c.ModelLabel())

	pending := agenttask.StatusPending
	tree := &agenttask.PlanTree{Root: &agenttask.PlanNode{ID: "root", Target: "example.test"}}
	for i, d := range []string{"idor", "authbypass", "ssrf", "CVE-2024-0001", "CVE-2024-0002", "sqli"} {
		tree.Root.Children = append(tree.Root.Children, &agenttask.PlanNode{
			ID: fmt.Sprintf("leaf-%d", i+1), Target: "https://example.test/api", Detector: d, Status: pending, Priority: 30,
		})
	}
	prompt := buildOrchestratePrompt(tree, sampleOrchestrateCatalog, nil, RunDigest{Recon: []string{"technologies: nginx (example.test, high)"}})

	trials := 3
	if n, err := strconv.Atoi(os.Getenv("HACKERFIVE_LIVE_TRIALS")); err == nil && n > 0 {
		trials = n
	}
	type arm struct {
		name string
		opts callOpts
		to   time.Duration
	}
	for _, a := range []arm{
		{"before (no cap, no reasoning control)", callOpts{}, requestTimeout},
		{"envelope (cap + effort from env/default)", decisionCallOpts(), decisionTimeout},
	} {
		var total time.Duration
		var cost float64
		ok := 0
		for i := 0; i < trials; i++ {
			start := time.Now()
			text, c1, err := c.completeBestAvailableWith(context.Background(), orchestrateSystemPrompt, prompt, "live-probe", a.to, a.opts)
			d := time.Since(start)
			total += d
			cost += c1
			var act Action
			decErr := error(nil)
			if err == nil {
				decErr = decodeJSONResponse(text, &act)
			}
			if err == nil && decErr == nil && orchestrateActionKinds[act.Kind] {
				ok++
			}
			t.Logf("%s trial %d: %s err=%v decodeErr=%v kind=%q", a.name, i+1, d.Round(time.Millisecond), err, decErr, act.Kind)
		}
		t.Logf("%s: %d/%d valid decisions, mean latency %s, total cost $%.5f", a.name, ok, trials, (total / time.Duration(trials)).Round(time.Millisecond), cost)
	}
}
