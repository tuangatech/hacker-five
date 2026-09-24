//go:build eval

package eval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// TestAblationRealScope is LT-183 item (j): every TestAblation run so far is a
// 6-25-leaf tree against a lab container, so doc94's own conclusion —
// no-model+all-leaves reproduces the model arms on crAPI/vAPI/Juice Shop, so
// selection is unproven at scale rather than shown useless — has never been
// checked against anything resembling a real target's leaf count. This drives
// the same arms (ablation_arms.go) against a real, owned scope instead of a
// lab, reusing every measurement primitive the lab harness uses
// (runAblationOnce, ParseAgentStream, Summarize, FormatSummary,
// FormatFindingDiff, JSONL output). One real difference: no known-vulns or
// expected-findings fixture exists for a live program, so grading is empty
// here and the comparison is arms against each other — finding count,
// finding-ID diff (LT-183 i), cost, wall time — not a recall number.
//
// No target or scope is hardcoded: this is a real, in-scope, owned target,
// not a lab, and CLAUDE.md's rule against naming one in generic/LLM-visible
// code applies just as much to shared test infra — the operator supplies
// both through environment, and this file never names either.
//
// Environment (beyond TestAblation's own HACKERFIVE_ABLATION_RUNS/ARMS/
// TIMEOUT/OUT/TEMPLATES/EXTRA_ARGS/RECON_AUTH, all reused as-is):
//
//	HACKERFIVE_ABLATION_REALSCOPE_TARGET  base URL to scan, e.g. https://example.com (required)
//	HACKERFIVE_ABLATION_REALSCOPE_SCOPE   path to a scope file, pkg/scanner/scope's format
//	                                      (bare hostnames, "*." wildcard allowed) — NOT
//	                                      derived from the target the way a lab scenario's
//	                                      single-host scope is, since a wider, multi-host
//	                                      tree is the whole point (required)
//	HACKERFIVE_ABLATION_REALSCOPE_DEPTH   --recon-depth, default "full"
func TestAblationRealScope(t *testing.T) {
	target := os.Getenv("HACKERFIVE_ABLATION_REALSCOPE_TARGET")
	scopeSrc := os.Getenv("HACKERFIVE_ABLATION_REALSCOPE_SCOPE")
	if target == "" || scopeSrc == "" {
		t.Skip("set HACKERFIVE_ABLATION_REALSCOPE_TARGET and HACKERFIVE_ABLATION_REALSCOPE_SCOPE to run (LT-183 j, docs/94-llm-finding-capability-strategy.md)")
	}
	depth := os.Getenv("HACKERFIVE_ABLATION_REALSCOPE_DEPTH")
	if depth == "" {
		depth = "full"
	}
	scopeBytes, err := os.ReadFile(scopeSrc)
	require.NoError(t, err)

	runs := envInt("HACKERFIVE_ABLATION_RUNS", 1)
	timeout := 45 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("HACKERFIVE_ABLATION_TIMEOUT")); err == nil && d > 0 {
		timeout = d
	}
	armFilter := csvSet(os.Getenv("HACKERFIVE_ABLATION_ARMS"))
	for name := range armFilter {
		if _, ok := ArmByName(name); !ok {
			t.Fatalf("HACKERFIVE_ABLATION_ARMS names an unknown arm %q", name)
		}
	}
	templatesOverride := os.Getenv("HACKERFIVE_ABLATION_TEMPLATES")
	extraArgs := strings.Fields(os.Getenv("HACKERFIVE_ABLATION_EXTRA_ARGS"))
	reconAuth := os.Getenv("HACKERFIVE_ABLATION_RECON_AUTH") != ""
	settings := strings.TrimSpace("templates=" + templatesOverride + " extra=" + strings.Join(extraArgs, " "))
	if reconAuth {
		settings += " recon-auth=true"
	}

	outDir := os.Getenv("HACKERFIVE_ABLATION_OUT")
	if outDir == "" {
		outDir = filepath.Join(repoRoot(), "tests", "eval", "results")
	}
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	outPath := filepath.Join(outDir, "ablation-realscope-"+time.Now().Format("20060102-150405")+".jsonl")
	out, err := os.Create(outPath)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	enc := json.NewEncoder(out)

	_, modelErr := llmfallback.New()

	sc := OrchestratorScenario{
		Name:      "real-scope (orchestrator)",
		Target:    func() string { return target },
		Depth:     depth,
		Templates: templatesOverride,
	}
	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(scopeFile, scopeBytes, 0o644))

	var records []RunRecord
	for _, arm := range Arms {
		if len(armFilter) > 0 && !armFilter[arm.Name] {
			continue
		}
		if arm.NeedsModel && modelErr != nil {
			t.Logf("%s: skipped, no LLM tier configured (%v)", arm.Name, modelErr)
			continue
		}
		for run := 1; run <= runs; run++ {
			rec := runAblationOnce(t, sc, scopeFile, arm, run, nil, nil, timeout, extraArgs, reconAuth)
			rec.Settings = settings
			records = append(records, rec)
			require.NoError(t, enc.Encode(rec)) // written per run, so a killed harness keeps what finished
			t.Logf("%s [%s] run %d: %d finding(s), unlabeled %d, $%.4f, %.0fs, result=%v",
				rec.Arm, rec.Model, rec.Run, rec.Findings, rec.Unlabeled, rec.CostUSD, rec.WallSeconds, rec.SawResult)
		}
	}

	if len(records) == 0 {
		t.Skip("no arm ran: check HACKERFIVE_ABLATION_ARMS")
	}
	// No known-vulns ground truth, so no "known vulnerability lost" section — but
	// FormatMissAttribution still prints the recon-endpoint stage histogram
	// (coverage.EndpointStages doesn't need a known list), which is the part of
	// this run that actually answers "how big is the tree".
	t.Logf("results written to %s\n\n%s\nRecon-endpoint stage histogram:%s\nFinding-ID diff across arms (LT-183 i/j):%s",
		outPath, FormatSummary(Summarize(records)), FormatMissAttribution(records), FormatFindingDiff(records))
}
