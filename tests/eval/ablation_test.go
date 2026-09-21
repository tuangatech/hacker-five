//go:build eval

package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// TestAblation is docs/94-llm-finding-capability-strategy.md Phase 0's
// harness: it runs every Arm (ablation_arms.go) against every configured lab,
// N times each, grades each run against both ground-truth lists (grade.go),
// appends one JSON line per run to a results file, and logs the comparison
// table. It reports; it does not gate — whether an arm is better is read from
// the table, with the run count in mind.
//
// Like the other eval tests it needs live labs and is opt-in (-tags eval). Run
// one lab at a time with the other lab containers stopped (docs/20-setup-
// testing-targets.md): the labs share a host and a neighbouring lab's stack
// leaks into recon's tech attribution (LT-169). Model-driven arms spend real
// money; the arm list and HACKERFIVE_ABLATION_RUNS set how much.
//
// Environment:
//
//	HACKERFIVE_ABLATION_RUNS     runs per (lab, arm), default 1 (a single run of a
//	                             model-driven arm is an anecdote; use 3+ to compare)
//	HACKERFIVE_ABLATION_ARMS     comma-separated arm names, default all
//	HACKERFIVE_ABLATION_LABS     comma-separated substrings of a scenario name, default all
//	HACKERFIVE_ABLATION_TIMEOUT  per-run limit, default 45m
//	HACKERFIVE_ABLATION_OUT      results directory, default tests/eval/results
//	HACKERFIVE_ABLATION_TEMPLATES  replace the scenario's --templates directory (the full synced corpus
//	                             makes one misconfig sweep take 16+ minutes at the default rate, LT-179)
//	HACKERFIVE_ABLATION_EXTRA_ARGS  extra `hackerfive agent` flags, space-separated, added to every run
//	                             of every arm (e.g. "--rate-limit 60")
//
// Both overrides are recorded on every result (RunRecord.Settings). They apply equally to all
// arms of an invocation, so a comparison inside one results file is like-for-like; do not compare
// numbers across files with different settings.
func TestAblation(t *testing.T) {
	runs := envInt("HACKERFIVE_ABLATION_RUNS", 1)
	timeout := 45 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("HACKERFIVE_ABLATION_TIMEOUT")); err == nil && d > 0 {
		timeout = d
	}
	armFilter := csvSet(os.Getenv("HACKERFIVE_ABLATION_ARMS"))
	labFilter := csvSet(os.Getenv("HACKERFIVE_ABLATION_LABS"))
	for name := range armFilter {
		if _, ok := ArmByName(name); !ok {
			t.Fatalf("HACKERFIVE_ABLATION_ARMS names an unknown arm %q", name)
		}
	}

	templatesOverride := os.Getenv("HACKERFIVE_ABLATION_TEMPLATES")
	extraArgs := strings.Fields(os.Getenv("HACKERFIVE_ABLATION_EXTRA_ARGS"))
	settings := strings.TrimSpace("templates=" + templatesOverride + " extra=" + strings.Join(extraArgs, " "))

	outDir := os.Getenv("HACKERFIVE_ABLATION_OUT")
	if outDir == "" {
		outDir = filepath.Join(repoRoot(), "tests", "eval", "results")
	}
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	outPath := filepath.Join(outDir, "ablation-"+time.Now().Format("20060102-150405")+".jsonl")
	out, err := os.Create(outPath)
	require.NoError(t, err)
	defer func() { _ = out.Close() }()
	enc := json.NewEncoder(out)

	_, modelErr := llmfallback.New()

	var records []RunRecord
	for _, sc := range OrchestratorScenarios {
		if len(labFilter) > 0 && !matchesAnySubstring(sc.Name, labFilter) {
			continue
		}
		if missing := missingEnv(sc.RequiredEnv); missing != "" {
			t.Logf("%s: skipped, %s not set", sc.Name, missing)
			continue
		}

		if templatesOverride != "" {
			sc.Templates = templatesOverride
		}
		var expected expectedFindings
		raw, err := os.ReadFile(filepath.Join(repoRoot(), sc.ExpectedFile))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &expected))
		var prefixes []string
		for _, p := range expected.ExpectedIDPrefixes {
			if !contains(sc.SkipPrefixes, p) {
				prefixes = append(prefixes, p)
			}
		}
		var known []KnownVuln
		if sc.KnownVulnsFile != "" {
			kf, err := LoadKnownVulns(filepath.Join(repoRoot(), sc.KnownVulnsFile))
			require.NoError(t, err)
			known = kf.Vulns
		}

		for _, arm := range Arms {
			if len(armFilter) > 0 && !armFilter[arm.Name] {
				continue
			}
			if arm.NeedsModel && modelErr != nil {
				t.Logf("%s / %s: skipped, no LLM tier configured (%v)", sc.Name, arm.Name, modelErr)
				continue
			}
			for run := 1; run <= runs; run++ {
				rec := runAblationOnce(t, sc, arm, run, prefixes, known, timeout, extraArgs)
				rec.Settings = settings
				records = append(records, rec)
				require.NoError(t, enc.Encode(rec)) // written per run, so a killed harness keeps what finished
				t.Logf("%s / %s [%s] run %d: %d finding(s), expected %d/%d, known %d/%d, unlabeled %d, $%.4f, %.0fs, result=%v",
					rec.Lab, rec.Arm, rec.Model, rec.Run, rec.Findings, rec.ExpectedHit, rec.ExpectedTotal, rec.KnownHit, rec.KnownTotal,
					rec.Unlabeled, rec.CostUSD, rec.WallSeconds, rec.SawResult)
			}
		}
	}

	if len(records) == 0 {
		t.Skip("no (lab, arm) ran: set the lab env vars (docs/20-setup-testing-targets.md) and check the arm/lab filters")
	}
	t.Logf("results written to %s\n\n%s", outPath, FormatSummary(Summarize(records)))
}

func runAblationOnce(t *testing.T, sc OrchestratorScenario, arm Arm, run int, prefixes []string, known []KnownVuln, timeout time.Duration, extraArgs []string) RunRecord {
	t.Helper()
	target := sc.Target()
	scopeFile := filepath.Join(t.TempDir(), "scope.txt")
	require.NoError(t, os.WriteFile(scopeFile, []byte(hostScopeEntry(target)+"\n"), 0o644))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, sc.AgentArgs(target, scopeFile, append(append([]string{}, arm.ExtraArgs...), extraArgs...)...)...)
	cmd.Dir = repoRoot()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	start := time.Now()
	runErr := cmd.Run()
	wall := time.Since(start).Seconds()

	errText := ""
	if runErr != nil {
		errText = runErr.Error()
		t.Logf("%s / %s run %d: agent exited with error (recorded, not fatal): %v\nstderr tail:\n%s", sc.Name, arm.Name, run, runErr, tail(stderr.String(), 1500))
	}
	parsed, parseErr := ParseAgentStream(stdout.Bytes())
	if parseErr != nil {
		errText += " parse: " + parseErr.Error()
	}
	rec := NewRunRecord(sc.Name, arm.Name, run, parsed, GradeRun(parsed.Findings, prefixes, known), wall, errText)
	rec.Model = ModelFromStderr(stderr.String())
	return rec
}

func envInt(key string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil && n > 0 {
		return n
	}
	return def
}

func csvSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

func matchesAnySubstring(name string, subs map[string]bool) bool {
	for s := range subs {
		if strings.Contains(strings.ToLower(name), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func missingEnv(vars []string) string {
	for _, v := range vars {
		if os.Getenv(v) == "" {
			return v
		}
	}
	return ""
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
