package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tuangatech/hacker-five/pkg/detectors"
)

func finding(id, target string) detectors.Finding { return detectors.Finding{ID: id, Target: target} }

func TestGradeRun_ExpectedPrefixesAndKnownVulns(t *testing.T) {
	known := []KnownVuln{
		{ID: "bola-reports", EndpointContains: "/api/reports", IDPrefixes: []string{"idor-"}},
		{ID: "ssrf-contact", EndpointContains: "contact", IDPrefixes: []string{"ssrf-"}},
		{ID: "any-finding-on-env", EndpointContains: "/.env"},
	}
	findings := []detectors.Finding{
		finding("idor-1", "https://x.test/API/reports?id=3"), // endpoint match is case-insensitive
		finding("idor-2", "https://x.test/api/other"),        // right class, wrong endpoint: not the reports vuln
		finding("misconfig-missing-header-hsts", "https://x.test/"),
		finding("misconfig-exposed-path-.env", "https://x.test/.env"),
		finding("nuclei-something-odd", "https://x.test/"), // matches nothing
	}
	g := GradeRun(findings, []string{"misconfig-missing-header-", "nuclei-php-detect"}, known)

	assert.Equal(t, 5, g.Findings)
	assert.Equal(t, 2, g.ExpectedTotal)
	assert.Equal(t, 1, g.ExpectedHit)
	assert.Equal(t, []string{"nuclei-php-detect"}, g.MissedPrefixes)
	assert.Equal(t, 3, g.KnownTotal)
	assert.Equal(t, []string{"bola-reports", "any-finding-on-env"}, g.KnownHitIDs)
	assert.Equal(t, []string{"ssrf-contact"}, g.KnownMissedIDs)
	// idor-2 and nuclei-something-odd match no expected prefix and no known vuln.
	assert.Equal(t, 2, g.Unlabeled)
}

func TestGradeRun_EmptyGroundTruthStillCountsFindings(t *testing.T) {
	g := GradeRun([]detectors.Finding{finding("a", "t")}, nil, nil)
	assert.Equal(t, 1, g.Findings)
	assert.Equal(t, 1, g.Unlabeled, "with no ground truth every finding is unlabeled")
	assert.Zero(t, g.ExpectedTotal+g.KnownTotal)
}

func TestLoadKnownVulns_RejectsAnEntryThatWouldMatchEverything(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
		return p
	}
	_, err := LoadKnownVulns(write("neither.json", `{"vulns":[{"id":"x","baseline":"unknown"}]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "neither endpoint_contains nor id_prefixes")

	_, err = LoadKnownVulns(write("dup.json", `{"vulns":[{"id":"x","id_prefixes":["a"]},{"id":"x","id_prefixes":["b"]}]}`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")

	_, err = LoadKnownVulns(write("noid.json", `{"vulns":[{"id_prefixes":["a"]}]}`))
	require.Error(t, err)
}

// The shipped fixtures must load and be self-consistent; a typo here would
// silently turn a known vulnerability into an always-missed one.
func TestShippedKnownVulnsFixturesLoad(t *testing.T) {
	for _, sc := range OrchestratorScenarios {
		if sc.KnownVulnsFile == "" {
			continue
		}
		kf, err := LoadKnownVulns(filepath.Join("..", "..", sc.KnownVulnsFile))
		require.NoError(t, err, sc.Name)
		require.NotEmpty(t, kf.Vulns, sc.Name)
		for _, v := range kf.Vulns {
			assert.Contains(t, []string{"found", "missed", "unknown"}, v.Baseline, "%s: baseline must be found|missed|unknown", v.ID)
			assert.NotEmpty(t, v.Source, "%s: a ground-truth entry must cite where it came from", v.ID)
		}
	}
}

func TestParseAgentStream_KilledRunKeepsStreamedFindings(t *testing.T) {
	stream := `{"type":"finding","finding":{"id":"idor-1","target":"https://x/a"}}
{"type":"finding","finding":{"id":"idor-2","target":"https://x/b"}}
`
	p, err := ParseAgentStream([]byte(stream))
	require.NoError(t, err)
	assert.False(t, p.SawResult)
	assert.Len(t, p.Findings, 2)
}

func TestParseAgentStream_FinalResultIsAuthoritative(t *testing.T) {
	stream := `{"type":"finding","finding":{"id":"idor-1","target":"https://x/a"}}
{"type":"result","result":{"Findings":[{"id":"idor-1","target":"https://x/a"},{"id":"authbypass-jwt-x","target":"https://x/b"}],"Iterations":3,"FastLaneTurns":11,"SpendUSD":0.0123,"Degraded":"model unavailable"}}
`
	p, err := ParseAgentStream([]byte(stream))
	require.NoError(t, err)
	assert.True(t, p.SawResult)
	assert.Len(t, p.Findings, 2, "the result's list is a superset of what streamed")
	assert.Equal(t, 3, p.Result.Iterations)
	assert.Equal(t, 11, p.Result.FastLaneTurns)
	assert.InDelta(t, 0.0123, p.Result.SpendUSD, 1e-9)
	assert.Equal(t, "model unavailable", p.Result.Degraded)

	_, err = ParseAgentStream([]byte("not json\n"))
	assert.Error(t, err)
}

func TestSummarize_AggregatesPerLabAndArmWithRange(t *testing.T) {
	rec := func(arm string, run, hit, unl int, cost float64, saw bool, deg string) RunRecord {
		return RunRecord{Lab: "crAPI", Arm: arm, Run: run, ExpectedHit: 1, ExpectedTotal: 2, KnownHit: hit, KnownTotal: 4,
			Unlabeled: unl, CostUSD: cost, ModelTurns: 5, WallSeconds: 100, SawResult: saw, Degraded: deg}
	}
	sums := Summarize([]RunRecord{
		rec("fast-lane+model", 1, 2, 3, 0.01, true, ""),
		rec("fast-lane+model", 2, 4, 5, 0.03, false, ""),
		rec("no-model", 1, 1, 0, 0, true, "the model is disabled"),
	})
	require.Len(t, sums, 2)

	// sorted by lab then arm: fast-lane+model, no-model
	m := sums[0]
	assert.Equal(t, "fast-lane+model", m.Arm)
	assert.Equal(t, 2, m.Runs)
	assert.Equal(t, 1, m.Failed, "a run with no result event counts as failed")
	assert.InDelta(t, 0.75, m.KnownRecall.Mean, 1e-9)
	assert.InDelta(t, 0.5, m.KnownRecall.Min, 1e-9)
	assert.InDelta(t, 1.0, m.KnownRecall.Max, 1e-9)
	assert.InDelta(t, 0.02, m.CostUSD.Mean, 1e-9)
	assert.Equal(t, 0, m.Degraded)

	c := sums[1]
	assert.Equal(t, "no-model", c.Arm)
	assert.Equal(t, 1, c.Degraded)

	table := FormatSummary(sums)
	assert.Contains(t, table, "no-model*", "an arm with a degraded run is starred")
	assert.Contains(t, table, "50-100", "the range behind a mean is shown, not just the mean")
	assert.Equal(t, 4, strings.Count(table, "\n"), "header, two rows, footnote")
}

func TestModelFromStderr(t *testing.T) {
	assert.Equal(t, "openrouter:openai/gpt-5.6-luna", ModelFromStderr("agent: [info] x\nagent: model: openrouter:openai/gpt-5.6-luna\nagent: [info] y\n"))
	assert.Equal(t, "none", ModelFromStderr("agent: model: none\n"))
	assert.Empty(t, ModelFromStderr("agent: [info] no model line\n"))
}

// Runs under different models are never averaged together.
func TestSummarize_DoesNotMergeAcrossModels(t *testing.T) {
	mk := func(model string) RunRecord {
		return RunRecord{Lab: "crAPI", Arm: "fast-lane+model", Model: model, ExpectedTotal: 1, SawResult: true}
	}
	sums := Summarize([]RunRecord{mk("openrouter:a"), mk("openrouter:b"), mk("openrouter:a")})
	require.Len(t, sums, 2)
	assert.Equal(t, "openrouter:a", sums[0].Model)
	assert.Equal(t, 2, sums[0].Runs)
	assert.Equal(t, "openrouter:b", sums[1].Model)
	assert.Equal(t, 1, sums[1].Runs)
}

func TestArms_ControlFirstNoModelAndNamesUnique(t *testing.T) {
	require.NotEmpty(t, Arms)
	assert.Equal(t, "no-model", Arms[0].Name, "the control arm comes first")
	assert.False(t, Arms[0].NeedsModel)
	assert.Contains(t, Arms[0].ExtraArgs, "--no-model")
	seen := map[string]bool{}
	for _, a := range Arms {
		assert.False(t, seen[a.Name], "duplicate arm %q", a.Name)
		seen[a.Name] = true
	}
}

func TestAgentArgs_BuildsTheSameCommandForEveryCaller(t *testing.T) {
	t.Setenv("CRAPI_OWNER_TOKEN", "own")
	t.Setenv("CRAPI_OTHER_TOKEN", "oth")
	var crapi OrchestratorScenario
	for _, sc := range OrchestratorScenarios {
		if strings.HasPrefix(sc.Name, "crAPI") {
			crapi = sc
		}
	}
	args := crapi.AgentArgs("http://localhost:8888", "/tmp/scope.txt", "--no-model")
	joined := strings.Join(args, " ")
	assert.True(t, strings.HasPrefix(joined, "agent -t http://localhost:8888 --recon-depth full --scope /tmp/scope.txt"), joined)
	assert.Contains(t, joined, "--auth-token own")
	assert.Contains(t, joined, "--other-auth-token oth")
	assert.Equal(t, "--no-model", args[len(args)-1], "an arm's flags come last")
}
