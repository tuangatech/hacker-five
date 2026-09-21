package eval

import "os"

// OrchestratorScenario is docs/93-implementation-plan-agent-orchestrator.md
// M5's third eval driver: the same lab targets and
// tests/fixtures/expected-findings/*.json fixtures as AgentScenario
// (agent_run.go, the existing MCP-plan mode), resolved through
// `hackerfive agent` (pkg/orchestrator's LLM-driven loop) instead of an
// MCP client session or a hand-built `scan` command. Unlike AgentScenario, a
// Header is supported directly — `hackerfive agent`'s --header flag has no
// equivalent to the MCP recon tool's documented header-less input (see
// agent_run.go's "Known, named gap" comment on AgentScenario), so DVWA's
// login-gated content is reachable here the same way challenges.go's
// baseline Scenario reaches it.
type OrchestratorScenario struct {
	Name              string
	ExpectedFile      string
	RequiredEnv       []string
	Target            func() string
	Depth             string        // --recon-depth
	AuthTokenEnv      string        // env var carrying --auth-token, "" if none
	OtherAuthTokenEnv string        // env var carrying --other-auth-token, "" if none
	Header            func() string // raw "Name: Value" for --header, nil if none
	Templates         string        // --templates override, "" leaves the CLI default (full bundled+synced corpus)
	SkipPrefixes      []string

	// KnownVulnsFile is the tests/fixtures/known-vulns/*.json ground truth the
	// ablation harness grades against, "" if this lab has none yet (only crAPI
	// does so far). See grade.go for why it exists beside ExpectedFile.
	KnownVulnsFile string
}

// AgentArgs builds the `hackerfive agent` command line for this scenario, with
// extra (an ablation arm's flags) appended. TestOrchestratorEvalHarness and the
// ablation harness both use it so they cannot drift into running different
// commands.
func (sc OrchestratorScenario) AgentArgs(target, scopeFile string, extra ...string) []string {
	args := []string{"agent", "-t", target, "--recon-depth", sc.Depth, "--scope", scopeFile}
	if sc.AuthTokenEnv != "" {
		args = append(args, "--auth-token", os.Getenv(sc.AuthTokenEnv))
	}
	if sc.OtherAuthTokenEnv != "" {
		args = append(args, "--other-auth-token", os.Getenv(sc.OtherAuthTokenEnv))
	}
	if sc.Header != nil {
		args = append(args, "--header", sc.Header())
	}
	if sc.Templates != "" {
		args = append(args, "--templates", sc.Templates)
	}
	return append(args, extra...)
}

// OrchestratorScenarios mirrors AgentScenarios' four live lab targets.
var OrchestratorScenarios = []OrchestratorScenario{
	{
		Name:         "DVWA (orchestrator)",
		ExpectedFile: "tests/fixtures/expected-findings/dvwa.json",
		RequiredEnv:  []string{"DVWA_BASE_URL", "DVWA_COOKIE"},
		Target:       func() string { return os.Getenv("DVWA_BASE_URL") },
		Depth:        "active",
		Header:       func() string { return "Cookie: " + os.Getenv("DVWA_COOKIE") + "; security=low" },
	},
	{
		Name:         "Juice Shop (orchestrator)",
		ExpectedFile: "tests/fixtures/expected-findings/juiceshop.json",
		RequiredEnv:  []string{"JUICESHOP_BASE_URL"},
		Target:       func() string { return os.Getenv("JUICESHOP_BASE_URL") },
		Depth:        "active",
	},
	{
		// Templates: "./templates/", mirroring challenges.go's deterministic
		// "vAPI" Scenario — live-verified 2026-08-30
		// (docs/20-setup-testing-targets-macos.md's vAPI section) that the
		// CLI default (full bundled+synced corpus, ~2,500+ tag-scoped
		// templates) makes every scan.leaf against vAPI's slow dev server
		// take 4+ minutes, so a MinIterations-forced multi-turn run blows
		// past this harness's 10m timeout before NextAction ever gets to
		// decide anything (0 tool_calls, 0 findings — an infra artifact, not
		// a reasoning miss). Without this override the two modes' vAPI
		// numbers aren't comparable at all.
		Name:         "vAPI (orchestrator)",
		ExpectedFile: "tests/fixtures/expected-findings/vapi.json",
		RequiredEnv:  []string{"VAPI_BASE_URL"},
		Target:       func() string { return os.Getenv("VAPI_BASE_URL") },
		Depth:        "active",
		Templates:    "./templates/",
	},
	{
		// Templates: templatesDir() — same corpus-hang rationale as vAPI's
		// override above, live-verified 2026-09-19: without it, the run hit
		// this harness's 10m timeout mid-scan.leaf (signal: killed, 0 tool
		// calls surfaced), same shape as vAPI's pre-fix failure. crAPI's own
		// deterministic Scenario (challenges.go) already uses templatesDir()
		// for the same reason.
		//
		// Depth: "full", not "active" (LT-164, docs/follow-up.md): the idor-
		// prefix this fixture expects only exists on a leaf built from a
		// recon-discovered endpoint (unlike challenges.go's deterministic
		// Scenario, which is handed it directly via --endpoint) — and
		// recon's Wave 3 (crawl + JS-static analysis, where LT-164's
		// service-prefix+API-path join lives) never runs below "full". Every
		// other OrchestratorScenario stays at "active" since none of their
		// expected findings need Wave 3.
		Name:              "crAPI (orchestrator)",
		ExpectedFile:      "tests/fixtures/expected-findings/crapi.json",
		RequiredEnv:       []string{"CRAPI_BASE_URL", "CRAPI_OWNER_TOKEN", "CRAPI_OTHER_TOKEN"},
		Target:            func() string { return os.Getenv("CRAPI_BASE_URL") },
		Depth:             "full",
		AuthTokenEnv:      "CRAPI_OWNER_TOKEN",
		OtherAuthTokenEnv: "CRAPI_OTHER_TOKEN",
		Templates:         templatesDir(),
		KnownVulnsFile:    "tests/fixtures/known-vulns/crapi.json",
	},
}
