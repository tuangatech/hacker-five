package eval

import (
	"os"
)

// AgentScenario is one G1 (docs/16-implementation-plan-ph7.md Step 6)
// agent-driven challenge: the same target + expected-findings fixture as
// the matching detector-only Scenario in challenges.go, but resolved
// through a real MCP recon -> plan -> approve -> execute (-> triage)
// session instead of a hand-built scan command with explicit
// --detector/--endpoint/--protected-paths flags — the agent's own
// leaf/field resolution (I3's tag/rule match, I4's LLM fallback for
// anything it can't fill deterministically) is exercised too, not just the
// underlying detector. Tracks agent-driven false-positive/false-negative
// rate separately from the Scenarios baseline (Phase 5 Step 1), per doc16
// Step 6's G1 design.
//
// Known, named gap (not solved here): the MCP `recon` tool has no
// header/auth-token input at all (see pkg/mcpserver/tools_recon.go's
// reconInput) — only `plan`/`scan` accept credentials. A session-gated
// target (DVWA's Cookie-gated app behind its setup redirect) therefore
// can't be reconned authenticated through this path the way the CLI's
// `recon --header` can; `plan`'s own execution still carries auth_token
// through to the leaves it runs, so a token-gated API (crAPI) still works,
// but recon's own tech/endpoint fingerprinting against it happens
// unauthenticated.
type AgentScenario struct {
	Name              string
	ExpectedFile      string
	RequiredEnv       []string
	Target            func() string
	Depth             string // recon depth passed to both `recon` and `plan`
	AuthTokenEnv      string // env var name carrying the owner token for `plan`, "" if none
	OtherAuthTokenEnv string
	SkipPrefixes      []string
}

// AgentScenarios mirrors Scenarios' four live lab targets. Unlike Scenarios,
// there is no --detector/--endpoint/--protected-paths override here — the
// plan tool's own decision engine + field-suggest/I4 pipeline must resolve
// them, which is exactly what this harness is measuring.
var AgentScenarios = []AgentScenario{
	{
		Name:         "DVWA (agent)",
		ExpectedFile: "tests/fixtures/expected-findings/dvwa.json",
		RequiredEnv:  []string{"DVWA_BASE_URL"},
		Target:       func() string { return os.Getenv("DVWA_BASE_URL") },
		Depth:        "active",
	},
	{
		Name:         "Juice Shop (agent)",
		ExpectedFile: "tests/fixtures/expected-findings/juiceshop.json",
		RequiredEnv:  []string{"JUICESHOP_BASE_URL"},
		Target:       func() string { return os.Getenv("JUICESHOP_BASE_URL") },
		Depth:        "active",
	},
	{
		Name:         "vAPI (agent)",
		ExpectedFile: "tests/fixtures/expected-findings/vapi.json",
		RequiredEnv:  []string{"VAPI_BASE_URL"},
		Target:       func() string { return os.Getenv("VAPI_BASE_URL") },
		Depth:        "active",
	},
	{
		Name:              "crAPI (agent)",
		ExpectedFile:      "tests/fixtures/expected-findings/crapi.json",
		RequiredEnv:       []string{"CRAPI_BASE_URL", "CRAPI_OWNER_TOKEN", "CRAPI_OTHER_TOKEN"},
		Target:            func() string { return os.Getenv("CRAPI_BASE_URL") },
		Depth:             "active",
		AuthTokenEnv:      "CRAPI_OWNER_TOKEN",
		OtherAuthTokenEnv: "CRAPI_OTHER_TOKEN",
	},
}
