package mcpserver

import (
	"os"

	"github.com/tuangatech/hacker-five/pkg/preflight"
	"github.com/tuangatech/hacker-five/pkg/recon"
)

// policyFileEnv names the env var pinning the D2 program-policy file for an
// mcp-serve process (doc15 Step 3). An MCP tool call carries no --scope file
// path to derive a sibling policy.yaml from, so the operator sets this once
// when launching the server for an engagement. Unset = no policy file: the
// pre-flight can only warn, never block.
const policyFileEnv = "HACKERFIVE_POLICY_FILE"

// preflightBlock runs the D2 program-policy pre-flight for an agent-initiated
// tool call. There is no override on the MCP path (unlike the CLI's
// --allow-policy-override) — a disallowed verdict is always a hard refusal.
func preflightBlock(targets []string) (warnings []string, err error) {
	return preflight.Check(targets, preflight.Options{PolicyPath: os.Getenv(policyFileEnv)})
}

// policyRequestHeaders returns the `request_headers:` list from the pinned
// policy file (LT-36) so an MCP-driven recon/plan carries a program-mandated
// identifying header (e.g. X-Hackerone) the same way the CLI and scan do. A
// malformed file surfaces as an error to the caller — the same posture
// preflightBlock takes; an unset env var or absent list yields (nil, nil).
func policyRequestHeaders() (map[string]string, error) {
	path := os.Getenv(policyFileEnv)
	if path == "" {
		return nil, nil
	}
	ps, err := preflight.Load(path)
	if err != nil {
		return nil, err
	}
	return ps.RequestHeaders(), nil
}

// reconSignalWarnings derives the advisory security.txt/robots.txt pre-flight
// warnings from a completed recon pass (the plan/recon tools have these only
// after recon runs).
func reconSignalWarnings(r *recon.ReconResult) []string {
	if r == nil || r.Policy == nil {
		return nil
	}
	return preflight.SignalWarnings(&preflight.Signals{
		SecurityTxt:       r.Policy.SecurityTxt,
		RobotsDisallowAll: r.Policy.RobotsDisallowAll,
	})
}
