package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// newTriageCmd is Phase 7 A6's CLI entry point (docs/16-implementation-plan-ph7.md
// Step 1; docs/follow-up.md LT-41). The recon -> plan -> scan pipeline had no
// triage stage on the CLI — llmfallback.TriageFindings was reachable only
// from pkg/mcpserver and pkg/webui, so the documented "triage agent" step
// was MCP-only. This routes a completed scan's JSON finding list
// (`scan --format json --output <file>`) through the same tiered LLM
// fallback (I4) for a ranking *only* — never a mutation of a finding's
// severity/confidence, never a submission. Behind --llm-assist, the same
// opt-in posture `plan` has, since triage is by definition a paid model call
// with no deterministic mode to fall back to.
func newTriageCmd(root *rootFlags) *cobra.Command {
	var findingsPath string
	var llmAssist bool
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "triage",
		Short: "Rank a completed scan's findings by what's worth investigating first (LLM-assisted, ranking only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if findingsPath == "" {
				return fmt.Errorf("--findings <path> is required (a prior 'hackerfive scan --format json --output <path>' file)")
			}
			if !llmAssist {
				return fmt.Errorf("triage makes a paid LLM call and has no deterministic mode — re-run with --llm-assist to confirm")
			}

			data, err := os.ReadFile(findingsPath)
			if err != nil {
				return fmt.Errorf("reading --findings: %w", err)
			}
			var findings []detectors.Finding
			if err := json.Unmarshal(data, &findings); err != nil {
				return fmt.Errorf("parsing --findings (expected the JSON array 'scan --format json' writes): %w", err)
			}
			if len(findings) == 0 {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "triage: the findings file is empty — nothing to rank")
				return nil
			}

			// LT-146 (docs/follow-up.md): heartbeat/retry visibility for
			// TriageFindings' one single-shot, whole-finding-list call.
			fb, fbErr := llmfallback.New(llmfallback.WithLogCallback(func(level, msg string) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "triage: %s\n", msg)
			}))
			if fbErr != nil {
				return fmt.Errorf("triage needs an LLM tier configured (local runtime and/or OPENROUTER_API_KEY): %w", fbErr)
			}
			result, cost, err := fb.TriageFindings(cmd.Context(), findings)
			if err != nil {
				return fmt.Errorf("triage call failed: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "triage: ranked %d finding(s), spent $%.4f\n", len(findings), cost)
			if result.EscalateToHuman != "" {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "triage: escalated to human — %s\n", result.EscalateToHuman)
			}

			out := cmd.OutOrStdout()
			if root.output != "" {
				f, err := os.Create(root.output)
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer func() { _ = f.Close() }()
				out = f
			}

			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			if result.EscalateToHuman != "" {
				return nil // nothing to tabulate — the stderr line above said why
			}
			return writeTriageTable(out, findings, result.Ranked)
		},
	}

	cmd.Flags().StringVar(&findingsPath, "findings", "", "path to a JSON finding list from 'hackerfive scan --format json --output <path>' (required)")
	cmd.Flags().BoolVar(&llmAssist, "llm-assist", false, "required — acknowledges triage makes a paid LLM call (it has no deterministic mode)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the ranking as JSON ({\"ranked\": [...]}) instead of the text table")
	return cmd
}

// writeTriageTable renders the ranking joined back against each finding's own
// severity/type, ordered by rank.
func writeTriageTable(out io.Writer, findings []detectors.Finding, ranked []llmfallback.RankedFinding) error {
	byID := make(map[string]detectors.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}
	ordered := make([]llmfallback.RankedFinding, len(ranked))
	copy(ordered, ranked)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Rank < ordered[j].Rank })

	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "RANK\tSEVERITY\tTYPE\tFINDING\tRATIONALE"); err != nil {
		return err
	}
	for _, r := range ordered {
		f := byID[r.FindingID]
		if _, err := fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.Rank, f.Severity, f.Type, r.FindingID, r.Rationale); err != nil {
			return err
		}
	}
	return tw.Flush()
}
