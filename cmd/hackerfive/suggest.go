package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/coveragegap"
	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/llmfallback"
)

// suggestOutput is what newSuggestCmd prints — the deterministic ledger
// always, the LLM-proposed action list only under --llm-assist.
type suggestOutput struct {
	CoverageGaps []coveragegap.GapRow          `json:"coverage_gaps"`
	Actions      []llmfallback.SuggestedAction `json:"actions,omitempty"`
}

// newSuggestCmd is LT-108's CLI entry point (docs/16-implementation-plan-ph7.md
// Step 7, rung 2 of the end-of-scan re-plan ladder). Reads a completed scan's
// JSON finding list (`scan --format json --output <file>`), which already
// carries LT-107's coverage-gap-* findings inline (pkg/scanner's Engine.Run
// emits them as ordinary Findings — no separate ledger file/schema). Unlike
// `triage`, which hard-fails without --llm-assist (it has no deterministic
// mode), `suggest` always prints the deterministic ledger and only makes a
// model call when --llm-assist is passed — same optional, off-by-default
// posture as `plan --llm-assist`.
func newSuggestCmd(root *rootFlags) *cobra.Command {
	var llmAssist bool

	cmd := &cobra.Command{
		Use:   "suggest <scan-output.json>",
		Short: "Print the end-of-scan coverage-gap ledger, and (with --llm-assist) a proposed next-action list — never applies anything",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("reading scan output: %w", err)
			}
			var findings []detectors.Finding
			if err := json.Unmarshal(data, &findings); err != nil {
				return fmt.Errorf("parsing scan output (expected the JSON array 'scan --format json' writes): %w", err)
			}

			var ledger []coveragegap.GapRow
			var other []detectors.Finding
			for _, f := range findings {
				if strings.HasPrefix(f.ID, "coverage-gap-") {
					ledger = append(ledger, coveragegap.GapRow{
						Host:    f.Target,
						Product: f.Evidence["product"],
						Reason:  f.Evidence["reason"],
					})
					continue
				}
				other = append(other, f)
			}
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "suggest: %d coverage gap(s), %d other finding(s)\n", len(ledger), len(other))

			result := suggestOutput{CoverageGaps: ledger}

			if llmAssist {
				fb, fbErr := llmfallback.New()
				if fbErr != nil {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "suggest: --llm-assist requested but no LLM tier is configured (local runtime and/or OPENROUTER_API_KEY): %v — printing the ledger only\n", fbErr)
				} else {
					suggested, cost, err := fb.Suggest(cmd.Context(), ledger, other)
					if err != nil {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "suggest: llm-assist call failed: %v — printing the ledger only\n", err)
					} else {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "suggest: llm-assist proposed %d action(s), spent $%.4f\n", len(suggested.Actions), cost)
						result.Actions = suggested.Actions
					}
				}
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
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		},
	}

	cmd.Flags().BoolVar(&llmAssist, "llm-assist", false, "resolve the ledger into a proposed next-action list via the tiered LLM fallback (I4) — off by default (zero LLM calls); requires OPENROUTER_API_KEY and/or a local runtime (see pkg/llmfallback)")
	return cmd
}
