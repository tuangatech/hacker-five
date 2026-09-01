package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/detectors"
	"github.com/tuangatech/hacker-five/pkg/hackerone"
	"github.com/tuangatech/hacker-five/pkg/reporter"
)

// newReportCmd is the `report` subcommand family for drafting HackerOne
// reports from a prior scan's findings. Every command here that talks to
// HackerOne's API only ever creates or lists — the one command that can
// make a report visible to a program, `report submit`, requires an
// explicit --yes flag. This is HackerFive's permanent
// report-drafting-only invariant (see CLAUDE.md's Rules section) enforced
// in code, not just documented.
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Draft HackerOne reports from scan findings",
	}
	cmd.AddCommand(newReportWeaknessesCmd())
	cmd.AddCommand(newReportScopesCmd())
	cmd.AddCommand(newReportCreateCmd())
	cmd.AddCommand(newReportSubmitCmd())
	return cmd
}

// hackeroneClientFromEnv reads HACKERONE_API_USERNAME/HACKERONE_API_TOKEN —
// the API token identifier and value HackerOne issues, never a hardcoded or
// flag-supplied secret, per CLAUDE.md's credential rule. HACKERONE_API_BASE_URL
// is an undocumented escape hatch (not a CLI flag — no real deployment needs
// it) that lets tests point this at an httptest.Server instead of the real
// API.
func hackeroneClientFromEnv() (*hackerone.Client, error) {
	// TrimSpace guards against a trailing \r on the value — e.g. a
	// credentials file with CRLF line endings sourced by a POSIX shell,
	// which silently corrupts the Basic Auth header and surfaces as an
	// opaque 401 with no hint that the credential itself was mangled.
	username := strings.TrimSpace(os.Getenv("HACKERONE_API_USERNAME"))
	token := strings.TrimSpace(os.Getenv("HACKERONE_API_TOKEN"))
	if username == "" || token == "" {
		return nil, fmt.Errorf("HACKERONE_API_USERNAME and HACKERONE_API_TOKEN env vars are required")
	}
	var opts []hackerone.Option
	if baseURL := strings.TrimSpace(os.Getenv("HACKERONE_API_BASE_URL")); baseURL != "" {
		opts = append(opts, hackerone.WithBaseURL(baseURL))
	}
	return hackerone.New(username, token, opts...), nil
}

func newReportWeaknessesCmd() *cobra.Command {
	var team string
	cmd := &cobra.Command{
		Use:   "weaknesses",
		Short: "List a HackerOne program's CWE-mapped weakness IDs (for report create --weakness-id)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := hackeroneClientFromEnv()
			if err != nil {
				return err
			}
			weaknesses, err := client.ListWeaknesses(cmd.Context(), team)
			if err != nil {
				return fmt.Errorf("listing weaknesses: %w", err)
			}
			out := cmd.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "ID\tCWE\tNAME"); err != nil {
				return err
			}
			for _, w := range weaknesses {
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", w.ID, w.ExternalID, w.Name); err != nil {
					return err
				}
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&team, "team", "", "HackerOne program handle (required)")
	_ = cmd.MarkFlagRequired("team")
	return cmd
}

func newReportScopesCmd() *cobra.Command {
	var team string
	cmd := &cobra.Command{
		Use:   "scopes",
		Short: "List a HackerOne program's in-scope structured assets (for report create --scope-id)",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := hackeroneClientFromEnv()
			if err != nil {
				return err
			}
			scopes, err := client.ListStructuredScopes(cmd.Context(), team)
			if err != nil {
				return fmt.Errorf("listing structured scopes: %w", err)
			}
			out := cmd.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "ID\tASSET\tTYPE\tSUBMITTABLE\tBOUNTY\tINSTRUCTION"); err != nil {
				return err
			}
			for _, s := range scopes {
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%t\t%s\n", s.ID, s.AssetIdentifier, s.AssetType, s.EligibleForSubmission, s.EligibleForBounty, s.Instruction); err != nil {
					return err
				}
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&team, "team", "", "HackerOne program handle (required)")
	_ = cmd.MarkFlagRequired("team")
	return cmd
}

func newReportCreateCmd() *cobra.Command {
	var (
		findingsPath string
		findingID    string
		team         string
		weaknessID   string
		scopeID      string
		title        string
		impact       string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a private HackerOne draft report_intent from one scan finding — never submits it",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := hackeroneClientFromEnv()
			if err != nil {
				return err
			}
			finding, err := findingByID(findingsPath, findingID)
			if err != nil {
				return err
			}

			reportTitle := title
			if reportTitle == "" {
				reportTitle = fmt.Sprintf("%s: %s", finding.Type, finding.Target)
			}

			input := hackerone.ReportIntentInput{
				TeamHandle:               team,
				Title:                    reportTitle,
				VulnerabilityInformation: reporter.HackerOneVulnerabilityInformation(finding),
				SeverityRating:           reporter.HackerOneSeverityRating(finding.Severity),
				WeaknessID:               weaknessID,
				StructuredScopeID:        scopeID,
				Impact:                   impact,
			}

			id, state, err := client.CreateReportIntent(cmd.Context(), input)
			if err != nil {
				return fmt.Errorf("creating report intent: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"Created report_intent %s (state: %s) — a private draft, not visible to the program.\nReview it in the HackerOne UI, then run: hackerfive report submit --intent-id %s --yes\n",
				id, state, id)
			return err
		},
	}

	cmd.Flags().StringVar(&findingsPath, "findings", "", `path to a findings JSON file from "hackerfive scan --format json -o <path>" (required)`)
	cmd.Flags().StringVar(&findingID, "finding-id", "", "Finding.ID of the specific finding to draft a report from, within --findings (required)")
	cmd.Flags().StringVar(&team, "team", "", "HackerOne program handle (required)")
	cmd.Flags().StringVar(&weaknessID, "weakness-id", "", `weakness ID for the program, from "hackerfive report weaknesses --team ..." (required)`)
	cmd.Flags().StringVar(&scopeID, "scope-id", "", `structured scope ID for the program, from "hackerfive report scopes --team ..." (required)`)
	cmd.Flags().StringVar(&title, "title", "", "report title (default: derived from the finding's type and target)")
	cmd.Flags().StringVar(&impact, "impact", "", "optional impact statement")
	for _, name := range []string{"findings", "finding-id", "team", "weakness-id", "scope-id"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

func newReportSubmitCmd() *cobra.Command {
	var (
		intentID string
		yes      bool
	)

	cmd := &cobra.Command{
		Use:   "submit",
		Short: "Submit a draft report_intent to its program — the one action here visible outside your own account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return fmt.Errorf("refusing to submit report_intent %s without --yes — this makes the report visible to the program and cannot be undone by this tool; re-run with --yes once you've reviewed the draft", intentID)
			}
			client, err := hackeroneClientFromEnv()
			if err != nil {
				return err
			}
			if err := client.SubmitReportIntent(cmd.Context(), intentID); err != nil {
				return fmt.Errorf("submitting report intent: %w", err)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Submitted report_intent %s to its program.\n", intentID)
			return err
		},
	}

	cmd.Flags().StringVar(&intentID, "intent-id", "", "report_intent ID from a prior report create (required)")
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm submission — required, not a default-true convenience flag")
	_ = cmd.MarkFlagRequired("intent-id")
	return cmd
}

// findingByID reads a findings JSON file (the shape reporter.WriteJSON
// produces) and returns the one Finding whose ID matches id.
func findingByID(path, id string) (detectors.Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return detectors.Finding{}, fmt.Errorf("reading findings file: %w", err)
	}
	var findings []detectors.Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return detectors.Finding{}, fmt.Errorf("parsing findings file: %w", err)
	}
	for _, f := range findings {
		if f.ID == id {
			return f, nil
		}
	}
	return detectors.Finding{}, fmt.Errorf("no finding with id %q in %s", id, path)
}
