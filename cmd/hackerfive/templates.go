package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/templatesync"
)

func newTemplatesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "templates",
		Short: "Manage the Nuclei-compatible template corpus",
	}
	cmd.AddCommand(newTemplatesSyncCmd())
	cmd.AddCommand(newTemplatesListCmd())
	return cmd
}

func newTemplatesSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Sync the pinned nuclei-templates commit into the persistent user-config directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := templatesync.DefaultSyncDir()
			if err != nil {
				return fmt.Errorf("resolving sync directory: %w", err)
			}

			result, err := templatesync.Sync(cmd.Context(), dir)
			if err != nil {
				if errors.Is(err, templatesync.ErrGitNotFound) {
					return fmt.Errorf("%w — install git and ensure it's on PATH, then re-run 'hackerfive templates sync'", err)
				}
				return fmt.Errorf("syncing templates: %w", err)
			}

			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(out, "Synced nuclei-templates @ %s into %s:\n", result.Commit, dir); err != nil {
				return err
			}
			for _, category := range templatesync.Categories {
				if _, err := fmt.Fprintf(out, "  %s: %d templates\n", category, result.CategoryCounts[category]); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newTemplatesListCmd() *cobra.Command {
	var tags string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List currently active templates (bundled and, if synced, the synced corpus)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs, labels := defaultTemplateDirsWithLabels()

			entries, rejected, err := templatesync.List(dirs, labels, parseTags(tags))
			if err != nil {
				return fmt.Errorf("listing templates: %w", err)
			}

			out := cmd.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			if _, err := fmt.Fprintln(tw, "ID\tNAME\tFORMAT\tSEVERITY\tTAGS\tSOURCE"); err != nil {
				return fmt.Errorf("writing template list: %w", err)
			}
			for _, e := range entries {
				if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.Name, e.Format, e.Severity, strings.Join(e.Tags, ","), e.Source); err != nil {
					return fmt.Errorf("writing template list: %w", err)
				}
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("writing template list: %w", err)
			}
			if _, err := fmt.Fprintf(out, "\n%d templates (%d rejected)\n", len(entries), rejected); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&tags, "tags", "", "comma-separated tags — only list templates carrying at least one (default: no filtering)")
	return cmd
}

// defaultTemplateDirsWithLabels is the default two-source list both
// `templates list` and `scan`'s auto-appended --templates default resolve:
// the bundled, project-authored ./templates/ directory, plus the synced
// directory from templatesync.DefaultSyncDir() — only included if a sync has
// actually been run (os.Stat succeeds), so a fresh install with no sync
// history behaves exactly as before this command existed.
func defaultTemplateDirsWithLabels() (dirs, labels []string) {
	dirs = []string{defaultBundledTemplatesDir}
	labels = []string{"bundled"}

	if syncedDir, err := templatesync.DefaultSyncDir(); err == nil {
		if _, statErr := os.Stat(syncedDir); statErr == nil {
			dirs = append(dirs, syncedDir)
			labels = append(labels, "synced")
		}
	}
	return dirs, labels
}
