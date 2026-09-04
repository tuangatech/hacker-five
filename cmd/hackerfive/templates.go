package main

import (
	"errors"
	"fmt"
	"io"
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
	cmd.AddCommand(newTemplatesIndexCmd())
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

func newTemplatesIndexCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "index",
		Short: "Generate templates/index.json — template metadata pkg/registry's decision engine matches tech signals against",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs, labels := defaultTemplateDirsWithLabels()
			entries, rejected, err := templatesync.List(dirs, labels, nil)
			if err != nil {
				return fmt.Errorf("indexing templates: %w", err)
			}

			if err := templatesync.WriteIndex(output, entries); err != nil {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %d templates (%d rejected) to %s\n", len(entries), rejected, output)
			return err
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "templates/index.json", "output path for the generated index")
	return cmd
}

// loadTemplateIndex reads templates/index.json via templatesync.LoadIndex.
// Callers that can proceed without a template index (e.g. `plan`) should
// treat a missing file as a soft degrade, not a hard error — mirroring
// pkg/recon's own "missing binary -> warning, not failure" posture.
func loadTemplateIndex(path string) ([]templatesync.Entry, error) {
	return templatesync.LoadIndex(path)
}

// warnIndexDrift (P2-5, docs/follow-up.md) compares a loaded index's entry
// count against a fresh on-disk file count across the same dirs
// defaultTemplateDirsWithLabels/`templates index` itself indexes from,
// printing a warning to stderr when they look wildly out of sync — the real
// scenario this catches: an index generated before the synced directory was
// cleared, or re-pointed at a different pinned commit, without re-running
// `templates index`. Best-effort: a directory that can't be walked just
// skips the check silently, matching the "missing optional input, warn and
// continue" posture already used for a missing index file itself.
func warnIndexDrift(stderr io.Writer, index []templatesync.Entry) {
	if len(index) == 0 {
		return
	}
	dirs, _ := defaultTemplateDirsWithLabels()
	if w := indexDriftWarningForDirs(len(index), dirs); w != "" {
		_, _ = fmt.Fprintln(stderr, w)
	}
}

// indexDriftWarningForDirs is warnIndexDrift's dirs-parameterized core,
// split out so a test can exercise the real counting + comparison logic
// against temp directories rather than this machine's real
// templates/synced-templates state (mirroring
// TestDefaultTemplateDirsWithLabels_Invariants' own reasoning for not
// asserting exact real-machine dir contents). Best-effort: a directory that
// can't be walked returns "" (skips the check) rather than propagating the
// error, matching the "missing optional input, warn and continue" posture
// already used for a missing index file itself.
func indexDriftWarningForDirs(indexCount int, dirs []string) string {
	disk := 0
	for _, dir := range dirs {
		n, err := templatesync.CountTemplateFiles(dir)
		if err != nil {
			return ""
		}
		disk += n
	}
	return templatesync.IndexDriftWarning(indexCount, disk)
}

// defaultTemplateDirsWithLabels is the default two-source list both
// `templates list` and `scan`'s auto-appended --templates default resolve:
// the bundled, project-authored ./templates/ directory, plus the synced
// directory from templatesync.DefaultSyncDir() — only included if a sync has
// actually been run (os.Stat succeeds), so a fresh install with no sync
// history behaves exactly as before this command existed.
func defaultTemplateDirsWithLabels() (dirs, labels []string) {
	dirs = []string{templatesync.DefaultBundledDir}
	labels = []string{"bundled"}

	if syncedDir, err := templatesync.DefaultSyncDir(); err == nil {
		if _, statErr := os.Stat(syncedDir); statErr == nil {
			dirs = append(dirs, syncedDir)
			labels = append(labels, "synced")
		}
	}
	return dirs, labels
}
