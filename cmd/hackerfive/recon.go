package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/toolsync"
)

// reconSetupTimeout bounds the whole Install run — 6 sequential downloads
// plus httpx's own ~93MB model-file warm-up, generous enough for a slow
// connection without hanging forever on a genuinely stuck request.
const reconSetupTimeout = 10 * time.Minute

// reconRunTimeout bounds the whole multi-wave Run — each individual wave
// already has its own shorter per-binary timeout (pkg/recon's internal
// waveTimeout); this is the outer ceiling for the full run.
const reconRunTimeout = 10 * time.Minute

func newReconCmd(root *rootFlags) *cobra.Command {
	var (
		target       string
		depth        string
		scopeFile    string
		allowNoScope bool
		rateLimit    int
		concurrency  int
		verbose      bool
	)

	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Run HackerFive's recon phase standalone against a target (no agent required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--targets is required")
			}
			d := recon.Depth(depth)
			switch d {
			case recon.DepthPassive, recon.DepthActive, recon.DepthFull:
			default:
				return fmt.Errorf(`--recon-depth must be "passive", "active", or "full", got %q`, depth)
			}

			s, err := requireScopeOrOptOut(scopeFile, allowNoScope, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			client := httpclient.New(recon.ClientConfig(httpclient.Config{
				Timeout:             root.timeout,
				MaxRedirects:        5,
				MaxIdleConnsPerHost: concurrency,
				ProxyURL:            root.proxy,
			}), httpclient.WithRateLimit(ratelimit.New(rateLimit)))

			opts := []recon.Option{recon.WithRateLimit(rateLimit), recon.WithConcurrency(concurrency)}
			if s != nil {
				opts = append(opts, recon.WithScope(s))
			}
			if verbose {
				opts = append(opts, recon.WithProgressCallback(verboseProgress(cmd.ErrOrStderr())))
			}
			r := recon.New(client, opts...)

			ctx, cancel := context.WithTimeout(cmd.Context(), reconRunTimeout)
			defer cancel()

			result, err := r.Run(ctx, target, d)
			if err != nil {
				return fmt.Errorf("running recon: %w", err)
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

	cmd.Flags().StringVarP(&target, "targets", "t", "", "target URL to run recon against (required)")
	cmd.Flags().StringVar(&depth, "recon-depth", "passive", `how far to escalate: "passive" (Wave 0-1 only), "active" (+ Wave 2: DNS/port scan/HTTP probe), "full" (+ Wave 3: bounded crawl)`)
	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to a target allow-list file (same format as scan's --scope; see .engagements/*/scope.txt for real examples) — required unless --allow-no-scope is set")
	cmd.Flags().BoolVar(&allowNoScope, "allow-no-scope", false, "proceed with no --scope boundary — every host recon discovers is treated as in-scope, including unrelated infrastructure (e.g. a shared CDN/vendor domain); lab/local use only, never a real engagement")
	cmd.Flags().IntVar(&rateLimit, "rate-limit", recon.DefaultRateLimit, "requests/sec passed to each external recon binary's own native rate-limit flag, and used for this package's own direct HTTP calls")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", recon.DefaultConcurrency, "concurrency passed to each external recon binary's own native concurrency flag")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print wave-by-wave progress to stderr as recon runs (LT-11, docs/follow-up.md) — off by default so scripted invocations see no output change")

	cmd.AddCommand(newReconSetupCmd())

	return cmd
}

// verboseProgress returns the callback --verbose passes to
// recon.WithProgressCallback (already used by the Web UI's own progress bar)
// — LT-11 (docs/follow-up.md, 2026-09-04): a real `hackerfive recon
// --recon-depth full` run had a literal 0-byte stderr log for its whole 82s
// wall-clock duration, no way to tell which wave was running or whether the
// process had hung. The mechanism already existed; it was simply never
// registered by any CLI command. Factored out as a plain func(wave, status
// string) — not a recon.Option directly — so it's testable without needing
// a real *recon.Recon.
func verboseProgress(stderr io.Writer) func(wave, status string) {
	return func(wave, status string) {
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", wave, status)
	}
}

// newReconSetupCmd is `hackerfive recon setup` — installs the 6 recon
// binaries pkg/recon shells out to (subfinder/tlsx/dnsx/naabu/httpx/
// katana), replacing the manual `go install ...@latest` per tool
// (docs/04-environment-and-testing.md §2) for anyone without a Go
// toolchain. Never runs automatically (not on `serve` startup, not as a
// side effect of `recon`/`plan`) — installing binaries is a real network
// operation with a real failure mode, so it stays one explicit, opt-in
// action, same posture as `hackerfive templates sync`.
func newReconSetupCmd() *cobra.Command {
	var (
		dir   string
		check bool
	)

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install the 6 recon binaries (subfinder/tlsx/dnsx/naabu/httpx/katana) needed for --recon-depth active|full",
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				d, err := toolsync.DefaultInstallDir()
				if err != nil {
					return fmt.Errorf("resolving install directory: %w", err)
				}
				dir = d
			}

			out := cmd.OutOrStdout()
			if check {
				return printToolStatus(out, toolsync.Status(dir), dir)
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), reconSetupTimeout)
			defer cancel()

			result := toolsync.Install(ctx, dir, func(tool, message string) {
				if tool == "" {
					_, _ = fmt.Fprintf(out, "%s\n", message)
					return
				}
				_, _ = fmt.Fprintf(out, "[%s] %s\n", tool, message)
			})

			_, _ = fmt.Fprintln(out)
			failed := 0
			tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "TOOL\tSTATUS\tVERSION")
			for _, tr := range result.Tools {
				status := "ok"
				extra := "v" + tr.Version
				if !tr.OK {
					status = "failed"
					extra = tr.Err
					failed++
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", tr.Name, status, extra)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d tools failed to install — see above; the rest installed successfully", failed, len(result.Tools))
			}
			_, _ = fmt.Fprintf(out, "\nAll tools installed into %s\n", dir)
			return nil
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "install directory (default: the OS user-config dir, same base as 'templates sync')")
	cmd.Flags().BoolVar(&check, "check", false, "report current install status only — no network, no download")

	return cmd
}

func printToolStatus(out io.Writer, statuses []toolsync.ToolStatus, dir string) error {
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TOOL\tINSTALLED\tVERSION")
	for _, s := range statuses {
		version := s.Version
		if version == "" {
			version = "unknown"
		}
		installed := "no"
		if s.Installed {
			installed = "yes"
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Name, installed, version)
			continue
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t-\n", s.Name, installed)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "\ninstall directory: %s\n", dir)
	return err
}
