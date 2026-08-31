package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/ratelimit"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
)

// reconRunTimeout bounds the whole multi-wave Run — each individual wave
// already has its own shorter per-binary timeout (pkg/recon's internal
// waveTimeout); this is the outer ceiling for the full run.
const reconRunTimeout = 10 * time.Minute

func newReconCmd(root *rootFlags) *cobra.Command {
	var (
		target      string
		depth       string
		scopeFile   string
		rateLimit   int
		concurrency int
		insecure    bool
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

			var s *scope.Scope
			if scopeFile != "" {
				parsed, err := scope.Parse(scopeFile)
				if err != nil {
					return fmt.Errorf("parsing --scope: %w", err)
				}
				s = parsed
			} else {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: no --scope given — every host recon discovers is treated as in-scope")
			}

			client := httpclient.New(httpclient.Config{
				Timeout:             root.timeout,
				MaxRedirects:        5,
				InsecureSkipVerify:  insecure,
				MaxIdleConnsPerHost: concurrency,
				ProxyURL:            root.proxy,
			}, httpclient.WithRateLimit(ratelimit.New(rateLimit)))

			opts := []recon.Option{recon.WithRateLimit(rateLimit), recon.WithConcurrency(concurrency)}
			if s != nil {
				opts = append(opts, recon.WithScope(s))
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
	cmd.Flags().StringVar(&scopeFile, "scope", "", "path to a target allow-list file (same format as scan's --scope); omitted = every discovered host is treated as in-scope, with a warning")
	cmd.Flags().IntVar(&rateLimit, "rate-limit", recon.DefaultRateLimit, "requests/sec passed to each external recon binary's own native rate-limit flag, and used for this package's own direct HTTP calls")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", recon.DefaultConcurrency, "concurrency passed to each external recon binary's own native concurrency flag")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification for this package's own direct HTTP calls — lab targets only, never the default")

	return cmd
}
