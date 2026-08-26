package main

import (
	"time"

	"github.com/spf13/cobra"
)

// rootFlags holds flags persistent across every subcommand.
type rootFlags struct {
	proxy   string
	timeout time.Duration
	output  string
}

func newRootCmd() *cobra.Command {
	flags := &rootFlags{}

	cmd := &cobra.Command{
		Use:           "hackerfive",
		Short:         "HackerFive — a template-driven vulnerability scanner",
		Version:       version, // non-empty enables Cobra's built-in --version flag
		SilenceUsage:  true,
		SilenceErrors: false,
	}

	cmd.PersistentFlags().StringVar(&flags.proxy, "proxy", "", "proxy URL for all requests (e.g. http://127.0.0.1:8080)")
	cmd.PersistentFlags().DurationVar(&flags.timeout, "timeout", 30*time.Second, "per-request timeout")
	cmd.PersistentFlags().StringVarP(&flags.output, "output", "o", "", "output file path (default: stdout)")

	cmd.AddCommand(newScanCmd(flags))

	return cmd
}
