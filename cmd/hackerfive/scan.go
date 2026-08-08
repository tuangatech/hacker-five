package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/reporter"
	"github.com/tuangatech/hacker-five/pkg/scanner"
)

func newScanCmd(root *rootFlags) *cobra.Command {
	var (
		targets          string
		templatesPath    string
		concurrency      int
		rateLimit        int
		detector         string
		endpointTemplate string
		authToken        string
		otherAuthToken   string
		insecure         bool
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a scan against one or more targets",
		RunE: func(cmd *cobra.Command, args []string) error {
			if authToken == "" {
				authToken = os.Getenv("HACKERFIVE_AUTH_TOKEN")
			}
			if otherAuthToken == "" {
				otherAuthToken = os.Getenv("HACKERFIVE_OTHER_AUTH_TOKEN")
			}

			targetList, err := resolveTargets(targets)
			if err != nil {
				return fmt.Errorf("resolving targets: %w", err)
			}

			cfg := scanner.Config{
				Targets:          targetList,
				TemplatePaths:    []string{templatesPath},
				Concurrency:      concurrency,
				RateLimit:        rateLimit,
				ProxyURL:         root.proxy,
				Timeout:          root.timeout,
				OutputFormat:     "json",
				OutputPath:       root.output,
				Detector:         detector,
				EndpointTemplate: endpointTemplate,
				Insecure:         insecure,
				AuthToken:        authToken,
				OtherAuthToken:   otherAuthToken,
			}
			if err := cfg.Validate(); err != nil {
				return err
			}

			engine := scanner.New(cfg)
			findings, err := engine.Run(cmd.Context())
			if err != nil {
				return fmt.Errorf("running scan: %w", err)
			}

			out := cmd.OutOrStdout()
			if cfg.OutputPath != "" {
				f, err := os.Create(cfg.OutputPath)
				if err != nil {
					return fmt.Errorf("opening output file: %w", err)
				}
				defer func() { _ = f.Close() }()
				out = f
			}
			return reporter.WriteJSON(out, findings)
		},
	}

	cmd.Flags().StringVarP(&targets, "targets", "t", "", "target URL, or path to a file with one target per line (required)")
	cmd.Flags().StringVar(&templatesPath, "templates", "./templates/", "template directory")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "c", 25, "worker pool size")
	cmd.Flags().IntVar(&rateLimit, "rate-limit", 50, "requests/sec across the whole scan")
	cmd.Flags().StringVar(&detector, "detector", "", `detector to run (required); only "idor" is recognized in Phase 1a`)
	cmd.Flags().StringVar(&endpointTemplate, "endpoint", "", `endpoint path with an {{id}} placeholder to enumerate, e.g. "/identity/api/v2/user/dashboard/{{id}}" (required for --detector idor)`)
	cmd.Flags().StringVar(&authToken, "auth-token", "", "owner/primary account token (env: HACKERFIVE_AUTH_TOKEN)")
	cmd.Flags().StringVar(&otherAuthToken, "other-auth-token", "", "second account token for IDOR baseline mode (env: HACKERFIVE_OTHER_AUTH_TOKEN)")
	cmd.Flags().BoolVar(&insecure, "insecure", false, "skip TLS verification — lab targets only, never the default")

	return cmd
}

// resolveTargets treats value as a path to a file with one target per line if
// it exists on disk, otherwise as a single literal target URL.
func resolveTargets(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	if info, err := os.Stat(value); err == nil && !info.IsDir() {
		data, err := os.ReadFile(value)
		if err != nil {
			return nil, fmt.Errorf("reading targets file: %w", err)
		}
		var targetList []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				targetList = append(targetList, line)
			}
		}
		return targetList, nil
	}
	return []string{value}, nil
}
