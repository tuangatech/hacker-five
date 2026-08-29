package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tuangatech/hacker-five/pkg/webui"
)

func newServeCmd() *cobra.Command {
	var (
		port int
		host string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the local web UI (hackerfive serve)",
		RunE: func(cmd *cobra.Command, args []string) error {
			srv, err := webui.New(webui.Options{Host: host, Port: port})
			if err != nil {
				return fmt.Errorf("starting web server: %w", err)
			}

			url := srv.URL()
			out := cmd.OutOrStdout()
			if _, err := fmt.Fprintf(out, "HackerFive web UI: %s\n", url); err != nil {
				return err
			}
			if err := webui.OpenBrowser(url); err != nil {
				if _, printErr := fmt.Fprintf(out, "(couldn't open a browser automatically: %v — open the URL above manually)\n", err); printErr != nil {
					return printErr
				}
			}

			return srv.ListenAndServe(cmd.Context())
		},
	}

	cmd.Flags().IntVar(&port, "port", 8877, "port to listen on")
	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "host to bind to — anything other than 127.0.0.1/::1/localhost requires the printed access token")

	return cmd
}
