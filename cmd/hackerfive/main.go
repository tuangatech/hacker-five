// Command hackerfive is the HackerFive CLI entrypoint.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// version is overridden at build time via -ldflags "-X main.version=...":
// goreleaser sets it to the release tag, the Dockerfile's build ARG sets it
// to the image tag; a plain `go build`/`make build` leaves it at "dev".
var version = "dev"

func main() {
	loadDotEnv()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
