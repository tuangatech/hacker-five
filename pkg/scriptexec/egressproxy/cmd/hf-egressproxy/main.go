// Command hf-egressproxy is pkg/scriptexec's sandbox egress-proxy sidecar
// entrypoint: a tiny, first-party binary that does nothing but start
// egressproxy.Proxy and block. It is cross-compiled for the Docker daemon's
// own OS/architecture (see pkg/scriptexec/sandbox.go's
// ensureEgressProxyBinary) and bind-mounted into a sidecar container
// attached to both the script container's --internal network (its only
// route out) and a normal network with real internet access — the only two
// networks whose intersection is this one process, so the script container
// can reach the outside world only through it.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
	"github.com/tuangatech/hacker-five/pkg/scanner/scope"
	"github.com/tuangatech/hacker-five/pkg/scriptexec/egressproxy"
)

func main() {
	scopePath := os.Getenv("HF_SCOPE_FILE")
	if scopePath == "" {
		log.Fatal("hf-egressproxy: HF_SCOPE_FILE is required")
	}
	listenAddr := os.Getenv("HF_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "0.0.0.0:8080"
	}

	sc, err := scope.Parse(scopePath)
	if err != nil {
		log.Fatalf("hf-egressproxy: parsing scope file: %v", err)
	}

	hc := httpclient.New(httpclient.Config{
		Timeout:             30 * time.Second,
		MaxRedirects:        5,
		MaxIdleConnsPerHost: 4,
	})

	p := egressproxy.New(sc, hc)
	if err := p.Start(listenAddr); err != nil {
		log.Fatalf("hf-egressproxy: %v", err)
	}
	log.Printf("hf-egressproxy: listening on %s", p.Addr())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	<-ctx.Done()
	_ = p.Close()
}
