// Package webui is the local-only web UI over pkg/scanner — see
// docs/12-implementation-plan-ph3.md for the full design. It is a frontend
// on an unchanged scanner core: every route ultimately calls into
// pkg/scanner and pkg/templatesync exactly as cmd/hackerfive already does,
// no scan logic is duplicated here.
package webui

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"time"
)

// Options configures a Server — the values cmd/hackerfive/serve.go's
// --port/--host flags map onto.
type Options struct {
	Host string
	Port int
}

// Server is the embedded HTTP server backing `hackerfive serve`.
type Server struct {
	httpServer *http.Server
	handlers   *handlers
	auth       *nonLoopbackAuth
	addr       string
}

// New builds a Server from opts — parses the embedded templates, wires
// routes, and applies the CSRF and (conditionally) non-loopback-token
// middleware. Does not start listening; see (*Server) ListenAndServe.
func New(opts Options) (*Server, error) {
	tmpl, err := template.ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing embedded templates: %w", err)
	}

	auth, err := newNonLoopbackAuth(opts.Host)
	if err != nil {
		return nil, fmt.Errorf("initializing access token: %w", err)
	}

	h := &handlers{tmpl: tmpl, store: newJobStore(), reconStore: newReconJobStore()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.dashboard)
	mux.HandleFunc("GET /scans", h.scanHistory)
	mux.HandleFunc("GET /scans/new", h.newScanForm)
	mux.HandleFunc("GET /scans/new/detector-fields", h.detectorFields)
	mux.HandleFunc("POST /scans", h.startScan)
	mux.HandleFunc("GET /scans/{id}", h.scanStatus)
	mux.HandleFunc("GET /scans/{id}/export.json", h.exportJSON)
	mux.HandleFunc("GET /scans/{id}/events", h.scanEvents)
	mux.HandleFunc("GET /templates", h.templatesPage)
	mux.HandleFunc("GET /templates/table", h.templateTable)
	mux.HandleFunc("POST /templates/sync", h.syncTemplates)
	mux.HandleFunc("GET /recon", h.newReconForm)
	mux.HandleFunc("POST /recon", h.startRecon)
	mux.HandleFunc("GET /recon/{id}", h.reconStatus)
	mux.HandleFunc("GET /recon/{id}/events", h.reconEvents)
	mux.HandleFunc("POST /recon/setup", h.setupTools)
	mux.HandleFunc("GET /plan-preview", h.planPreview)

	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		return nil, fmt.Errorf("preparing embedded static assets: %w", err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// Order matters: CSRF checks the form field ParseForm() just populated;
	// auth gates access before any of that, since an unauthenticated
	// non-loopback request shouldn't even reach form parsing.
	var handler http.Handler = mux
	handler = csrfMiddleware(handler)
	handler = auth.middleware(handler)

	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	return &Server{
		httpServer: &http.Server{Addr: addr, Handler: handler},
		handlers:   h,
		auth:       auth,
		addr:       addr,
	}, nil
}

// URL is the address to open in a browser — includes the one-time bootstrap
// token when bound to a non-loopback host (see auth.go).
func (s *Server) URL() string {
	return s.auth.BootstrapURL(fmt.Sprintf("http://%s", s.addr))
}

// ListenAndServe blocks until ctx is cancelled, then gracefully shuts down.
// ctx also becomes every background scan's lifecycle context (handlers.
// baseCtx) — a scan outlives the HTTP request that started it, and should
// only be cancelled when the server itself is (Ctrl+C/SIGTERM, already
// wired into cmd.Context() by cmd/hackerfive/main.go), not per-request.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.handlers.baseCtx = ctx

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("webui: shutdown: %v", err)
			return err
		}
		return nil
	}
}
